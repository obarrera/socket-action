import json
import argparse
import os

def map_severity_to_sarif(severity):
    """
    Map Socket severity levels to SARIF levels.
    """
    severity_mapping = {
        "low": "note",
        "medium": "warning",
        "middle": "warning",  # older data might say "middle"
        "high": "error",
        "critical": "error",
        "error": "error"       # sometimes reported as 'error'
    }
    return severity_mapping.get(severity.lower(), "note")

def fetch_code_snippet(file_path, start_line, num_lines=3):
    """
    Attempt to read a snippet of code from 'file_path'.
    Returns up to 'num_lines' lines or an error message if unavailable.
    """
    if not os.path.isfile(file_path):
        return f"Could not fetch snippet: File '{file_path}' does not exist."
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            lines = f.readlines()
            # Convert 1-based line numbers to zero-based indexing
            start_index = max(start_line - 1, 0)
            end_index = min(start_index + num_lines, len(lines))
            snippet_lines = lines[start_index:end_index]
            return ''.join(snippet_lines)
    except Exception as e:
        return f"Could not fetch snippet: {e}"

def convert_to_sarif(socket_file, output_file):
    """
    Converts the Socket CLI JSON results into a SARIF 2.1.0 file.
    """
    print(f"[INFO] Loading Socket results from '{socket_file}'...")

    if not os.path.isfile(socket_file):
        print(f"[ERROR] The results file '{socket_file}' does not exist.")
        exit(1)

    try:
        with open(socket_file, 'r', encoding='utf-8') as f:
            data = json.load(f)
    except Exception as e:
        print(f"[ERROR] Failed to parse JSON: {e}")
        exit(1)

    # Basic skeleton for SARIF
    sarif_data = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "Socket Security",
                        "informationUri": "https://socket.dev",
                        "rules": []
                    }
                },
                "results": []
            }
        ]
    }

    # We assume 'new_alerts' is the key that holds newly introduced issues
    # If there's another key (e.g. 'all_alerts'), adjust accordingly.
    alerts = data.get("new_alerts", [])

    print(f"[INFO] Found {len(alerts)} 'new_alerts' in the data.")

    # If no alerts, produce an empty SARIF and exit
    if not alerts:
        print("[INFO] No new alerts to report. Creating empty SARIF.")
        with open(output_file, 'w', encoding='utf-8') as out:
            json.dump(sarif_data, out, indent=2)
        print(f"[INFO] Empty SARIF file written to '{output_file}'.")
        return

    # Track unique rules to avoid duplicates
    rule_map = {}
    results = []

    for idx, alert in enumerate(alerts, start=1):
        print(f"[DEBUG] Processing alert #{idx}: {alert}")

        # Extract relevant fields from the alert
        rule_id = alert.get("type", "unknown-type")
        title = alert.get("title", rule_id)
        description = alert.get("description", "No description provided.")
        severity = alert.get("severity", "low")

        # Some alerts store file path in different keys; adjust if needed.
        file_path = alert.get("pkg_name", "unknown_file")

        # For best results, ensure 'file_path' matches an actual path
        # in your repo so GitHub can display a snippet.
        # For demonstration, assume the CLI's 'pkg_name' is the correct relative path.

        # Default to line 1 if the alert doesn't specify a line number
        start_line = alert.get("line_number", 1)

        # Optional "props" that might store additional notes
        props = alert.get("props", {})
        note_text = props.get("note", "")

        # Build or reuse the SARIF rule
        if rule_id not in rule_map:
            rule_obj = {
                "id": rule_id,
                "name": title,
                "shortDescription": {"text": description},
                "fullDescription": {"text": note_text},
                "helpUri": "https://socket.dev",
                "defaultConfiguration": {
                    "level": map_severity_to_sarif(severity)
                }
            }
            rule_map[rule_id] = rule_obj

        # Attempt to fetch a snippet from the local file
        snippet_text = fetch_code_snippet(file_path, start_line, num_lines=5)

        # Build a single result object
        result_obj = {
            "ruleId": rule_id,
            "message": {"text": description},
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": file_path  # must match a real path in your repo
                        },
                        "region": {
                            "startLine": start_line,
                            "snippet": {"text": snippet_text}
                        }
                    }
                }
            ]
        }
        results.append(result_obj)

    # Add unique rules + results to SARIF
    sarif_data["runs"][0]["tool"]["driver"]["rules"] = list(rule_map.values())
    sarif_data["runs"][0]["results"] = results

    # Write the final SARIF
    try:
        with open(output_file, 'w', encoding='utf-8') as out:
            json.dump(sarif_data, out, indent=2)
        print(f"[INFO] SARIF file successfully written to '{output_file}'.")
    except Exception as e:
        print(f"[ERROR] Failed to write SARIF file: {e}")
        exit(1)

def main():
    parser = argparse.ArgumentParser(description="Convert Socket CLI JSON to SARIF.")
    parser.add_argument("--socket_results", required=True, help="Path to the Socket CLI JSON file.")
    parser.add_argument("--output_file", required=True, help="Path for the output SARIF file.")
    args = parser.parse_args()

    convert_to_sarif(args.socket_results, args.output_file)

if __name__ == "__main__":
    main()
