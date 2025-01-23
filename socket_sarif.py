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
        "middle": "warning",  # sometimes "medium" is spelled "middle" in older data
        "high": "error",
        "critical": "error",
    }
    return severity_mapping.get(severity.lower(), "note")


def fetch_code_snippet(file_path, start_line, num_lines=3):
    """
    Attempt to read a snippet of code from file_path.
    Returns up to num_lines of code or an error message if unavailable.
    """
    if not os.path.isfile(file_path):
        return f"Could not fetch snippet: File '{file_path}' does not exist."
    try:
        with open(file_path, 'r') as f:
            lines = f.readlines()
            start_index = max(start_line - 1, 0)
            end_index = min(start_index + num_lines, len(lines))
            return ''.join(lines[start_index:end_index])
    except Exception as e:
        return f"Could not fetch snippet: {e}"


def convert_to_sarif(input_file, output_file):
    """
    Convert Socket's JSON results into a SARIF 2.1.0 file.
    Adds extra debug logging to show what data was loaded.
    """
    print(f"[DEBUG] Loading results from: {input_file} ...")
    if not os.path.isfile(input_file):
        print(f"[ERROR] Input file '{input_file}' does not exist.")
        exit(1)

    # Load the JSON
    try:
        with open(input_file, 'r') as f:
            data = json.load(f)
    except Exception as e:
        print(f"[ERROR] Failed to load input file: {e}")
        exit(1)

    # Print the entire JSON structure for debugging (optional)
    print("[DEBUG] Full JSON content from Socket results:")
    print(json.dumps(data, indent=2))

    # Basic SARIF scaffold
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

    # For debugging, let's see if "new_alerts" or other keys exist
    if "new_alerts" not in data:
        print("[DEBUG] 'new_alerts' key not found in JSON. Checking for other possible alert keys...")
        possible_alerts_keys = [k for k in data.keys() if "alert" in k.lower()]
        print(f"[DEBUG] Possible alert-related keys found: {possible_alerts_keys}")

        # If you want to treat all 'alerts' keys the same, you might check them here.
        # For now, we'll proceed with the assumption that "new_alerts" is the only relevant key for new issues.
        print("[INFO] No 'new_alerts' found. We'll treat this as zero new alerts.")
        # Create an empty SARIF and exit gracefully
        with open(output_file, 'w') as f:
            json.dump(sarif_data, f, indent=2)
        print(f"[DEBUG] Empty SARIF file successfully written to {output_file}.")
        return

    alerts = data.get("new_alerts", [])
    print(f"[DEBUG] Found 'new_alerts' with {len(alerts)} alerts.")

    if not alerts:
        print("[INFO] 'new_alerts' array is empty. Creating empty SARIF file.")
        with open(output_file, 'w') as f:
            json.dump(sarif_data, f, indent=2)
        print(f"[DEBUG] Empty SARIF file successfully written to {output_file}.")
        return

    # We'll keep a dict to avoid duplicating the same rule
    unique_rules = {}
    results = []

    for idx, alert in enumerate(alerts, start=1):
        print(f"[DEBUG] Processing alert #{idx}: {alert}")

        rule_id = alert.get("type", "unknown_type")
        title = alert.get("title", "No Title Provided")
        description = alert.get("description", "No Description Provided")
        severity = alert.get("severity", "low")
        props = alert.get("props", {})
        note_text = props.get("note", "No additional note provided.")

        # Create the rule if not already present
        if rule_id not in unique_rules:
            rule_obj = {
                "id": rule_id,
                "name": title,
                "helpUri": "https://socket.dev",
                "shortDescription": {"text": description},
                "fullDescription": {"text": note_text},
                "defaultConfiguration": {
                    "level": map_severity_to_sarif(severity)
                },
            }
            unique_rules[rule_id] = rule_obj

        # We'll assume pkg_name is the file path, or "unknown_file" if missing
        file_path = alert.get("pkg_name", "unknown_file")
        start_line = 1
        code_snippet = fetch_code_snippet(file_path, start_line)

        result_obj = {
            "ruleId": rule_id,
            "message": {"text": description},
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {"uri": file_path},
                        "region": {
                            "startLine": start_line,
                            "snippet": {"text": code_snippet}
                        },
                    }
                }
            ],
        }
        results.append(result_obj)

    # Populate the SARIF structure
    sarif_data["runs"][0]["tool"]["driver"]["rules"] = list(unique_rules.values())
    sarif_data["runs"][0]["results"] = results

    # Write the final SARIF
    print(f"[DEBUG] Writing SARIF data with {len(results)} results to {output_file}...")
    try:
        with open(output_file, 'w') as f:
            json.dump(sarif_data, f, indent=2)
        print(f"[INFO] SARIF file successfully written to {output_file}.")
    except Exception as e:
        print(f"[ERROR] Failed to write SARIF file: {e}")
        exit(1)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Convert Socket results to SARIF.")
    parser.add_argument("--socket_results", required=True, help="Input JSON results file.")
    parser.add_argument("--output_file", required=True, help="Output SARIF file.")
    args = parser.parse_args()

    convert_to_sarif(args.socket_results, args.output_file)
