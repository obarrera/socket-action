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
    }
    return severity_mapping.get(severity.lower(), "note")

def find_line_in_requirements(pkg_name, req_file="requirements.txt"):
    """
    Search for 'pkg_name' in the lines of 'requirements.txt'.
    Return a (line_number, line_content) if found, else (1, 'Fallback snippet').
    """
    if not os.path.isfile(req_file):
        # If there's no requirements.txt, fallback to line 1
        return 1, f"[No {req_file} found in repo]"
    try:
        with open(req_file, "r", encoding="utf-8") as f:
            lines = f.readlines()
            for i, line in enumerate(lines, start=1):
                # Basic check if pkg_name appears in that line
                if pkg_name.lower() in line.lower():
                    return i, line.rstrip("\n")
    except Exception as e:
        return 1, f"[Error reading {req_file}: {e}]"

    # If we never matched the package name, fallback
    return 1, f"[Package '{pkg_name}' not found in {req_file}]"

def convert_to_sarif(input_file, output_file):
    """
    Convert the Socket CLI JSON results into a SARIF 2.1.0 file.
    """
    print(f"[DEBUG] Loading results from: {input_file} ...")
    if not os.path.isfile(input_file):
        print(f"[ERROR] Input file '{input_file}' does not exist.")
        exit(1)

    # Load the JSON
    try:
        with open(input_file, "r", encoding="utf-8") as f:
            data = json.load(f)
    except Exception as e:
        print(f"[ERROR] Failed to parse JSON from '{input_file}': {e}")
        exit(1)

    # Debug: print entire JSON
    print("[DEBUG] Full JSON content from Socket results:")
    print(json.dumps(data, indent=2))

    # Basic SARIF skeleton
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

    # Grab new_alerts
    alerts = data.get("new_alerts", [])
    print(f"[DEBUG] Found {len(alerts)} 'new_alerts' in the data.")

    if not alerts:
        print("[INFO] 'new_alerts' is empty or missing. Creating empty SARIF.")
        with open(output_file, "w", encoding="utf-8") as out:
            json.dump(sarif_data, out, indent=2)
        print(f"[DEBUG] Wrote empty SARIF to '{output_file}'.")
        return

    # We'll store each unique rule
    rules_map = {}
    results_list = []

    # For each alert, anchor it to requirements.txt
    requirements_file = "requirements.txt"

    for idx, alert in enumerate(alerts, start=1):
        print(f"[DEBUG] Processing alert #{idx}: {alert}")

        rule_id = alert.get("type", "unknown_type")
        title = alert.get("title", "No Title")
        description = alert.get("description", "No description")
        severity = alert.get("severity", "low")
        props = alert.get("props", {})
        note_text = props.get("note", "No additional context.")

        # If not in the rules map, create a new rule
        if rule_id not in rules_map:
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
            rules_map[rule_id] = rule_obj

        # The "pkg_name" is the malicious package. We'll search for it in requirements.txt
        pkg_name = alert.get("pkg_name", "unknown")
        line_number, line_content = find_line_in_requirements(pkg_name, requirements_file)

        # Build the snippet from that single line
        snippet_text = line_content

        # Build result object
        result_obj = {
            "ruleId": rule_id,
            "message": {"text": description},
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {
                            # Always reference 'requirements.txt'
                            "uri": requirements_file
                        },
                        "region": {
                            "startLine": line_number,
                            "snippet": {"text": snippet_text}
                        }
                    }
                }
            ]
        }

        results_list.append(result_obj)

    # Populate the SARIF structure
    sarif_data["runs"][0]["tool"]["driver"]["rules"] = list(rules_map.values())
    sarif_data["runs"][0]["results"] = results_list

    print(f"[DEBUG] Writing SARIF with {len(results_list)} results to '{output_file}'...")
    try:
        with open(output_file, "w", encoding="utf-8") as out:
            json.dump(sarif_data, out, indent=2)
        print("[INFO] SARIF successfully written.")
    except Exception as e:
        print(f"[ERROR] Failed writing SARIF to '{output_file}': {e}")
        exit(1)

def main():
    parser = argparse.ArgumentParser(description="Convert Socket results to SARIF with lines referencing requirements.txt.")
    parser.add_argument("--socket_results", required=True, help="Input JSON results from Socket CLI.")
    parser.add_argument("--output_file", required=True, help="Output SARIF file.")
    args = parser.parse_args()

    convert_to_sarif(args.socket_results, args.output_file)

if __name__ == "__main__":
    main()
