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

def find_line_in_file(pkg_name, manifest_file):
    """
    Search 'manifest_file' for 'pkg_name'.
    Return (line_number, line_content) if found, else (1, fallback).
    """
    if not manifest_file or not os.path.isfile(manifest_file):
        return 1, f"[No {manifest_file or 'manifest'} found in repo]"
    try:
        with open(manifest_file, "r", encoding="utf-8") as f:
            lines = f.readlines()
            for i, line in enumerate(lines, start=1):
                if pkg_name.lower() in line.lower():
                    return i, line.rstrip("\n")
    except Exception as e:
        return 1, f"[Error reading {manifest_file}: {e}]"
    return 1, f"[Package '{pkg_name}' not found in {manifest_file}]"

def convert_to_sarif(input_file, output_file):
    """
    Convert Socket JSON results into SARIF 2.1.0 for GitHub code scanning.
    - 'description' goes into rule.shortDescription and result.message.text
    - 'props.note' (if any) goes into rule.fullDescription for deeper details
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

    alerts = data.get("new_alerts", [])
    print(f"[DEBUG] Found {len(alerts)} 'new_alerts' in the data.")

    if not alerts:
        print("[INFO] 'new_alerts' is empty. Creating empty SARIF.")
        with open(output_file, "w", encoding="utf-8") as out:
            json.dump(sarif_data, out, indent=2)
        print(f"[DEBUG] Wrote empty SARIF to '{output_file}'.")
        return

    rules_map = {}
    results_list = []

    for idx, alert in enumerate(alerts, start=1):
        print(f"[DEBUG] Processing alert #{idx}: {alert}")

        # Gather fields
        rule_id     = alert.get("type", "unknown_type")
        title       = alert.get("title", "No Title")
        description = alert.get("description", "No description")
        severity    = alert.get("severity", "low")
        props       = alert.get("props", {})
        note_text   = props.get("note", "")

        # Introduced-by logic (which manifest file references this package?)
        introduced_list = alert.get("introduced_by", [])
        if introduced_list and isinstance(introduced_list[0], list) and len(introduced_list[0]) > 1:
            manifest_file = introduced_list[0][1]
        else:
            # Fallback if data is missing
            manifest_file = alert.get("manifests", "requirements.txt")

        pkg_name = alert.get("pkg_name", "unknown")
        line_number, line_content = find_line_in_file(pkg_name, manifest_file)

        # Create or update the rule for this alert type
        if rule_id not in rules_map:
            rule_obj = {
                "id": rule_id,
                "name": title,  # e.g. "Known malware"
                # shortDescription: smaller summary (from .description)
                "shortDescription": {"text": description},
                # fullDescription: the deeper “note” from props
                "fullDescription": {"text": note_text},
                "helpUri": "https://socket.dev",
                "defaultConfiguration": {
                    "level": map_severity_to_sarif(severity)
                }
            }
            rules_map[rule_id] = rule_obj

        # Build the result. The "message.text" is what GitHub code‐scanning
        # shows as the main line in the alert UI.
        result_obj = {
            "ruleId": rule_id,
            "message": {"text": description},  # e.g. “This package is malware...”
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": manifest_file
                        },
                        "region": {
                            "startLine": line_number,
                            "snippet": {"text": line_content}
                        }
                    }
                }
            ]
        }
        results_list.append(result_obj)

    # Populate the final SARIF structure
    sarif_data["runs"][0]["tool"]["driver"]["rules"] = list(rules_map.values())
    sarif_data["runs"][0]["results"] = results_list

    print(f"[DEBUG] Writing SARIF with {len(results_list)} results to '{output_file}'...")
    try:
        with open(output_file, "w", encoding="utf-8") as out:
            json.dump(sarif_data, out, indent=2)
        print(f"[INFO] SARIF file successfully written to '{output_file}'.")
    except Exception as e:
        print(f"[ERROR] Failed writing SARIF to '{output_file}': {e}")
        exit(1)

def main():
    parser = argparse.ArgumentParser(description="Convert Socket results to SARIF for GitHub code scanning.")
    parser.add_argument("--socket_results", required=True, help="Input JSON results from Socket CLI.")
    parser.add_argument("--output_file", required=True, help="Output SARIF file.")
    args = parser.parse_args()

    convert_to_sarif(args.socket_results, args.output_file)

if __name__ == "__main__":
    main()
