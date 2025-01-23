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
    Convert Socket JSON results into SARIF 2.1.0 for GitHub code scanning, with
    the 'note' from Socket as the main message so the alert comment aligns with
    the detailed malware info.
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
        rule_id      = alert.get("type", "unknown_type")  # e.g. "malware"
        pkg_name     = alert.get("pkg_name", "unknown")
        pkg_version  = alert.get("pkg_version", "unknown")
        description  = alert.get("description", "No description")
        severity     = alert.get("severity", "low")
        props        = alert.get("props", {})
        # The long malware details we want to appear as the main “comment”
        note_text    = props.get("note", "[No detailed note found]")

        # For the rule name, include package info & the short “title”
        # e.g. "pycordwd==1.0.0 - Known malware"
        rule_name = f"{pkg_name}=={pkg_version} - {alert.get('title', 'Unknown')}"

        # Which manifest references this package?
        introduced_list = alert.get("introduced_by", [])
        if introduced_list and isinstance(introduced_list[0], list) and len(introduced_list[0]) > 1:
            manifest_file = introduced_list[0][1]
        else:
            manifest_file = alert.get("manifests", "requirements.txt")

        line_number, line_content = find_line_in_file(pkg_name, manifest_file)

        # If we have not seen this rule before, create it
        if rule_id not in rules_map:
            # shortDescription is typically short; use the alert's "description"
            # fullDescription can hold more info, or we can keep it simple
            # but we'll rely on the “note” primarily in the result.message below.
            rule_obj = {
                "id": rule_id,
                "name": rule_name,
                "shortDescription": {"text": description},
                "fullDescription": {"text": "Refer to the alert message for detailed info."},
                "helpUri": "https://socket.dev",
                "defaultConfiguration": {
                    "level": map_severity_to_sarif(severity)
                }
            }
            rules_map[rule_id] = rule_obj

        # Put the note_text in the main “message” so it shows up in the big comment box
        # (The short “description” is still stored in rule.shortDescription above.)
        message_text = (
            f"{note_text}\n\n"
            f"({pkg_name}=={pkg_version})\n\n"
            f"{description}"
        ).strip()

        result_obj = {
            "ruleId": rule_id,
            # The top line in GitHub’s code‐scanning UI = message.text
            # We combine the note, plus the package version, plus the short description
            "message": {"text": message_text},
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {"uri": manifest_file},
                        "region": {
                            "startLine": line_number,
                            "snippet": {"text": line_content}
                        }
                    }
                }
            ]
        }

        results_list.append(result_obj)

    # Populate the final SARIF
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
    parser = argparse.ArgumentParser(description="Convert Socket results to SARIF with the 'note' as the main message.")
    parser.add_argument("--socket_results", required=True, help="Input JSON results from Socket CLI.")
    parser.add_argument("--output_file", required=True, help="Output SARIF file.")
    args = parser.parse_args()

    convert_to_sarif(args.socket_results, args.output_file)

if __name__ == "__main__":
    main()
