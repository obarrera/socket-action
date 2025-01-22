import os
import sys
import json
import argparse

def map_severity_to_sarif(severity):
    severity_mapping = {
        "low": "note",
        "medium": "warning",
        "middle": "warning",
        "high": "error",
        "critical": "error"
    }
    return severity_mapping.get(severity.lower(), "note")

def generate_sarif_from_results(results, output_file):
    print("Generating SARIF data from results...")
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

    rules = {}
    for alert in results.get("new_alerts", []):
        rule_id = alert.get("type", "unknown")
        if rule_id not in rules:
            rules[rule_id] = {
                "id": rule_id,
                "shortDescription": {"text": alert.get("title", "Unknown alert")},
                "fullDescription": {"text": alert.get("description", "No description provided.")},
                "help": {
                    "text": alert.get("suggestion", "No suggestion provided."),
                    "markdown": f"[Learn more about this issue]({alert.get('next_step_title', 'https://socket.dev')})"
                }
            }

        sarif_data["runs"][0]["results"].append({
            "ruleId": rule_id,
            "level": map_severity_to_sarif(alert.get("severity", "note")),
            "message": {"text": alert.get("description", "No description provided.")},
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": alert.get("pkg_name", "unknown"),
                            "uriBaseId": "%SRCROOT%"
                        },
                        "region": {"startLine": 1, "startColumn": 1}
                    }
                }
            ]
        })

    sarif_data["runs"][0]["tool"]["driver"]["rules"] = list(rules.values())

    with open(output_file, "w") as f:
        json.dump(sarif_data, f, indent=2)
        print(f"SARIF file written to {output_file}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Convert Socket CLI or SBOM results to SARIF format.")
    parser.add_argument("--socket_results", required=True, help="Path to the results JSON file")
    parser.add_argument("--output_file", required=True, help="Path to save the SARIF output file")
    args = parser.parse_args()

    if not os.path.exists(args.socket_results) or os.path.getsize(args.socket_results) == 0:
        print(f"Error: Input file {args.socket_results} is missing or empty.")
        sys.exit(1)

    try:
        with open(args.socket_results, "r") as f:
            data = json.load(f)
    except json.JSONDecodeError as e:
        print(f"Error decoding JSON from {args.socket_results}: {e}")
        sys.exit(1)

    generate_sarif_from_results(data, args.output_file)
