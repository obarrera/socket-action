import json
import argparse

def map_severity_to_sarif(severity):
    severity_mapping = {
        "low": "note",
        "medium": "warning",
        "middle": "warning",
        "high": "error",
        "critical": "error",
    }
    return severity_mapping.get(severity.lower(), "note")

def convert_to_sarif(input_file, output_file):
    print(f"Loading results from {input_file}...")
    try:
        with open(input_file, 'r') as f:
            data = json.load(f)
    except Exception as e:
        print(f"Failed to load input file: {e}")
        return  # Do not fail pipeline

    if not data or "new_alerts" not in data:
        print(f"No new alerts found in input file: {input_file}. Full data: {data}")
        return  # Do not fail pipeline

    sarif_data = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "Socket Security",
                        "informationUri": "https://socket.dev",
                        "rules": [],
                    }
                },
                "results": [],
            }
        ],
    }

    for alert in data.get("new_alerts", []):
        print(f"Processing alert: {alert}")
        rule = {
            "id": alert["type"],
            "name": alert["title"],
            "helpUri": "https://socket.dev",
            "shortDescription": {"text": alert["description"]},
            "fullDescription": {"text": alert.get("props", {}).get("note", "No additional details provided.")},
            "defaultConfiguration": {
                "level": map_severity_to_sarif(alert["severity"])
            },
        }

        result = {
            "ruleId": alert["type"],
            "message": {"text": alert["description"]},
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {"uri": alert["pkg_name"]},
                        "region": {"startLine": 1, "startColumn": 1},
                    }
                }
            ],
        }

        sarif_data["runs"][0]["tool"]["driver"]["rules"].append(rule)
        sarif_data["runs"][0]["results"].append(result)

    print(f"Final SARIF structure: {json.dumps(sarif_data, indent=2)}")

    try:
        print(f"Writing SARIF data to {output_file}...")
        with open(output_file, 'w') as f:
            json.dump(sarif_data, f, indent=2)
        print(f"SARIF file successfully written to {output_file}.")
    except Exception as e:
        print(f"Failed to write SARIF file: {e}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Convert Socket results to SARIF.")
    parser.add_argument("--socket_results", required=True, help="Input JSON results file.")
    parser.add_argument("--output_file", required=True, help="Output SARIF file.")
    args = parser.parse_args()

    convert_to_sarif(args.socket_results, args.output_file)
