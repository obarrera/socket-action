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
        print(f"Loaded data from {input_file}: {json.dumps(data, indent=2)}")
    except json.JSONDecodeError as e:
        print(f"Failed to parse JSON from {input_file}: {e}")
        exit(1)
    except Exception as e:
        print(f"Unexpected error when loading {input_file}: {e}")
        exit(1)

    if "new_alerts" not in data or not data["new_alerts"]:
        print("No new alerts found in input data.")
        print("Ensure the CLI generated the expected output.")
        exit(0)

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

    for alert in data["new_alerts"]:
        try:
            rule = {
                "id": alert["type"],
                "name": alert["title"],
                "helpUri": "https://socket.dev",
                "shortDescription": {"text": alert["description"]},
                "fullDescription": {"text": alert["props"]["note"]},
                "defaultConfiguration": {
                    "level": map_severity_to_sarif(alert["severity"]),
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

        except KeyError as e:
            print(f"Missing key in alert data: {e}")
            continue
        except Exception as e:
            print(f"Unexpected error processing alert: {e}")
            continue

    print(f"Writing SARIF data to {output_file}...")
    with open(output_file, 'w') as f:
        json.dump(sarif_data, f, indent=2)
    print(f"SARIF file successfully written to {output_file}.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Convert Socket results to SARIF.")
    parser.add_argument("--socket_results", required=True, help="Input JSON results file.")
    parser.add_argument("--output_file", required=True, help="Output SARIF file.")
    args = parser.parse_args()

    convert_to_sarif(args.socket_results, args.output_file)
