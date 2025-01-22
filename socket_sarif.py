import json
import argparse

def convert_to_sarif(socket_results_path, output_file):
    try:
        print(f"Loading Socket results from: {socket_results_path}")
        with open(socket_results_path, 'r') as file:
            socket_results = json.load(file)

        print("Loaded Socket results:", json.dumps(socket_results, indent=2))

        if not socket_results or 'new_alerts' not in socket_results:
            raise ValueError("No new alerts found in Socket results.")

        # Define severity mapping
        severity_mapping = {
            "critical": "error",
            "high": "error",
            "medium": "warning",
            "low": "note"
        }

        sarif_data = {
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
                    "results": []
                }
            ]
        }

        for alert in socket_results.get("new_alerts", []):
            # Add rule information
            rule = {
                "id": alert["type"],
                "name": alert["title"],
                "shortDescription": {"text": alert["description"]},
                "fullDescription": {"text": alert["props"].get("note", "")},
                "defaultConfiguration": {"level": severity_mapping.get(alert["severity"], "note")},
                "help": {"text": alert["suggestion"]}
            }

            # Add result information
            result = {
                "ruleId": alert["type"],
                "message": {"text": alert["description"]},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": alert["manifests"], "uriBaseId": "%SRCROOT%"},
                            "region": {"startLine": 1, "startColumn": 1}
                        }
                    }
                ],
                "properties": {
                    "packageName": alert["pkg_name"],
                    "packageVersion": alert["pkg_version"],
                    "packageUrl": alert["url"]
                }
            }

            sarif_data["runs"][0]["tool"]["driver"]["rules"].append(rule)
            sarif_data["runs"][0]["results"].append(result)

        print("Generated SARIF data:", json.dumps(sarif_data, indent=2))

        with open(output_file, 'w') as out_file:
            json.dump(sarif_data, out_file, indent=2)

        print(f"SARIF file successfully created at: {output_file}")

    except json.JSONDecodeError as e:
        print(f"Error decoding JSON from {socket_results_path}: {e}")
        raise
    except Exception as e:
        print(f"Error while converting to SARIF: {e}")
        raise


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Convert Socket results to SARIF.")
    parser.add_argument("--socket_results", required=True, help="Path to the Socket results JSON file.")
    parser.add_argument("--output_file", required=True, help="Path to the output SARIF file.")
    args = parser.parse_args()

    convert_to_sarif(args.socket_results, args.output_file)
