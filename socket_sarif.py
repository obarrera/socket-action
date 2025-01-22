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
        exit(1)

    # Debug the raw data received
    print(f"Debug: Raw CLI JSON data: {json.dumps(data, indent=2)}")

    # Validate and ensure "new_alerts" exists
    if "new_alerts" not in data:
        print("Error: 'new_alerts' key is missing in the input data.")
        exit(1)

    if not data["new_alerts"]:
        print("No new alerts found in input data.")
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

    # Process each alert and debug individual alerts
    for alert in data.get("new_alerts", []):
        print(f"Debug: Processing alert: {json.dumps(alert, indent=2)}")

        try:
            rule = {
                "id": alert.get("type", "unknown"),
                "name": alert.get("title", "No Title Provided"),
                "helpUri": "https://socket.dev",
                "shortDescription": {
                    "text": alert.get("description", "No description available.")
                },
                "fullDescription": {
                    "text": alert.get("props", {}).get("note", "No additional information provided.")
                },
                "defaultConfiguration": {
                    "level": map_severity_to_sarif(alert.get("severity", "low"))
                },
            }

            result = {
                "ruleId": alert.get("type", "unknown"),
                "message": {
                    "text": alert.get("description", "No description available.")
                },
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {
                                "uri": alert.get("pkg_name", "unknown"),
                            },
                            "region": {
                                "startLine": 1,
                                "startColumn": 1,
                                "snippet": {
                                    "text": f"Package: {alert.get('pkg_name', 'unknown')}@{alert.get('pkg_version', 'unknown')}"
                                },
                            },
                        }
                    }
                ],
            }

            sarif_data["runs"][0]["tool"]["driver"]["rules"].append(rule)
            sarif_data["runs"][0]["results"].append(result)
        except Exception as e:
            print(f"Error processing alert: {e}")
            continue

    # Debug the final SARIF structure
    print(f"Debug: Final SARIF structure: {json.dumps(sarif_data, indent=2)}")

    # Write SARIF data to the output file
    print(f"Writing SARIF data to {output_file}...")
    try:
        with open(output_file, 'w') as f:
            json.dump(sarif_data, f, indent=2)
        print(f"SARIF file successfully written to {output_file}.")
    except Exception as e:
        print(f"Failed to write SARIF file: {e}")
        exit(1)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Convert Socket results to SARIF.")
    parser.add_argument("--socket_results", required=True, help="Input JSON results file.")
    parser.add_argument("--output_file", required=True, help="Output SARIF file.")
    args = parser.parse_args()

    convert_to_sarif(args.socket_results, args.output_file)
