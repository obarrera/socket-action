import json
import argparse

# Severity mapping
SEVERITY_MAP = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "low": "note",
    "info": "note"
}

def convert_to_sarif(socket_results_path, output_file):
    try:
        # Debugging: Log file path
        print(f"Loading Socket results from: {socket_results_path}")

        # Load results from the Socket results JSON
        with open(socket_results_path, 'r') as file:
            socket_results = json.load(file)

        # Debugging: Log loaded JSON
        print("Loaded Socket results:")
        print(json.dumps(socket_results, indent=2))

        # Initialize SARIF template
        sarif_data = {
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

        # Populate SARIF rules and results
        for alert in socket_results.get('alerts', []):
            rule_id = alert.get('rule_id', 'unknown')
            description = alert.get('description', 'No description provided.')
            file_path = alert.get('file', 'unknown_file')
            severity = SEVERITY_MAP.get(alert.get('severity', 'info').lower(), 'note')

            # Debugging: Log each alert being processed
            print(f"Processing alert: {rule_id}, severity: {severity}, file: {file_path}")

            # Add rule
            sarif_data["runs"][0]["tool"]["driver"]["rules"].append({
                "id": rule_id,
                "shortDescription": {"text": description},
                "defaultConfiguration": {"level": severity}
            })

            # Add result
            sarif_data["runs"][0]["results"].append({
                "ruleId": rule_id,
                "message": {"text": description},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {
                                "uri": file_path,
                                "uriBaseId": "%SRCROOT%"
                            },
                            "region": {
                                "startLine": alert.get('line', 1),
                                "startColumn": alert.get('column', 1)
                            }
                        }
                    }
                ]
            })

        # Debugging: Log SARIF data before writing
        print("Generated SARIF data:")
        print(json.dumps(sarif_data, indent=2))

        # Write SARIF data to output file
        with open(output_file, 'w') as file:
            json.dump(sarif_data, file, indent=2)

        print(f"SARIF file successfully created at: {output_file}")

    except Exception as e:
        print(f"Error while converting to SARIF: {e}")
        raise

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Convert Socket results to SARIF format.")
    parser.add_argument("--socket_results", required=True, help="Path to Socket results JSON file.")
    parser.add_argument("--output_file", required=True, help="Path to output SARIF file.")

    args = parser.parse_args()

    convert_to_sarif(args.socket_results, args.output_file)
