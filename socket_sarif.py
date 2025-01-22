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

        # Validate the file path
        if not socket_results_path:
            raise FileNotFoundError("Socket results path is empty or not provided.")

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

        # Process each new alert in the results
        for alert in socket_results.get('new_alerts', []):
            rule_id = alert.get('type', 'unknown')
            description = alert.get('description', 'No description provided.')
            file_path = alert.get('manifests', 'unknown_file')
            severity = SEVERITY_MAP.get(alert.get('severity', 'info').lower(), 'note')
            alert_title = alert.get('title', 'Unknown issue')
            suggestion = alert.get('suggestion', 'No suggestion provided.')

            # Debugging: Log each alert being processed
            print(f"Processing alert: {alert_title}, severity: {severity}, file: {file_path}")

            # Add rule to SARIF
            sarif_data["runs"][0]["tool"]["driver"]["rules"].append({
                "id": rule_id,
                "name": alert_title,
                "shortDescription": {"text": description},
                "fullDescription": {"text": alert.get('props', {}).get('note', '')},
                "defaultConfiguration": {"level": severity},
                "help": {"text": suggestion}
            })

            # Add result to SARIF
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
                                "startLine": 1,  # Assuming the alert applies to the entire file
                                "startColumn": 1
                            }
                        }
                    }
                ],
                "properties": {
                    "packageName": alert.get('pkg_name'),
                    "packageVersion": alert.get('pkg_version'),
                    "packageUrl": alert.get('url')
                }
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
