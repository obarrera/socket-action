import json
import argparse
import os

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
        if not os.path.exists(socket_results_path):
            raise FileNotFoundError("Socket results file does not exist.")

        # Validate the file is not empty
        if os.stat(socket_results_path).st_size == 0:
            raise ValueError("Socket results file is empty.")

        # Load results from JSON
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

        # Process alerts and avoid duplicate rules
        processed_rules = set()
        for alert in socket_results.get('new_alerts', []):
            rule_id = alert.get('type', 'unknown') + "-" + alert.get('pkg_name')  # Unique rule ID per package
            description = alert.get('description', 'No description provided.')
            file_path = alert.get('manifests', 'unknown_file')
            severity = SEVERITY_MAP.get(alert.get('severity', 'info').lower(), 'note')
            alert_title = alert.get('title', 'Unknown issue')
            suggestion = alert.get('suggestion', 'No suggestion provided.')
            full_description = alert.get('props', {}).get('note', '')

            # Add unique rule if not already processed
            if rule_id not in processed_rules:
                sarif_data["runs"][0]["tool"]["driver"]["rules"].append({
                    "id": rule_id,
                    "name": alert_title,
                    "shortDescription": {"text": description},
                    "fullDescription": {"text": full_description},
                    "defaultConfiguration": {"level": severity},
                    "help": {"text": suggestion}
                })
                processed_rules.add(rule_id)

            # Debugging: Log each alert being processed
            print(f"Processing alert: {alert_title}, severity: {severity}, file: {file_path}")

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
                                "startLine": 1,
                                "startColumn": 1
                            }
                        }
                    }
                ],
                "properties": {
                    "packageName": alert.get('pkg_name'),
                    "packageVersion": alert.get('pkg_version'),
                    "packageUrl": alert.get('url'),
                    "introducedBy": alert.get('introduced_by', [])
                }
            })

        # Debugging: Log SARIF data before writing
        print("Generated SARIF data:")
        print(json.dumps(sarif_data, indent=2))

        # Write SARIF data to output file
        with open(output_file, 'w') as file:
            json.dump(sarif_data, file, indent=2)

        print(f"SARIF file successfully created at: {output_file}")

    except FileNotFoundError as fnfe:
        print(f"Error: {fnfe}")
        raise
    except ValueError as ve:
        print(f"Error: {ve}")
        raise
    except json.JSONDecodeError as jde:
        print("Error: Failed to parse JSON.")
        raise
    except Exception as e:
        print(f"Unexpected error: {e}")
        raise

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Convert Socket results to SARIF format.")
    parser.add_argument("--socket_results", required=True, help="Path to Socket results JSON file.")
    parser.add_argument("--output_file", required=True, help="Path to output SARIF file.")

    args = parser.parse_args()

    convert_to_sarif(args.socket_results, args.output_file)
