import json
import argparse
import os

def map_severity_to_sarif(severity):
    severity_mapping = {
        "low": "note",
        "medium": "warning",
        "middle": "warning",  # Handle alternate naming
        "high": "error",
        "critical": "error",
    }
    return severity_mapping.get(severity.lower(), "note")

def generate_sarif(socket_results_path, output_file):
    with open(socket_results_path, 'r') as f:
        socket_results = json.load(f)

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

    for alert in socket_results.get('new_alerts', []):
        pkg_name = alert['pkg_name']
        pkg_version = alert['pkg_version']
        severity = map_severity_to_sarif(alert['severity'])
        description = alert['description']
        note = alert['props'].get('note', '')

        result = {
            "ruleId": alert['type'],
            "level": severity,
            "message": {
                "text": f"{description}\n\n{note}"
            },
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": f"{pkg_name}@{pkg_version}",
                            "uriBaseId": "%SRCROOT%"
                        }
                    }
                }
            ]
        }
        sarif_data['runs'][0]['results'].append(result)

    with open(output_file, 'w') as f:
        json.dump(sarif_data, f, indent=2)
    print(f"SARIF file written successfully to {output_file}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Convert Socket CLI results to SARIF format.")
    parser.add_argument("--socket_results", required=True, help="Path to the Socket CLI results JSON file.")
    parser.add_argument("--output_file", required=True, help="Path to the output SARIF file.")
    args = parser.parse_args()

    if not os.path.exists(args.socket_results):
        print(f"Error: {args.socket_results} does not exist.")
        exit(1)

    generate_sarif(args.socket_results, args.output_file)
