import os
import sys
import json
import argparse

def sanitize_uri(uri):
    if uri.startswith("file://"):
        return uri.replace("file://", "")
    if uri.startswith("https://"):
        return uri
    return f"file://{uri}"

def map_severity_to_sarif(severity):
    severity_mapping = {
        "low": "note",
        "medium": "warning",
        "middle": "warning",  # Handle alternate naming
        "high": "error",
        "critical": "error"
    }
    return severity_mapping.get(severity.lower(), "note")

def generate_sarif(results, output_file):
    print("Generating SARIF data...")
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

    for alert in results.get("new_alerts", []):
        result = {
            "ruleId": alert.get("type", "unknown"),
            "level": map_severity_to_sarif(alert.get("severity", "note")),
            "message": {
                "text": alert.get("description", "No description provided.")
            },
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": sanitize_uri(alert.get("pkg_name", "unknown")),
                            "uriBaseId": "%SRCROOT%"
                        },
                        "region": {
                            "startLine": 1,
                            "startColumn": 1
                        }
                    }
                }
            ]
        }
        sarif_data["runs"][0]["results"].append(result)

    with open(output_file, "w") as f:
        json.dump(sarif_data, f, indent=2)
        print(f"SARIF file written successfully to {output_file}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Convert Socket CLI results to SARIF format.")
    parser.add_argument("--socket_results", required=True, help="Path to the socket_results.json file")
    parser.add_argument("--output_file", required=True, help="Path to save the SARIF output file")
    args = parser.parse_args()

    if not os.path.exists(args.socket_results) or os.path.getsize(args.socket_results) == 0:
        print(f"Error: Input file {args.socket_results} is missing or empty.")
        sys.exit(1)

    try:
        with open(args.socket_results, "r") as f:
            socket_results = json.load(f)
    except json.JSONDecodeError as e:
        print(f"Error decoding JSON from {args.socket_results}: {e}")
        sys.exit(1)

    generate_sarif(socket_results, args.output_file)
