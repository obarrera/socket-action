import json
import argparse

def map_severity_to_sarif(severity):
    """
    Map severity levels to SARIF-compliant levels.
    """
    severity_mapping = {
        "low": "note",
        "medium": "warning",
        "middle": "warning",  # Handle alternate naming
        "high": "error",
        "critical": "error"
    }
    return severity_mapping.get(severity.lower(), "note")

def generate_sarif(socket_results, output_file):
    """
    Generate a SARIF file from the Socket results.
    """
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

    print("Processing alerts in Socket results...")
    for alert in socket_results.get("new_alerts", []):
        pkg_name = alert["pkg_name"]
        pkg_version = alert["pkg_version"]
        severity = map_severity_to_sarif(alert["severity"])
        description = alert.get("description", "No description provided.")
        note = alert["props"].get("note", "No additional information available.")
        recommendation = alert.get("suggestion", "No recommendations provided.")

        print(f"Adding alert for package {pkg_name}@{pkg_version} with severity {severity}.")

        sarif_data["runs"][0]["results"].append({
            "ruleId": alert["type"],
            "ruleIndex": 0,
            "level": severity,
            "message": {
                "text": f"{description}\n\n{note}\n\nRecommendation: {recommendation}"
            },
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": f"{pkg_name}@{pkg_version}"
                        }
                    }
                }
            ]
        })

    print("Writing SARIF file...")
    with open(output_file, "w") as f:
        json.dump(sarif_data, f, indent=2)
    print(f"SARIF file written successfully to {output_file}.")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Convert Socket results to SARIF.")
    parser.add_argument("--socket_results", required=True, help="Path to the Socket results JSON file.")
    parser.add_argument("--output_file", required=True, help="Path to save the generated SARIF file.")

    args = parser.parse_args()

    print(f"Loading Socket CLI results from {args.socket_results}...")
    try:
        with open(args.socket_results, "r") as f:
            socket_results = json.load(f)
    except json.JSONDecodeError as e:
        print(f"Error: Failed to parse JSON file {args.socket_results}. {e}")
        exit(1)

    print("Processing Socket CLI results...")
    generate_sarif(socket_results, args.output_file)
    print("SARIF generation completed.")
