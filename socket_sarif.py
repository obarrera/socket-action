import json
import sys
import os


def map_severity_to_sarif(severity):
    """
    Map severity levels from Socket CLI to SARIF severity.
    """
    severity_mapping = {
        "low": "note",
        "medium": "warning",
        "middle": "warning",  # Handle alternate naming
        "high": "error",
        "critical": "error"
    }
    return severity_mapping.get(severity.lower(), "note")


def convert_to_sarif(socket_results, output_file):
    """
    Convert Socket CLI results to SARIF format with verbose debug output.
    """
    sarif = {
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

    print("Processing Socket CLI results...")
    for alert in socket_results.get("new_alerts", []):
        rule_id = alert.get("type", "unknown")
        description = alert.get("description", "No description provided.")
        severity = alert.get("severity", "low")
        package_name = alert.get("pkg_name", "unknown")
        package_version = alert.get("pkg_version", "unknown")
        additional_note = alert.get("props", {}).get("note", "No additional information provided.")
        suggestion = alert.get("suggestion", "No remediation steps provided.")

        # Add rule if it doesn't exist
        existing_rules = [rule["id"] for rule in sarif["runs"][0]["tool"]["driver"]["rules"]]
        if rule_id not in existing_rules:
            sarif["runs"][0]["tool"]["driver"]["rules"].append({
                "id": rule_id,
                "name": alert.get("title", "Unknown Issue"),
                "fullDescription": {
                    "text": description
                },
                "defaultConfiguration": {
                    "level": map_severity_to_sarif(severity)
                },
                "helpUri": alert.get("props", {}).get("helpUri", "https://socket.dev")
            })

        # Add result
        uri_path = os.path.join("package", f"{package_name}@{package_version}")
        print(f"Adding result for package: {package_name}@{package_version}")
        sarif["runs"][0]["results"].append({
            "ruleId": rule_id,
            "message": {
                "text": f"{description}\n\nAdditional Information:\n{additional_note}\n\nSuggested Remediation:\n{suggestion}"
            },
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": uri_path  # Use local path format
                        },
                        "region": {
                            "startLine": 1,
                            "startColumn": 1
                        }
                    }
                }
            ],
            "relatedLocations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": f"https://socket.dev/pypi/package/{package_name}/overview/{package_version}"
                        }
                    },
                    "message": {
                        "text": f"View package details for {package_name}@{package_version}"
                    }
                }
            ],
            "partialFingerprints": {
                "primaryLocationLineHash": alert.get("key", "unknown-key")
            },
            "level": map_severity_to_sarif(severity)
        })

    print(f"Writing SARIF file to {output_file}...")
    with open(output_file, "w") as f:
        json.dump(sarif, f, indent=2)
    print(f"SARIF file written successfully to {output_file}")


if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: python socket_sarif.py --socket_results <socket_results.json> --output_file <output.sarif>")
        sys.exit(1)

    socket_results_file = sys.argv[sys.argv.index("--socket_results") + 1]
    output_file = sys.argv[sys.argv.index("--output_file") + 1]

    print(f"Loading Socket CLI results from {socket_results_file}...")
    with open(socket_results_file, "r") as f:
        socket_results = json.load(f)

    convert_to_sarif(socket_results, output_file)
    print(f"SARIF generation completed. File saved at {output_file}.")
