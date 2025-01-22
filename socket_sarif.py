import json
import sys


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
    Convert Socket CLI results to SARIF format.
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

    for alert in socket_results.get("new_alerts", []):
        rule_id = alert.get("type", "unknown")
        description = alert.get("description", "No description provided.")
        severity = alert.get("severity", "low")
        package_name = alert.get("pkg_name", "unknown")
        package_version = alert.get("pkg_version", "unknown")

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
        sarif["runs"][0]["results"].append({
            "ruleId": rule_id,
            "message": {
                "text": description
            },
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": f"{package_name}@{package_version}"
                        }
                    }
                }
            ],
            "level": map_severity_to_sarif(severity)
        })

    # Write SARIF file
    with open(output_file, "w") as f:
        json.dump(sarif, f, indent=2)


if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: python socket_sarif.py --socket_results <socket_results.json> --output_file <output.sarif>")
        sys.exit(1)

    socket_results_file = sys.argv[sys.argv.index("--socket_results") + 1]
    output_file = sys.argv[sys.argv.index("--output_file") + 1]

    with open(socket_results_file, "r") as f:
        socket_results = json.load(f)

    convert_to_sarif(socket_results, output_file)
    print(f"SARIF file generated at {output_file}")
