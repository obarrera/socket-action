import json
import argparse
import os


def map_severity_to_sarif(severity):
    severity_mapping = {
        "low": "note",
        "medium": "warning",
        "middle": "warning",
        "high": "error",
        "critical": "error",
    }
    return severity_mapping.get(severity.lower(), "note")


def convert_to_sarif(input_file, output_file, repo_path):
    print(f"Loading results from {input_file}...")
    try:
        with open(input_file, 'r') as f:
            data = json.load(f)
    except json.JSONDecodeError as e:
        print(f"Failed to load input file: {e}. Check if the file is empty or invalid JSON.")
        exit(1)
    except Exception as e:
        print(f"Unexpected error reading input file: {e}")
        exit(1)

    if "new_alerts" not in data or not data["new_alerts"]:
        print("No alerts found in input file.")
        print("Debugging full scan ID:", data.get("full_scan_id", "N/A"))
        exit(0)  # Exit gracefully without failing the pipeline.

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

    for alert in data["new_alerts"]:
        # Add rule
        rule = {
            "id": alert["type"],
            "name": alert["title"],
            "helpUri": "https://socket.dev",
            "shortDescription": {"text": alert["description"]},
            "fullDescription": {"text": alert["props"].get("note", "")},
            "defaultConfiguration": {
                "level": map_severity_to_sarif(alert["severity"]),
            },
        }

        # Resolve file path
        file_path = alert.get("pkg_name", "unknown")
        if not os.path.isabs(file_path):
            file_path = os.path.join(repo_path, file_path)

        if not os.path.exists(file_path):
            print(f"Warning: File path {file_path} does not exist.")
            file_path = alert.get("pkg_name", "unknown")

        # Add result
        result = {
            "ruleId": alert["type"],
            "message": {"text": alert["description"]},
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {"uri": file_path},
                        "region": {
                            "startLine": alert.get("line", 1),
                            "startColumn": alert.get("column", 1),
                        },
                    }
                }
            ],
        }

        sarif_data["runs"][0]["tool"]["driver"]["rules"].append(rule)
        sarif_data["runs"][0]["results"].append(result)

    print(f"Writing SARIF data to {output_file}...")
    with open(output_file, 'w') as f:
        json.dump(sarif_data, f, indent=2)
    print(f"SARIF file successfully written to {output_file}.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Convert Socket results to SARIF.")
    parser.add_argument("--socket_results", required=True, help="Input JSON results file.")
    parser.add_argument("--output_file", required=True, help="Output SARIF file.")
    parser.add_argument("--repo_path", required=True, help="Repository root path.")
    args = parser.parse_args()

    convert_to_sarif(args.socket_results, args.output_file, args.repo_path)
