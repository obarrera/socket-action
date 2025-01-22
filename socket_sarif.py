import json
import argparse
import time
import os


def retry_load_json(file_path, retries=3, delay=5):
    """Retry logic for loading JSON files."""
    for attempt in range(retries):
        try:
            with open(file_path, 'r') as f:
                return json.load(f)
        except json.JSONDecodeError as e:
            print(f"Failed to parse JSON on attempt {attempt + 1}: {e}")
            time.sleep(delay)
    print(f"File {file_path} is either missing or not valid JSON after {retries} retries.")
    return None


def map_severity_to_sarif(severity):
    """Map severity levels to SARIF levels."""
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
    data = retry_load_json(input_file)

    if not data or "new_alerts" not in data:
        print(f"No valid data found in {input_file}.")
        return

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

    for alert in data.get("new_alerts", []):
        rule = {
            "id": alert["type"],
            "name": alert["title"],
            "helpUri": "https://socket.dev",
            "shortDescription": {"text": alert["description"]},
            "fullDescription": {"text": alert["props"]["note"]},
            "defaultConfiguration": {
                "level": map_severity_to_sarif(alert["severity"])
            },
        }

        result = {
            "ruleId": alert["type"],
            "message": {"text": alert["description"]},
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {"uri": alert.get("pkg_name", "unknown")},
                        "region": {"startLine": 1, "startColumn": 1},
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
    args = parser.parse_args()

    convert_to_sarif(args.socket_results, args.output_file)
