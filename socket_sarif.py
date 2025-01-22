import json
import argparse
import time


def map_severity_to_sarif(severity):
    severity_mapping = {
        "low": "note",
        "medium": "warning",
        "middle": "warning",
        "high": "error",
        "critical": "error",
    }
    return severity_mapping.get(severity.lower(), "note")


def retry_load_json(file_path, retries=3, delay=5):
    """Retry loading JSON file in case it is incomplete or not ready."""
    for attempt in range(retries):
        try:
            with open(file_path, 'r') as f:
                data = json.load(f)
                return data
        except json.JSONDecodeError as e:
            print(f"Attempt {attempt + 1}/{retries}: JSONDecodeError - {e}. Retrying in {delay} seconds...")
            time.sleep(delay)
        except FileNotFoundError:
            print(f"Attempt {attempt + 1}/{retries}: File {file_path} not found. Retrying in {delay} seconds...")
            time.sleep(delay)
    print(f"Failed to load JSON file {file_path} after {retries} attempts.")
    return None


def convert_to_sarif(input_file, output_file):
    print(f"Loading results from {input_file}...")
    data = retry_load_json(input_file)
    if not data:
        print(f"Error: Could not load or parse {input_file}. Exiting gracefully.")
        exit(0)

    if "new_alerts" not in data or not data["new_alerts"]:
        print("No new alerts found in input data.")
        exit(0)

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
        try:
            rule = {
                "id": alert["type"],
                "name": alert["title"],
                "helpUri": "https://socket.dev",
                "shortDescription": {"text": alert["description"]},
                "fullDescription": {"text": alert["props"]["note"]},
                "defaultConfiguration": {
                    "level": map_severity_to_sarif(alert["severity"]),
                },
            }

            result = {
                "ruleId": alert["type"],
                "message": {"text": alert["description"]},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": alert["pkg_name"]},
                            "region": {"startLine": 1, "startColumn": 1},
                        }
                    }
                ],
            }

            sarif_data["runs"][0]["tool"]["driver"]["rules"].append(rule)
            sarif_data["runs"][0]["results"].append(result)

        except KeyError as e:
            print(f"Missing key in alert data: {e}")
            continue
        except Exception as e:
            print(f"Unexpected error processing alert: {e}")
            continue

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
