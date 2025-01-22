import json
import argparse
import os


def debug_input_file(input_file):
    """Check the file's existence and print debug information."""
    if not os.path.exists(input_file):
        print(f"Error: File {input_file} does not exist.")
        return False
    if os.path.getsize(input_file) == 0:
        print(f"Error: File {input_file} is empty.")
        return False
    return True


def convert_to_sarif(input_file, output_file, repo_path):
    print(f"Loading results from {input_file}...")
    if not debug_input_file(input_file):
        print("Ensure the CLI generated a valid output.")
        exit(1)

    try:
        with open(input_file, "r") as f:
            data = json.load(f)
    except json.JSONDecodeError as e:
        print(f"Failed to parse JSON from {input_file}: {e}")
        exit(1)

    if not data.get("new_alerts"):
        print("No new alerts found in input file.")
        print(f"Full scan ID: {data.get('full_scan_id', 'N/A')}")
        return  # Do not exit, allow the workflow to continue

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
        rule = {
            "id": alert["type"],
            "name": alert["title"],
            "helpUri": "https://socket.dev",
            "shortDescription": {"text": alert["description"]},
            "fullDescription": {"text": alert["props"].get("note", "")},
            "defaultConfiguration": {
                "level": alert["severity"].lower()
            },
        }

        result = {
            "ruleId": alert["type"],
            "message": {"text": alert["description"]},
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {"uri": alert.get("pkg_name", "unknown")},
                        "region": {"startLine": 1},
                    }
                }
            ],
        }

        sarif_data["runs"][0]["tool"]["driver"]["rules"].append(rule)
        sarif_data["runs"][0]["results"].append(result)

    print(f"Writing SARIF data to {output_file}...")
    with open(output_file, "w") as f:
        json.dump(sarif_data, f, indent=2)
    print(f"SARIF file successfully written to {output_file}.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Convert Socket results to SARIF.")
    parser.add_argument("--socket_results", required=True, help="Input JSON results file.")
    parser.add_argument("--output_file", required=True, help="Output SARIF file.")
    parser.add_argument("--repo_path", required=True, help="Repository root path.")
    args = parser.parse_args()

    convert_to_sarif(args.socket_results, args.output_file, args.repo_path)
