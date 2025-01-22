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


def fetch_code_snippet(file_path, line_number, num_lines=3):
    """Fetch code snippet around the given line number."""
    try:
        with open(file_path, 'r') as f:
            lines = f.readlines()
            start = max(0, line_number - 1)
            end = min(len(lines), line_number - 1 + num_lines)
            return ''.join(lines[start:end])
    except Exception as e:
        return f"Could not fetch snippet: {e}"


def convert_to_sarif(input_file, output_file, repo_path):
    print(f"Loading results from {input_file}...")
    try:
        with open(input_file, 'r') as f:
            data = json.load(f)
    except json.JSONDecodeError as e:
        print(f"Failed to load input file: {e}. Ensure the file is valid JSON.")
        exit(1)
    except Exception as e:
        print(f"Unexpected error reading input file: {e}")
        exit(1)

    if not data.get("new_alerts"):
        print("No new alerts found in input file.")
        print("Full scan ID:", data.get("full_scan_id", "N/A"))
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

        file_path = os.path.join(repo_path, alert.get("pkg_name", "unknown"))
        line_number = alert.get("line", 1)

        if os.path.exists(file_path):
            code_snippet = fetch_code_snippet(file_path, line_number)
        else:
            code_snippet = f"File {file_path} not found in repository."

        result = {
            "ruleId": alert["type"],
            "message": {"text": alert["description"]},
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {"uri": alert.get("pkg_name", "unknown")},
                        "region": {
                            "startLine": line_number,
                            "startColumn": 1,
                            "snippet": {"text": code_snippet},
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
