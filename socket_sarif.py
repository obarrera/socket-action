import json
import argparse

def map_severity_to_sarif(severity):
    severity_mapping = {
        "low": "note",
        "medium": "warning",
        "middle": "warning",
        "high": "error",
        "critical": "error",
    }
    return severity_mapping.get(severity.lower(), "note")

def fetch_code_snippet(file_path, start_line, num_lines=3):
    try:
        with open(file_path, 'r') as f:
            lines = f.readlines()
            return ''.join(lines[start_line - 1: start_line - 1 + num_lines])
    except Exception as e:
        return f"Could not fetch snippet: {e}"

def convert_to_sarif(input_file, output_file):
    print(f"Loading results from {input_file}...")
    try:
        with open(input_file, 'r') as f:
            data = json.load(f)
        # Debugging: Log loaded JSON data
        print(f"Loaded data from {input_file}: {json.dumps(data, indent=2)}")
    except Exception as e:
        print(f"Failed to load input file: {e}")
        exit(1)

    if "new_alerts" not in data or not data.get("new_alerts", []):
        print("No alerts found in input file.")
        #exit(1)

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

    for i, alert in enumerate(data.get("new_alerts", []), start=1):
        # Debugging: Log individual alert data
        print(f"Processing alert #{i}: {json.dumps(alert, indent=2)}")

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

        file_path = alert.get("pkg_name", "unknown")
        start_line = 1  # Default to the first line if not provided

        # Add a code snippet if the file exists
        code_snippet = fetch_code_snippet(file_path, start_line)
        # Debugging: Log code snippet information
        print(f"Code snippet for alert #{i} (file: {file_path}): {code_snippet}")

        result = {
            "ruleId": alert["type"],
            "message": {"text": alert["description"]},
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {"uri": file_path},
                        "region": {"startLine": start_line, "snippet": {"text": code_snippet}},
                    }
                }
            ],
        }

        sarif_data["runs"][0]["tool"]["driver"]["rules"].append(rule)
        sarif_data["runs"][0]["results"].append(result)

    # Debugging: Log the final SARIF structure
    print("Final SARIF structure:")
    print(json.dumps(sarif_data, indent=2))

    print(f"Writing SARIF data to {output_file}...")
    with open(output_file, 'w') as f:
        json.dump(sarif_data, f, indent=2)
    print(f"SARIF file successfully written to {output_file}.")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Convert Socket results to SARIF.")
    parser.add_argument("--socket_results", required=True, help="Input JSON results file.")
    parser.add_argument("--output_file", required=True, help="Output SARIF file.")
    args = parser.parse_args()

    # Debugging: Log script arguments
    print(f"Input file: {args.socket_results}")
    print(f"Output file: {args.output_file}")

    convert_to_sarif(args.socket_results, args.output_file)
