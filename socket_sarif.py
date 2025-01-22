import json
import argparse
import os
from collections import defaultdict

def map_severity_to_sarif(severity):
    """
    Map severity levels from JSON to SARIF-compliant levels.
    :param severity: Severity level from JSON.
    :return: SARIF-compliant severity level.
    """
    severity_mapping = {
        "low": "note",
        "medium": "warning",
        "middle": "warning",  # Handle alternate naming
        "high": "error",
        "critical": "error"
    }
    return severity_mapping.get(severity.lower(), "note")

def parse_socket_results(socket_results):
    """
    Parse the JSON results from Socket and structure them for SARIF.
    """
    parsed_data = defaultdict(list)
    for issue in socket_results.get('issues', []):
        issue_type = issue.get('type', 'Unknown')
        label = issue.get('label', 'No Label')
        description = issue.get('description', 'No description provided.')
        severity = issue.get('value', {}).get('severity', 'Unknown')
        category = issue.get('value', {}).get('category', 'Unknown')
        props = issue.get('value', {}).get('props', {})

        # Extract properties
        notes = props.get('description', 'No additional notes provided.')
        title = props.get('title', 'No title provided.')
        url = props.get('url', 'No URL provided.')
        cwes = props.get('cwes', [])
        cvss_score = props.get('cvss', {}).get('score', 'No CVSS score provided.')

        # Parse locations
        locations = issue.get('value', {}).get('locations', [])
        location_details = []
        for loc in locations:
            loc_type = loc.get('type', 'Unknown')
            value = loc.get('value', {})
            package = value.get('package', 'Unknown Package')
            version = value.get('version', 'Unknown Version')
            file_info = value.get('file', {})
            file_path = file_info.get('path', 'Unknown Path')
            byte_range = file_info.get('bytes', {})

            location_details.append({
                "type": loc_type,
                "package": package,
                "version": version,
                "file_path": file_path,
                "bytes_start": byte_range.get('start', 'N/A'),
                "bytes_end": byte_range.get('end', 'N/A')
            })

        parsed_data[issue_type].append({
            "label": label,
            "description": description,
            "severity": map_severity_to_sarif(severity),
            "category": category,
            "locations": location_details,
            "props": {
                "notes": notes,
                "title": title,
                "url": url,
                "cwes": cwes,
                "cvss_score": cvss_score
            }
        })

    return parsed_data

def generate_sarif(parsed_data, output_file):
    """
    Generate SARIF file from parsed data.
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

    rule_map = {}

    for issue_type, issues in parsed_data.items():
        for issue in issues:
            rule_id = issue_type
            if rule_id not in rule_map:
                sarif["runs"][0]["tool"]["driver"]["rules"].append({
                    "id": rule_id,
                    "name": issue['label'],
                    "fullDescription": {"text": issue['description']},
                    "defaultConfiguration": {"level": issue['severity']},
                    "helpUri": issue['props']['url']
                })
                rule_map[rule_id] = len(sarif["runs"][0]["tool"]["driver"]["rules"]) - 1

            for loc in issue['locations']:
                sarif["runs"][0]["results"].append({
                    "ruleId": rule_id,
                    "ruleIndex": rule_map[rule_id],
                    "level": issue['severity'],
                    "message": {"text": issue['description']},
                    "locations": [
                        {
                            "physicalLocation": {
                                "artifactLocation": {"uri": loc['file_path']},
                                "region": {
                                    "startLine": loc['bytes_start'],
                                    "endLine": loc['bytes_end']
                                }
                            }
                        }
                    ],
                    "properties": {
                        "notes": issue['props']['notes'],
                        "title": issue['props']['title'],
                        "url": issue['props']['url'],
                        "cvss_score": issue['props']['cvss_score'],
                        "cwes": issue['props']['cwes']
                    }
                })

    with open(output_file, "w") as f:
        json.dump(sarif, f, indent=2)

    print(f"SARIF file generated at {output_file}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Generate SARIF file from Socket results.")
    parser.add_argument("--socket_results", required=True, help="Path to the Socket results JSON file.")
    parser.add_argument("--output_file", required=True, help="Path to save the SARIF file.")

    args = parser.parse_args()

    with open(args.socket_results, "r") as f:
        socket_results = json.load(f)

    parsed_data = parse_socket_results(socket_results)
    generate_sarif(parsed_data, args.output_file)
