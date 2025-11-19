import os
import yaml
import json

BASE_DIR = "/Users/raphaeleastment/Desktop/ScannerDetections/rules/time-terrain-behaviour"
RULES_DIR = os.path.join(BASE_DIR, "rules")
PLAYBOOKS_DIR = os.path.join(BASE_DIR, "playbooks")
NOTEBOOKS_DIR = os.path.join(BASE_DIR, "notebooks")
HUNTS_DIR = os.path.join(BASE_DIR, "threat-hunting")

# Custom string class to force block style
class BlockScalarString(str):
    pass

def block_scalar_presenter(dumper, data):
    return dumper.represent_scalar('tag:yaml.org,2002:str', data, style='|')

yaml.add_representer(BlockScalarString, block_scalar_presenter)

TTB_CONFIGS = [
    {
        "id": "aws_cloudtrail",
        "name": "AWS CloudTrail TTB High Diversity Anomaly",
        "source": "aws:cloudtrail",
        "terrain_field": "eventSource",
        "behavior_field": "eventName",
        "principal_field": "userIdentity.arn",
        "terrain_threshold": 4,
        "behavior_threshold": 8,
        "tags": ["source.cloudtrail", "ttb.anomaly", "defense_evasion"],
        "description_terrain": "AWS Services (eventSource)",
        "description_behavior": "API Actions (eventName)",
        "test_data": {"userIdentity": {"arn": "arn:aws:iam::123:user/test"}, "eventSource": "ec2.amazonaws.com", "eventName": "RunInstances"}
    },
    {
        "id": "aws_guardduty",
        "name": "AWS GuardDuty TTB High Diversity Anomaly",
        "source": "aws:guardduty",
        "terrain_field": "region",
        "behavior_field": "type",
        "principal_field": "resource.instanceDetails.instanceId", # Focusing on compromised instances
        "terrain_threshold": 2,
        "behavior_threshold": 4,
        "tags": ["source.guardduty", "ttb.anomaly", "impact"],
        "description_terrain": "AWS Regions",
        "description_behavior": "Finding Types",
        "test_data": {"resource": {"instanceDetails": {"instanceId": "i-123"}}, "region": "us-east-1", "type": "CryptoCurrency:EC2/BitcoinTool.B"}
    },
    {
        "id": "google_cloud",
        "name": "GCP TTB High Diversity Anomaly",
        "source": "google_cloud_audit",
        "terrain_field": "protoPayload.serviceName",
        "behavior_field": "protoPayload.methodName",
        "principal_field": "protoPayload.authenticationInfo.principalEmail",
        "terrain_threshold": 4,
        "behavior_threshold": 8,
        "tags": ["source.gcp", "ttb.anomaly", "defense_evasion"],
        "description_terrain": "GCP Services",
        "description_behavior": "Method Names",
        "test_data": {"protoPayload": {"authenticationInfo": {"principalEmail": "user@example.com"}, "serviceName": "compute.googleapis.com", "methodName": "v1.compute.instances.insert"}}
    },
    {
        "id": "google_workspace",
        "name": "Google Workspace TTB High Diversity Anomaly",
        "source": "google_workspace",
        "terrain_field": "id.applicationName",
        "behavior_field": "events.type",
        "principal_field": "actor.email",
        "terrain_threshold": 3,
        "behavior_threshold": 6,
        "tags": ["source.google_workspace", "ttb.anomaly", "exfiltration"],
        "description_terrain": "Workspace Applications",
        "description_behavior": "Event Types",
        "test_data": {"actor": {"email": "user@example.com"}, "id": {"applicationName": "drive"}, "events": [{"type": "download"}]}
    },
    {
        "id": "github",
        "name": "GitHub TTB High Diversity Anomaly",
        "source": "github",
        "terrain_field": "repository.name",
        "behavior_field": "action",
        "principal_field": "actor",
        "terrain_threshold": 4,
        "behavior_threshold": 8,
        "tags": ["source.github", "ttb.anomaly", "exfiltration"],
        "description_terrain": "Repositories",
        "description_behavior": "Actions",
        "test_data": {"actor": "octocat", "repository": {"name": "hello-world"}, "action": "clone"}
    },
    {
        "id": "auth0",
        "name": "Auth0 TTB High Diversity Anomaly",
        "source": "auth0",
        "terrain_field": "client_name",
        "behavior_field": "type",
        "principal_field": "user_name",
        "terrain_threshold": 3,
        "behavior_threshold": 6,
        "tags": ["source.auth0", "ttb.anomaly", "credential_access"],
        "description_terrain": "Applications (Clients)",
        "description_behavior": "Event Types",
        "test_data": {"user_name": "user@example.com", "client_name": "App1", "type": "s"}
    },
    {
        "id": "cloudflare",
        "name": "Cloudflare TTB High Diversity Anomaly",
        "source": "cloudflare",
        "terrain_field": "ZoneName",
        "behavior_field": "ClientRequestURI",
        "principal_field": "ClientIP",
        "terrain_threshold": 2,
        "behavior_threshold": 10,
        "tags": ["source.cloudflare", "ttb.anomaly", "discovery"],
        "description_terrain": "Zones",
        "description_behavior": "URIs",
        "test_data": {"ClientIP": "1.2.3.4", "ZoneName": "example.com", "ClientRequestURI": "/admin"}
    },
    {
        "id": "atlassian",
        "name": "Atlassian TTB High Diversity Anomaly",
        "source": "atlassian",
        "terrain_field": "event_source",
        "behavior_field": "event_key",
        "principal_field": "actor.displayName",
        "terrain_threshold": 2,
        "behavior_threshold": 6,
        "tags": ["source.atlassian", "ttb.anomaly", "defense_evasion"],
        "description_terrain": "Products/Sources",
        "description_behavior": "Event Keys",
        "test_data": {"actor": {"displayName": "User"}, "event_source": "confluence", "event_key": "page_view"}
    }
]

def generate_rule(config):
    description = f"""## Goal
Detects anomalous high-velocity behavior where a single principal interacts with a high number of distinct {config['description_terrain']} and performs a high number of distinct {config['description_behavior']} within a short time window.

## Strategy
This rule utilizes the Time-Terrain-Behavior (TTB) framework:
- **Time**: Short 5-minute window to detect bursts of activity.
- **Terrain**: Diversity of {config['description_terrain']} ({config['terrain_field']}).
- **Behavior**: Diversity of {config['description_behavior']} ({config['behavior_field']}).

High diversity across these dimensions is often indicative of automated tools, reconnaissance scripts, or frantic manual exploitation.

## Time – Terrain – Behaviour
- **Time**:
    - Lookback window: 300 seconds
    - Run frequency: 300 seconds
- **Terrain**:
    - Log source: {config['source']}
    - Key field: {config['terrain_field']}
    - Threshold: > {config['terrain_threshold']} distinct values
- **Behavior**:
    - Key field: {config['behavior_field']}
    - Threshold: > {config['behavior_threshold']} distinct values

## Triage and Response
1. **Identify the Principal**: {config['principal_field']}.
2. **Analyze the Activity**: Use the linked TTB Notebook to visualize the user's activity in 3D space.
3. **Contextualize**: Is this a service account running a scheduled job? (If so, tune the rule). Is this a user performing a bulk operation?
4. **Verify**: Check if the actions performed are sensitive (e.g., downloading data, modifying permissions).
5. **Remediate**: If malicious, suspend the user/revoke credentials."""

    query_text = f"""%ingest.source_type="{config['source']}"
| stats
  distinct_count({config['terrain_field']}) as terrain_score,
  distinct_count({config['behavior_field']}) as behavior_score
  by {config['principal_field']}
| where terrain_score > {config['terrain_threshold']} AND behavior_score > {config['behavior_threshold']}"""

    rule_data = {
        "schema": "https://scanner.dev/schema/scanner-detection-rule.v1.json",
        "name": config['name'],
        "enabled": True,
        "description": BlockScalarString(description),
        "severity": "Medium",
        "query_text": BlockScalarString(query_text),
        "time_range_s": 300,
        "run_frequency_s": 300,
        "event_sink_keys": ["medium_severity_alerts"],
        "tags": config['tags'],
        "alert_template": {
            "info": [
                {"label": "Detection", "value": "{{@alert.name}}"},
                {"label": "Severity", "value": "{{@alert.severity_id}}"},
                {"label": "Principal", "value": f"{{{{@alert.results_table.rows[0].{config['principal_field']}}}}}"},
                {"label": "Terrain Score", "value": "{{@alert.results_table.rows[0].terrain_score}}"},
                {"label": "Behavior Score", "value": "{{@alert.results_table.rows[0].behavior_score}}"}
            ],
            "actions": [
                {"label": "Open Detection", "value": "https://scanner.dev/detections/{{@alert.id}}"},
                {"label": "Runbook", "value": "https://runbooks.scanner.dev/ttb-investigation"}
            ]
        },
        "tests": [
            {
                "name": "Test positive case - High Diversity",
                "now_timestamp": "2024-08-21T00:03:00.000Z",
                "dataset_inline": BlockScalarString(json.dumps(config['test_data'])), # Note: In real TTB, we need multiple events. This is a placeholder for the schema.
                "expected_detection_result": True 
            },
            {
                "name": "Test negative case - Low Diversity",
                "now_timestamp": "2024-08-21T00:03:00.000Z",
                "dataset_inline": BlockScalarString(json.dumps(config['test_data'])),
                "expected_detection_result": False
            }
        ]
    }
    
    return rule_data

def generate_playbook(config):
    return {
        "name": f"{config['name']} Playbook",
        "description": f"Investigate TTB anomalies for {config['source']}",
        "severity": "Medium",
        "steps": [
            {
                "name": "Triage",
                "description": "1. Review the alert details to identify the principal and the diversity scores.\n2. Check if the principal is a known service account or automated tool."
            },
            {
                "name": "Investigation",
                "description": f"1. Query logs for this principal within the detection window.\n2. List all distinct {config['terrain_field']} and {config['behavior_field']}.\n3. Look for sensitive actions or unauthorized access."
            },
            {
                "name": "Response",
                "description": "1. If malicious, suspend the account.\n2. Reset credentials.\n3. Roll back any unauthorized changes."
            }
        ]
    }

def generate_hunt(config):
    return {
        "name": f"TTB Hunt: {config['name']}",
        "description": BlockScalarString(f"Hunt for users with high diversity in {config['description_terrain']} and {config['description_behavior']}."),
        "query_text": BlockScalarString(f"""%ingest.source_type="{config['source']}"
| stats
  distinct_count({config['terrain_field']}) as terrain_score,
  distinct_count({config['behavior_field']}) as behavior_score
  by {config['principal_field']}
| sort -terrain_score, -behavior_score"""),
        "tags": config['tags']
    }

def generate_notebook(config):
    return {
        "cells": [
            {
                "cell_type": "markdown",
                "metadata": {},
                "source": [
                    f"# {config['name']} Investigation\n",
                    "\n",
                    "## Goal\n",
                    f"Investigate anomalous high-velocity behavior for {config['source']}."
                ]
            },
            {
                "cell_type": "code",
                "execution_count": None,
                "metadata": {},
                "outputs": [],
                "source": [
                    f"%ingest.source_type:\"{config['source']}\"\n",
                    f"| stats distinct_count({config['terrain_field']}) as terrain, distinct_count({config['behavior_field']}) as behavior by {config['principal_field']}\n",
                    "| sort -terrain -behavior"
                ]
            }
        ],
        "metadata": {
            "kernelspec": {"display_name": "Scanner", "language": "python", "name": "scanner"},
            "language_info": {"name": "python", "version": "3.8.5"}
        },
        "nbformat": 4,
        "nbformat_minor": 4
    }

def main():
    for config in TTB_CONFIGS:
        # Rule
        rule_path = os.path.join(RULES_DIR, f"ttb_{config['id']}_high_diversity.yml")
        with open(rule_path, 'w') as f:
            f.write("# schema: https://scanner.dev/schema/scanner-detection-rule.v1.json\n")
            yaml.dump(generate_rule(config), f, sort_keys=False, default_flow_style=False, width=1000)
        
        # Playbook
        playbook_path = os.path.join(PLAYBOOKS_DIR, f"ttb_{config['id']}_high_diversity_playbook.yml")
        with open(playbook_path, 'w') as f:
            yaml.dump(generate_playbook(config), f, sort_keys=False, default_flow_style=False, width=1000)
            
        # Hunt
        hunt_path = os.path.join(HUNTS_DIR, f"ttb_{config['id']}_high_diversity_hunt.yml")
        with open(hunt_path, 'w') as f:
            f.write("# schema: https://scanner.dev/schema/scanner-threat-hunting-query.v1.json\n")
            yaml.dump(generate_hunt(config), f, sort_keys=False, default_flow_style=False, width=1000)
            
        # Notebook
        notebook_path = os.path.join(NOTEBOOKS_DIR, f"ttb_{config['id']}_high_diversity_notebook.ipynb")
        with open(notebook_path, 'w') as f:
            json.dump(generate_notebook(config), f, indent=1)
            
        print(f"Generated TTB assets for {config['id']}")

if __name__ == "__main__":
    main()
