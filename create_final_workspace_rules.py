import os
import yaml

RULES_DIR = "/Users/raphaeleastment/Desktop/ScannerDetections/rules/google-workspace/rules"
PLAYBOOKS_DIR = "/Users/raphaeleastment/Desktop/ScannerDetections/rules/google-workspace/playbooks"

# Custom string class to force block style
class BlockScalarString(str):
    pass

def block_scalar_presenter(dumper, data):
    return dumper.represent_scalar('tag:yaml.org,2002:str', data, style='|')

yaml.add_representer(BlockScalarString, block_scalar_presenter)

NEW_RULES = [
    {
        "filename": "google_workspace_gmail_delegation_granted.yml",
        "name": "Google Workspace Gmail Delegation Granted",
        "description": """## Goal
Detects when a user grants Gmail access delegation to another account.

## Strategy
Monitor Google Workspace Gmail audit logs for `grant_delegated_access`. Attackers use delegation to access mailboxes without needing the victim's credentials for every login, often bypassing MFA checks during access.

## Triage and Response
1. Identify the delegator and the delegate.
2. Verify if the delegation is business-justified (e.g., executive assistant).
3. Remove the delegation and investigate the delegate account if unauthorized.""",
        "query_text": """%ingest.source_type:google_workspace
action:grant_delegated_access """,
        "severity": "Critical",
        "tags": ["google_workspace", "gmail", "persistence"]
    },
    {
        "filename": "google_workspace_user_recovery_information_changed.yml",
        "name": "Google Workspace User Recovery Information Changed",
        "description": """## Goal
Detects changes to a user's account recovery email or phone number.

## Strategy
Monitor Google Workspace User audit logs for `change_recovery_email` or `change_recovery_phone`. Attackers modify this to maintain persistence and regain access if the password is reset.

## Triage and Response
1. Identify the user.
2. Contact the user via an out-of-band method (e.g., Slack, Manager) to verify the change.
3. Revert the change and reset credentials if unauthorized.""",
        "query_text": """%ingest.source_type:google_workspace
action:change_recovery_email OR action:change_recovery_phone """,
        "severity": "High",
        "tags": ["google_workspace", "identity", "persistence"]
    },
    {
        "filename": "google_workspace_vault_retention_policy_modified.yml",
        "name": "Google Workspace Vault Retention Policy Modified",
        "description": """## Goal
Detects changes to Google Vault retention policies.

## Strategy
Monitor Google Workspace Vault audit logs for `change_retention_policy`. Malicious actors may shorten retention periods to destroy evidence of their activities (Defense Evasion).

## Triage and Response
1. Identify the admin performing the change.
2. Verify if the policy change was authorized by Legal/Compliance.
3. Revert the policy immediately to preserve data if unauthorized.""",
        "query_text": """%ingest.source_type:google_workspace
action:change_retention_policy """,
        "severity": "Critical",
        "tags": ["google_workspace", "vault", "defense_evasion"]
    },
    {
        "filename": "google_workspace_data_export_initiated_takeout.yml",
        "name": "Google Workspace Data Export Initiated (Takeout)",
        "description": """## Goal
Detects when a user initiates a Google Takeout data export.

## Strategy
Monitor Google Workspace audit logs for `takeout_initiated`. Takeout allows users to export their entire Google account data, representing a significant exfiltration risk.

## Triage and Response
1. Identify the user.
2. Verify if the export is authorized (e.g., departing employee).
3. Suspend the user and cancel the export if unauthorized.""",
        "query_text": """%ingest.source_type:google_workspace
action:takeout_initiated """,
        "severity": "High",
        "tags": ["google_workspace", "exfiltration", "insider_threat"]
    },
    {
        "filename": "google_workspace_suspicious_app_script_created.yml",
        "name": "Google Workspace Suspicious App Script Created",
        "description": """## Goal
Detects the creation or modification of Google App Scripts.

## Strategy
Monitor Google Workspace Drive/Script audit logs for `create_script` or `edit_script`. App Scripts can be used to automate data theft, send phishing emails, or modify files.

## Triage and Response
1. Identify the user and the script content.
2. Review the script's permissions and code.
3. Delete the script and suspend the user if malicious.""",
        "query_text": """%ingest.source_type:google_workspace
doc_type:script AND (action:create OR action:edit) """,
        "severity": "Medium",
        "tags": ["google_workspace", "scripting", "execution"]
    }
]

def main():
    if not os.path.exists(RULES_DIR):
        print(f"Error: Rules directory {RULES_DIR} does not exist.")
        return

    for rule in NEW_RULES:
        rule_path = os.path.join(RULES_DIR, rule['filename'])
        playbook_path = os.path.join(PLAYBOOKS_DIR, rule['filename'].replace('.yml', '_playbook.yml'))
        
        # Prepare Rule Data
        rule_data = {
            "schema": "https://scanner.dev/schema/scanner-detection-rule.v1.json",
            "name": rule['name'],
            "description": BlockScalarString(rule['description']),
            "enabled": True,
            "severity": rule['severity'],
            "query_text": BlockScalarString(rule['query_text']),
            "time_range_s": 3600,
            "run_frequency_s": 300,
            "event_sink_keys": [f"{rule['severity'].lower()}_severity_alerts"],
            "tags": rule['tags']
        }
        
        # Write Rule
        with open(rule_path, 'w') as f:
            f.write("# schema: https://scanner.dev/schema/scanner-detection-rule.v1.json\n")
            yaml.dump(rule_data, f, sort_keys=False, default_flow_style=False, width=1000)
            
        # Prepare Playbook Data
        # Extract sections from description
        parts = rule['description'].split('## Strategy')
        goal = parts[0].replace('## Goal', '').strip()
        rest = parts[1]
        parts2 = rest.split('## Triage and Response')
        strategy = parts2[0].strip()
        triage = parts2[1].strip()
        
        playbook_data = {
            "name": rule['name'] + " Playbook",
            "description": goal,
            "severity": rule['severity'],
            "steps": [
                {
                    "name": "Investigation",
                    "description": strategy
                },
                {
                    "name": "Triage",
                    "description": triage
                },
                {
                    "name": "Remediation",
                    "description": "Follow the Triage steps to contain and remediate."
                }
            ]
        }
        
        # Write Playbook
        with open(playbook_path, 'w') as f:
            yaml.dump(playbook_data, f, sort_keys=False, default_flow_style=False, width=1000)
            
        print(f"Created rule and playbook for {rule['filename']}")

if __name__ == "__main__":
    main()
