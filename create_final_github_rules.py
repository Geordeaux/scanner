import os
import yaml

RULES_DIR = "/Users/raphaeleastment/Desktop/ScannerDetections/rules/github/rules"
PLAYBOOKS_DIR = "/Users/raphaeleastment/Desktop/ScannerDetections/rules/github/playbooks"

# Custom string class to force block style
class BlockScalarString(str):
    pass

def block_scalar_presenter(dumper, data):
    return dumper.represent_scalar('tag:yaml.org,2002:str', data, style='|')

yaml.add_representer(BlockScalarString, block_scalar_presenter)

NEW_RULES = [
    {
        "filename": "github_webhook_created_modified.yml",
        "name": "GitHub Webhook Created or Modified",
        "description": """## Goal
Detects the creation or modification of a GitHub webhook.

## Strategy
Monitor GitHub audit logs for `hook.create` or `hook.config_changed`. Attackers may create webhooks to exfiltrate repository events and data to external servers.

## Triage and Response
1. Identify the repository and the webhook URL.
2. Verify if the webhook destination is authorized.
3. Remove the webhook immediately if unauthorized.""",
        "query_text": """%ingest.source_type:github
action:hook.create OR action:hook.config_changed """,
        "severity": "High",
        "tags": ["github", "persistence", "exfiltration"]
    },
    {
        "filename": "github_user_ssh_key_added.yml",
        "name": "GitHub User SSH Key Added",
        "description": """## Goal
Detects when an SSH key is added to a user account.

## Strategy
Monitor GitHub audit logs for `public_key.create`. Adding an SSH key allows access to all repositories the user has permissions for.

## Triage and Response
1. Identify the user and the key fingerprint.
2. Verify if the user added this key from a known device.
3. Revoke the key immediately if unauthorized.""",
        "query_text": """%ingest.source_type:github
action:public_key.create """,
        "severity": "High",
        "tags": ["github", "iam", "persistence"]
    },
    {
        "filename": "github_user_gpg_key_added.yml",
        "name": "GitHub User GPG Key Added",
        "description": """## Goal
Detects when a GPG key is added to a user account.

## Strategy
Monitor GitHub audit logs for `gpg_key.create`. GPG keys are used to sign commits; an attacker could use a stolen or unauthorized key to sign malicious commits.

## Triage and Response
1. Identify the user and the key ID.
2. Verify if the user added this key.
3. Revoke the key immediately if unauthorized.""",
        "query_text": """%ingest.source_type:github
action:gpg_key.create """,
        "severity": "High",
        "tags": ["github", "iam", "integrity"]
    },
    {
        "filename": "github_environment_secret_accessed.yml",
        "name": "GitHub Environment Secret Accessed",
        "description": """## Goal
Detects access to GitHub environment secrets.

## Strategy
Monitor GitHub audit logs for `environment.get_secrets`. Unauthorized access to secrets can lead to credential theft and further compromise.

## Triage and Response
1. Identify the environment and the user/actor.
2. Verify if the access was part of a legitimate workflow.
3. Rotate secrets immediately if compromised.""",
        "query_text": """%ingest.source_type:github
action:environment.get_secrets """,
        "severity": "Critical",
        "tags": ["github", "secrets", "credential_access"]
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
