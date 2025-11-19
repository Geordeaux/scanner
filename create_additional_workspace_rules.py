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
        "filename": "google_workspace_suspicious_login_from_unusual_location.yml",
        "name": "Google Workspace Suspicious Login from Unusual Location",
        "description": """## Goal
Detects login attempts from unusual geographic locations.

## Strategy
Monitor Google Workspace login logs for `login_failure` or `login_success` events where the IP location is anomalous compared to the user's history.

## Triage and Response
1. Identify the user and the login location.
2. Verify if the user is traveling.
3. Reset password and enforce MFA if the login is unauthorized.""",
        "query_text": """%ingest.source_type:google_workspace
action:login_success OR action:login_failure """,
        "severity": "High",
        "tags": ["google_workspace", "login", "compromise"]
    },
    {
        "filename": "google_workspace_mobile_device_compromised.yml",
        "name": "Google Workspace Mobile Device Compromised",
        "description": """## Goal
Detects indications of a compromised mobile device managed by Google Workspace.

## Strategy
Monitor Google Workspace mobile audit logs for events indicating device compromise (e.g., jailbroken/rooted device detection).

## Triage and Response
1. Identify the user and the device.
2. Block the device from accessing corporate data.
3. Wipe the device if necessary.""",
        "query_text": """%ingest.source_type:google_workspace
action:device_compromised """,
        "severity": "High",
        "tags": ["google_workspace", "mobile", "endpoint"]
    },
    {
        "filename": "google_workspace_mass_drive_download.yml",
        "name": "Google Workspace Mass Drive Download",
        "description": """## Goal
Detects a high volume of file downloads from Google Drive by a single user.

## Strategy
Monitor Google Workspace Drive audit logs for `download` events. A sudden spike in downloads may indicate data exfiltration.

## Triage and Response
1. Identify the user and the files downloaded.
2. Verify if the activity is business-justified (e.g., backup, migration).
3. Suspend the user and revoke access if exfiltration is suspected.""",
        "query_text": """%ingest.source_type:google_workspace
action:download """,
        "severity": "High",
        "tags": ["google_workspace", "drive", "exfiltration"]
    },
    {
        "filename": "google_workspace_external_forwarding_rule_created.yml",
        "name": "Google Workspace External Forwarding Rule Created",
        "description": """## Goal
Detects the creation of email forwarding rules to external domains.

## Strategy
Monitor Google Workspace Gmail audit logs for `create_forwarding_rule`. Attackers often set up forwarding rules to exfiltrate sensitive emails.

## Triage and Response
1. Identify the user and the destination email.
2. Verify if the forwarding is authorized.
3. Remove the rule and investigate the user account if unauthorized.""",
        "query_text": """%ingest.source_type:google_workspace
action:create_forwarding_rule """,
        "severity": "High",
        "tags": ["google_workspace", "gmail", "exfiltration"]
    },
    {
        "filename": "google_workspace_admin_suspended_user.yml",
        "name": "Google Workspace Admin Suspended User",
        "description": """## Goal
Detects when an administrator suspends a user account.

## Strategy
Monitor Google Workspace Admin audit logs for `suspend_user`. This rule helps track administrative actions and potential insider threats or response actions.

## Triage and Response
1. Identify the admin and the suspended user.
2. Verify the reason for suspension.
3. Ensure proper documentation of the incident.""",
        "query_text": """%ingest.source_type:google_workspace
action:suspend_user """,
        "severity": "Medium",
        "tags": ["google_workspace", "admin", "impact"]
    },
    {
        "filename": "google_workspace_group_settings_modified_to_public.yml",
        "name": "Google Workspace Group Settings Modified to Public",
        "description": """## Goal
Detects when a Google Group's settings are changed to allow public access.

## Strategy
Monitor Google Workspace Groups audit logs for changes that allow "Public" or "External" access to group content or membership.

## Triage and Response
1. Identify the admin and the group.
2. Verify if public access is intended.
3. Revert settings immediately if unauthorized.""",
        "query_text": """%ingest.source_type:google_workspace
action:change_group_setting """,
        "severity": "High",
        "tags": ["google_workspace", "groups", "exposure"]
    },
    {
        "filename": "google_workspace_calendar_made_public.yml",
        "name": "Google Workspace Calendar Made Public",
        "description": """## Goal
Detects when a user's primary calendar is shared publicly.

## Strategy
Monitor Google Workspace Calendar audit logs for `change_calendar_setting` where visibility is set to public.

## Triage and Response
1. Identify the user and the calendar.
2. Verify if public sharing is necessary.
3. Restrict visibility if unauthorized.""",
        "query_text": """%ingest.source_type:google_workspace
action:change_calendar_setting """,
        "severity": "Medium",
        "tags": ["google_workspace", "calendar", "exposure"]
    },
    {
        "filename": "google_workspace_advanced_protection_unenrolled.yml",
        "name": "Google Workspace Advanced Protection Unenrolled",
        "description": """## Goal
Detects when a user unenrolls from the Advanced Protection Program.

## Strategy
Monitor Google Workspace User audit logs for `unenroll_advanced_protection`. High-risk users should remain enrolled to prevent targeted attacks.

## Triage and Response
1. Identify the user.
2. Verify if the unenrollment was intentional and authorized.
3. Re-enroll the user if necessary.""",
        "query_text": """%ingest.source_type:google_workspace
action:unenroll_advanced_protection """,
        "severity": "High",
        "tags": ["google_workspace", "security", "defense_evasion"]
    },
    {
        "filename": "google_workspace_api_access_granted.yml",
        "name": "Google Workspace API Access Granted",
        "description": """## Goal
Detects when a user grants API access to a third-party application.

## Strategy
Monitor Google Workspace Token audit logs for `authorize` events. Malicious apps can use OAuth tokens to access data.

## Triage and Response
1. Identify the user and the application.
2. Verify the reputation of the application.
3. Revoke the token if the app is suspicious.""",
        "query_text": """%ingest.source_type:google_workspace
action:authorize """,
        "severity": "Medium",
        "tags": ["google_workspace", "oauth", "credential_access"]
    },
    {
        "filename": "google_workspace_chat_attachment_downloaded.yml",
        "name": "Google Workspace Chat Attachment Downloaded",
        "description": """## Goal
Detects downloads of attachments from Google Chat.

## Strategy
Monitor Google Workspace Chat audit logs for `download_attachment`. Large volumes of downloads may indicate data exfiltration via Chat.

## Triage and Response
1. Identify the user and the file.
2. Verify if the download is business-related.
3. Investigate further if the file is sensitive.""",
        "query_text": """%ingest.source_type:google_workspace
action:download_attachment """,
        "severity": "Low",
        "tags": ["google_workspace", "chat", "exfiltration"]
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
