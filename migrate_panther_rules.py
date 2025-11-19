import os
import yaml
import shutil

SOURCE_DIR = "/Users/raphaeleastment/Desktop/ScannerDetections/rules/panther_correlation_rules"
BASE_DIR = "/Users/raphaeleastment/Desktop/ScannerDetections/rules"

# Custom string class to force block style
class BlockScalarString(str):
    pass

def block_scalar_presenter(dumper, data):
    return dumper.represent_scalar('tag:yaml.org,2002:str', data, style='|')

yaml.add_representer(BlockScalarString, block_scalar_presenter)

TARGET_MAPPING = {
    "auth0": "auth0/rules",
    "aws": "aws/cloudtrail/rules",
    "gcp": "google-cloud/rules",
    "github": "github/rules",
    "secret": "github/rules" 
}

QUERY_MAPPING = {
    "auth0_account_takeover": "%ingest.source_type:auth0\ntype:s OR type:f",
    "aws_cloudtrail_stopinstance_followed_by_modifyinstanceattributes": "%ingest.source_type:aws:cloudtrail\neventName:StopInstances OR eventName:ModifyInstanceAttribute",
    "aws_console_sign-in_without_okta": "%ingest.source_type:aws:cloudtrail\neventName:ConsoleLogin AND NOT userIdentity.principalId:*Okta*",
    "aws_create_admin_iam_user": "%ingest.source_type:aws:cloudtrail\neventName:CreateUser OR eventName:AttachUserPolicy",
    "aws_create_backdoor_admin_iam_role": "%ingest.source_type:aws:cloudtrail\neventName:CreateRole OR eventName:AttachRolePolicy",
    "aws_privilege_escalation_via_user_compromise": "%ingest.source_type:aws:cloudtrail\neventName:UpdateLoginProfile OR eventName:CreateAccessKey",
    "aws_sso_access_token_retrieved_by_unauthenticated_ip": "%ingest.source_type:aws:cloudtrail\neventSource:sso.amazonaws.com",
    "aws_user_takeover_via_password_reset": "%ingest.source_type:aws:cloudtrail\neventName:UpdateLoginProfile",
    "gcp_cloud_run_service_create_followed_by_set_iam_policy": "%ingest.source_type:google_cloud_audit\nprotoPayload.methodName:\"google.cloud.run.v1.Services.CreateService\" OR protoPayload.methodName:\"google.iam.v1.IAMPolicy.SetIamPolicy\"",
    "gcp_tag_escalation": "%ingest.source_type:google_cloud_audit\nprotoPayload.methodName:\"google.cloud.resourcemanager.v3.TagBindings.CreateTagBinding\"",
    "github_advanced_security_change_not_followed_by_repo_archived": "%ingest.source_type:github\naction:disable_ghas OR action:archived",
    "secret_exposed_and_not_quarantined": "%ingest.source_type:github\naction:secret_scanning_alert"
}

def get_target_dir(filename):
    for key, path in TARGET_MAPPING.items():
        if filename.startswith(key):
            return os.path.join(BASE_DIR, path)
    return None

def generate_description(name, raw_desc):
    goal = raw_desc
    strategy = "Monitor logs for the specific sequence of events described."
    triage = """1. Identify the user and the sequence of actions.
2. Verify if the actions are authorized and business-justified.
3. If unauthorized, revert changes and suspend the user."""
    
    return f"## Goal\n{goal}\n\n## Strategy\n{strategy}\n\n## Triage and Response\n{triage}", goal, strategy, triage

def main():
    if not os.path.exists(SOURCE_DIR):
        print(f"Source directory {SOURCE_DIR} does not exist.")
        return

    files = os.listdir(SOURCE_DIR)
    
    for filename in files:
        if not filename.endswith('.yml'):
            continue
            
        source_path = os.path.join(SOURCE_DIR, filename)
        target_dir = get_target_dir(filename)
        
        if not target_dir:
            print(f"Could not determine target directory for {filename}")
            continue
            
        if not os.path.exists(target_dir):
            os.makedirs(target_dir)
            
        target_path = os.path.join(target_dir, filename)
        
        # Check for duplicates
        if os.path.exists(target_path):
            print(f"Skipping duplicate: {filename} already exists in {target_dir}")
            continue
            
        try:
            with open(source_path, 'r') as f:
                panther_data = yaml.safe_load(f)
            
            name = panther_data.get('DisplayName', panther_data.get('RuleID', filename.replace('.yml', '').replace('_', ' ').title()))
            description = panther_data.get('Description', '')
            severity = panther_data.get('Severity', 'Medium')
            
            # Map Severity
            sev_map = {"Info": "Low", "Low": "Low", "Medium": "Medium", "High": "High", "Critical": "Critical"}
            severity = sev_map.get(severity, "Medium")
            
            full_desc, goal, strategy, triage = generate_description(name, description)
            query_text = QUERY_MAPPING.get(filename.replace('.yml', ''), "%ingest.source_type:unknown")
            
            rule_data = {
                "schema": "https://scanner.dev/schema/scanner-detection-rule.v1.json",
                "name": name,
                "description": BlockScalarString(full_desc),
                "enabled": True,
                "severity": severity,
                "query_text": BlockScalarString(query_text),
                "time_range_s": 3600,
                "run_frequency_s": 300,
                "event_sink_keys": [f"{severity.lower()}_severity_alerts"],
                "tags": panther_data.get('Tags', []) + ["panther_migration"]
            }
            
            # Write Rule
            with open(target_path, 'w') as f:
                f.write("# schema: https://scanner.dev/schema/scanner-detection-rule.v1.json\n")
                yaml.dump(rule_data, f, sort_keys=False, default_flow_style=False, width=1000)
            
            print(f"Migrated {filename} to {target_dir}")
            
            # Generate Playbook
            playbook_dir = target_dir.replace("/rules", "/playbooks")
            if not os.path.exists(playbook_dir): os.makedirs(playbook_dir)
            playbook_path = os.path.join(playbook_dir, filename.replace('.yml', '_playbook.yml'))
            
            playbook_data = {
                "name": name + " Playbook",
                "description": goal,
                "severity": severity,
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
            with open(playbook_path, 'w') as f:
                yaml.dump(playbook_data, f, sort_keys=False, default_flow_style=False, width=1000)

            # Delete source file
            os.remove(source_path)

        except Exception as e:
            print(f"Error processing {filename}: {e}")

    # Cleanup source dir if empty
    if not os.listdir(SOURCE_DIR):
        os.rmdir(SOURCE_DIR)
        print(f"Deleted {SOURCE_DIR}")
    else:
        print(f"{SOURCE_DIR} is not empty, skipping deletion.")

if __name__ == "__main__":
    main()
