import os
import yaml

RULES_DIR = "/Users/raphaeleastment/Desktop/ScannerDetections/rules/google-cloud/rules"
PLAYBOOKS_DIR = "/Users/raphaeleastment/Desktop/ScannerDetections/rules/google-cloud/playbooks"

# Custom string class to force block style
class BlockScalarString(str):
    pass

def block_scalar_presenter(dumper, data):
    return dumper.represent_scalar('tag:yaml.org,2002:str', data, style='|')

yaml.add_representer(BlockScalarString, block_scalar_presenter)

NEW_RULES = [
    {
        "filename": "gcp_service_account_impersonation.yml",
        "name": "GCP Service Account Impersonation",
        "description": """## Goal
Detects usage of Service Account impersonation.

## Strategy
Monitor Google Cloud audit logs for `iam.serviceAccounts.actAs` permission checks or `GenerateAccessToken` calls. Attackers may impersonate service accounts to elevate privileges.

## Triage and Response
1. Identify the user and the target service account.
2. Verify if the impersonation is authorized for this user.
3. Revoke permissions immediately if unauthorized.""",
        "query_text": """%ingest.source_type:google_cloud_audit
protoPayload.methodName:("google.iam.v1.IAMCredentials.GenerateAccessToken" OR "google.iam.v1.IAMCredentials.GenerateIdToken" OR "google.iam.v1.IAMCredentials.SignBlob" OR "google.iam.v1.IAMCredentials.SignJwt") """,
        "severity": "High",
        "tags": ["google_cloud", "iam", "privilege_escalation"]
    },
    {
        "filename": "gcp_custom_role_created.yml",
        "name": "GCP Custom Role Created",
        "description": """## Goal
Detects the creation of a custom IAM role.

## Strategy
Monitor Google Cloud audit logs for `google.iam.admin.v1.CreateRole`. Attackers may create custom roles with specific, sensitive permissions to maintain persistence or evade detection.

## Triage and Response
1. Identify the user and the permissions assigned to the new role.
2. Verify if the role creation is authorized.
3. Delete the role if unauthorized.""",
        "query_text": """%ingest.source_type:google_cloud_audit
protoPayload.methodName:"google.iam.admin.v1.CreateRole" """,
        "severity": "Medium",
        "tags": ["google_cloud", "iam", "persistence"]
    },
    {
        "filename": "gcp_compute_serial_console_access.yml",
        "name": "GCP Compute Serial Console Access",
        "description": """## Goal
Detects access to the interactive serial console of a VM instance.

## Strategy
Monitor Google Cloud audit logs for `compute.instances.serialPortOutput`. The serial console can provide root access to a VM, bypassing network controls.

## Triage and Response
1. Identify the user and the VM instance.
2. Verify if serial console access is necessary and authorized.
3. Disable serial console access if unauthorized.""",
        "query_text": """%ingest.source_type:google_cloud_audit
protoPayload.methodName:"v1.compute.instances.serialPortOutput" """,
        "severity": "High",
        "tags": ["google_cloud", "compute", "access"]
    },
    {
        "filename": "gcp_compute_startup_script_modified.yml",
        "name": "GCP Compute Startup Script Modified",
        "description": """## Goal
Detects modifications to VM instance startup scripts.

## Strategy
Monitor Google Cloud audit logs for `compute.instances.setMetadata` where the key is `startup-script`. Attackers may modify startup scripts to execute malicious code on reboot.

## Triage and Response
1. Identify the user and the VM instance.
2. Review the content of the new startup script.
3. Revert changes and isolate the instance if malicious.""",
        "query_text": """%ingest.source_type:google_cloud_audit
protoPayload.methodName:"v1.compute.instances.setMetadata"
protoPayload.request.items.key:"startup-script" """,
        "severity": "High",
        "tags": ["google_cloud", "compute", "persistence"]
    },
    {
        "filename": "gcp_compute_ssh_key_added.yml",
        "name": "GCP Compute SSH Key Added",
        "description": """## Goal
Detects the addition of SSH keys to project or instance metadata.

## Strategy
Monitor Google Cloud audit logs for `compute.projects.setCommonInstanceMetadata` or `compute.instances.setMetadata` involving `ssh-keys`. Adding SSH keys allows direct access to VMs.

## Triage and Response
1. Identify the user and the key added.
2. Verify if the key addition is authorized.
3. Remove the key immediately if unauthorized.""",
        "query_text": """%ingest.source_type:google_cloud_audit
protoPayload.methodName:("v1.compute.projects.setCommonInstanceMetadata" OR "v1.compute.instances.setMetadata")
protoPayload.request.items.key:"ssh-keys" """,
        "severity": "High",
        "tags": ["google_cloud", "compute", "persistence"]
    },
    {
        "filename": "gcp_vpc_peering_created.yml",
        "name": "GCP VPC Peering Created",
        "description": """## Goal
Detects the creation of a VPC peering connection.

## Strategy
Monitor Google Cloud audit logs for `compute.networks.addPeering`. Unauthorized peering can expose internal networks to external or malicious networks.

## Triage and Response
1. Identify the user and the peer network.
2. Verify if the peering is authorized and secure.
3. Remove the peering connection if unauthorized.""",
        "query_text": """%ingest.source_type:google_cloud_audit
protoPayload.methodName:"v1.compute.networks.addPeering" """,
        "severity": "High",
        "tags": ["google_cloud", "network", "exfiltration"]
    },
    {
        "filename": "gcp_dns_zone_modified.yml",
        "name": "GCP DNS Zone Modified",
        "description": """## Goal
Detects modifications to Cloud DNS managed zones.

## Strategy
Monitor Google Cloud audit logs for `dns.managedZones.update` or `dns.managedZones.patch`. Attackers may modify DNS records to redirect traffic (DNS hijacking).

## Triage and Response
1. Identify the user and the DNS zone.
2. Verify the changes to DNS records.
3. Revert changes immediately if malicious.""",
        "query_text": """%ingest.source_type:google_cloud_audit
protoPayload.methodName:("dns.managedZones.update" OR "dns.managedZones.patch") """,
        "severity": "Medium",
        "tags": ["google_cloud", "network", "impact"]
    },
    {
        "filename": "gcp_gke_cluster_admin_role_granted.yml",
        "name": "GCP GKE Cluster Admin Role Granted",
        "description": """## Goal
Detects granting of the Kubernetes Engine Admin role.

## Strategy
Monitor Google Cloud audit logs for IAM policy changes granting `roles/container.admin`. This role provides full control over GKE clusters.

## Triage and Response
1. Identify the user and the principal receiving the role.
2. Verify if the role grant is authorized.
3. Revoke the role immediately if unauthorized.""",
        "query_text": """%ingest.source_type:google_cloud_audit
protoPayload.methodName:"SetIamPolicy"
protoPayload.serviceData.policyDelta.bindingDeltas.role:"roles/container.admin" """,
        "severity": "Critical",
        "tags": ["google_cloud", "gke", "privilege_escalation"]
    },
    {
        "filename": "gcp_gke_exec_into_pod.yml",
        "name": "GCP GKE Exec into Pod",
        "description": """## Goal
Detects execution of commands inside a GKE pod.

## Strategy
Monitor Kubernetes audit logs (via Cloud Audit Logs) for `pods/exec` calls. Attackers may use `kubectl exec` to run malicious commands inside containers.

## Triage and Response
1. Identify the user and the pod.
2. Review the command executed.
3. Terminate the pod and investigate the user if malicious.""",
        "query_text": """%ingest.source_type:google_cloud_audit
protoPayload.methodName:"io.k8s.core.v1.pods.exec" """,
        "severity": "High",
        "tags": ["google_cloud", "gke", "execution"]
    },
    {
        "filename": "gcp_sql_instance_public_access.yml",
        "name": "GCP SQL Instance Public Access",
        "description": """## Goal
Detects when a Cloud SQL instance is configured with a public IP.

## Strategy
Monitor Google Cloud audit logs for `cloudsql.instances.update` where `ipConfiguration.ipv4Enabled` is set to true or authorized networks are modified to allow `0.0.0.0/0`.

## Triage and Response
1. Identify the user and the SQL instance.
2. Verify if public access is required.
3. Disable public IP or restrict authorized networks immediately.""",
        "query_text": """%ingest.source_type:google_cloud_audit
protoPayload.methodName:"cloudsql.instances.update"
protoPayload.request.body.settings.ipConfiguration.ipv4Enabled:true """,
        "severity": "High",
        "tags": ["google_cloud", "sql", "exposure"]
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
