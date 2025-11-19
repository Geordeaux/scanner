import os
import re
import yaml

RULES_DIR = "/Users/raphaeleastment/Desktop/ScannerDetections/rules/github/rules"
PLAYBOOKS_DIR = "/Users/raphaeleastment/Desktop/ScannerDetections/rules/github/playbooks"

# Custom string class to force block style
class BlockScalarString(str):
    pass

def block_scalar_presenter(dumper, data):
    return dumper.represent_scalar('tag:yaml.org,2002:str', data, style='|')

yaml.add_representer(BlockScalarString, block_scalar_presenter)

def parse_yaral(content):
    data = {}
    
    # Extract meta
    name_match = re.search(r'rule_name\s*=\s*"([^"]+)"', content)
    if name_match:
        data['name'] = name_match.group(1)
    
    desc_match = re.search(r'description\s*=\s*"([^"]+)"', content)
    if desc_match:
        data['description'] = desc_match.group(1)
        
    severity_match = re.search(r'severity\s*=\s*"([^"]+)"', content)
    if severity_match:
        data['severity'] = severity_match.group(1)
    else:
        data['severity'] = "Medium"

    # Extract event types
    # Look for product_event_type = "value"
    event_types = re.findall(r'product_event_type\s*=\s*"([^"]+)"', content)
    data['event_types'] = sorted(list(set(event_types)))
    
    # Extract time window
    # match: $user_id over 30m
    time_match = re.search(r'over\s+(\d+)([mh])', content)
    if time_match:
        val = int(time_match.group(1))
        unit = time_match.group(2)
        if unit == 'm':
            data['time_range_s'] = val * 60
        elif unit == 'h':
            data['time_range_s'] = val * 3600
    else:
        data['time_range_s'] = 3600 # Default 1h

    return data

def generate_description(name, raw_desc):
    goal = raw_desc
    strategy = "Monitor GitHub audit logs for specific event types."
    triage = """1. Identify the actor and the target resource.
2. Verify if the action was authorized.
3. If unauthorized, revert the change and rotate credentials."""

    if "Dependabot" in name:
        strategy = "Monitor for disablement of Dependabot alerts or updates."
        triage = """1. Identify the repository and the user.
2. Re-enable Dependabot immediately.
3. Investigate why it was disabled."""
    elif "Audit Log" in name:
        strategy = "Monitor for changes to audit log streaming configurations."
        triage = """1. Identify the user.
2. Verify if this was a planned infrastructure change.
3. Restore the stream immediately."""
    elif "Recovery Codes" in name:
        strategy = "Monitor for generation or usage of recovery codes."
        triage = """1. Identify the user.
2. Verify if the user is locked out or if this is an account takeover.
3. Rotate credentials if suspicious."""
    elif "Invitation" in name:
        strategy = "Monitor for invitations sent to non-company domains."
        triage = """1. Identify the invited email and the inviter.
2. Verify if the external collaboration is authorized.
3. Revoke the invitation if unauthorized."""
    elif "Transfer" in name:
        strategy = "Monitor for organization or repository transfers."
        triage = """1. Identify the source and destination.
2. Verify authorization.
3. Contact GitHub support if malicious."""
    
    return f"## Goal\n{goal}\n\n## Strategy\n{strategy}\n\n## Triage and Response\n{triage}", goal, strategy, triage

def main():
    if not os.path.exists(PLAYBOOKS_DIR):
        os.makedirs(PLAYBOOKS_DIR)

    count = 0
    for filename in os.listdir(RULES_DIR):
        if filename.endswith(".yaral"):
            yaral_path = os.path.join(RULES_DIR, filename)
            yml_filename = filename.replace(".yaral", ".yml")
            yml_path = os.path.join(RULES_DIR, yml_filename)
            playbook_filename = filename.replace(".yaral", "_playbook.yml")
            playbook_path = os.path.join(PLAYBOOKS_DIR, playbook_filename)

            try:
                with open(yaral_path, 'r') as f:
                    content = f.read()
                
                parsed = parse_yaral(content)
                
                if not parsed.get('name'):
                    parsed['name'] = filename.replace('.yaral', '').replace('_', ' ').title()
                
                full_desc, goal, strategy, triage = generate_description(parsed['name'], parsed.get('description', ''))
                
                # Build Query
                query_parts = [f"action:{evt}" for evt in parsed['event_types']]
                if query_parts:
                    query_text = "%ingest.source_type:github\n" + " OR ".join(query_parts)
                else:
                    # Fallback if no events found (unlikely for these rules)
                    query_text = "%ingest.source_type:github"
                
                rule_data = {
                    "schema": "https://scanner.dev/schema/scanner-detection-rule.v1.json",
                    "name": parsed['name'],
                    "description": BlockScalarString(full_desc),
                    "enabled": True,
                    "severity": parsed['severity'],
                    "query_text": BlockScalarString(query_text),
                    "time_range_s": parsed.get('time_range_s', 3600),
                    "run_frequency_s": 300,
                    "event_sink_keys": [f"{parsed['severity'].lower()}_severity_alerts"],
                    "tags": ["github", "converted_yaral"]
                }
                
                # Write Rule
                with open(yml_path, 'w') as f:
                    f.write("# schema: https://scanner.dev/schema/scanner-detection-rule.v1.json\n")
                    yaml.dump(rule_data, f, sort_keys=False, default_flow_style=False, width=1000)
                
                # Create Playbook
                playbook_data = {
                    "name": parsed['name'] + " Playbook",
                    "description": goal,
                    "severity": parsed['severity'],
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
                
                # Delete YARAL
                os.remove(yaral_path)
                
                print(f"Converted {filename} to {yml_filename} and created playbook.")
                count += 1

            except Exception as e:
                print(f"Error processing {filename}: {e}")

    print(f"Successfully converted {count} YARAL rules.")

if __name__ == "__main__":
    main()
