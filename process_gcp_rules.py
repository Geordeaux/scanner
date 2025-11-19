import os
import re
import yaml
import difflib

RULES_DIR = "/Users/raphaeleastment/Desktop/ScannerDetections/rules/google-cloud/rules"
PLAYBOOKS_DIR = "/Users/raphaeleastment/Desktop/ScannerDetections/rules/google-cloud/playbooks"

# Custom string class to force block style
class BlockScalarString(str):
    pass

def block_scalar_presenter(dumper, data):
    return dumper.represent_scalar('tag:yaml.org,2002:str', data, style='|')

yaml.add_representer(BlockScalarString, block_scalar_presenter)

def normalize_name(filename):
    name = os.path.splitext(filename)[0]
    name = name.replace('_', ' ').lower()
    # Remove common prefixes/suffixes for comparison
    name = name.replace('gcp ', '').replace('google cloud ', '')
    return name

def parse_yaral(content):
    data = {}
    name_match = re.search(r'rule_name\s*=\s*"([^"]+)"', content)
    if name_match: data['name'] = name_match.group(1)
    
    desc_match = re.search(r'description\s*=\s*"([^"]+)"', content)
    if desc_match: data['description'] = desc_match.group(1)
        
    severity_match = re.search(r'severity\s*=\s*"([^"]+)"', content)
    data['severity'] = severity_match.group(1) if severity_match else "Medium"

    event_types = re.findall(r'method_name\s*=\s*"([^"]+)"', content)
    if not event_types:
         event_types = re.findall(r'permission_name\s*=\s*"([^"]+)"', content)
    data['event_types'] = sorted(list(set(event_types)))
    
    return data

def generate_description(name, raw_desc):
    goal = raw_desc
    strategy = "Monitor Google Cloud audit logs for specific API calls or permission changes."
    triage = """1. Identify the principal and the resource.
2. Verify if the action was authorized.
3. If unauthorized, revert the change and rotate credentials."""

    if "Public" in name or "World" in name:
        strategy = "Monitor for resources (Buckets, Datasets, Images) being made public."
        triage = """1. Identify the resource and the user.
2. Verify if public access is intended.
3. Remove public access immediately if unauthorized."""
    elif "Key" in name or "Service Account" in name:
        strategy = "Monitor for service account key creation or usage anomalies."
        triage = """1. Identify the service account and the key.
2. Verify if the key creation was authorized.
3. Revoke the key immediately if suspicious."""
    elif "Firewall" in name:
        strategy = "Monitor for firewall rules allowing broad access (e.g., 0.0.0.0/0)."
        triage = """1. Identify the firewall rule and the user.
2. Verify if the open port is necessary.
3. Restrict the rule to specific IPs if possible."""
    
    return f"## Goal\n{goal}\n\n## Strategy\n{strategy}\n\n## Triage and Response\n{triage}", goal, strategy, triage

def main():
    if not os.path.exists(PLAYBOOKS_DIR):
        os.makedirs(PLAYBOOKS_DIR)

    files = os.listdir(RULES_DIR)
    yaral_files = [f for f in files if f.endswith('.yaral')]
    yaml_files = [f for f in files if f.endswith('.yml') or f.endswith('.yaml')]

    # Deduplication
    to_delete = []
    to_convert = []

    for yrl in yaral_files:
        yrl_norm = normalize_name(yrl)
        match_found = False
        for yml in yaml_files:
            yml_norm = normalize_name(yml)
            # Check for exact normalized match or high similarity
            if yrl_norm == yml_norm or difflib.SequenceMatcher(None, yrl_norm, yml_norm).ratio() > 0.8:
                print(f"Duplicate found: {yrl} matches {yml}. Will delete YARAL.")
                to_delete.append(yrl)
                match_found = True
                break
        
        if not match_found:
            print(f"Unique YARAL found: {yrl}. Will convert.")
            to_convert.append(yrl)

    # Process Conversions
    for filename in to_convert:
        yaral_path = os.path.join(RULES_DIR, filename)
        yml_filename = filename.replace(".yaral", ".yml")
        yml_path = os.path.join(RULES_DIR, yml_filename)
        
        try:
            with open(yaral_path, 'r') as f:
                content = f.read()
            
            parsed = parse_yaral(content)
            if not parsed.get('name'): parsed['name'] = filename.replace('.yaral', '').replace('_', ' ').title()
            
            full_desc, goal, strategy, triage = generate_description(parsed['name'], parsed.get('description', ''))
            
            # Build Query
            query_parts = [f"protoPayload.methodName:{evt}" for evt in parsed['event_types']]
            if query_parts:
                query_text = "%ingest.source_type:google_cloud_audit\n" + " OR ".join(query_parts)
            else:
                query_text = "%ingest.source_type:google_cloud_audit"

            rule_data = {
                "schema": "https://scanner.dev/schema/scanner-detection-rule.v1.json",
                "name": parsed['name'],
                "description": BlockScalarString(full_desc),
                "enabled": True,
                "severity": parsed['severity'],
                "query_text": BlockScalarString(query_text),
                "time_range_s": 3600,
                "run_frequency_s": 300,
                "event_sink_keys": [f"{parsed['severity'].lower()}_severity_alerts"],
                "tags": ["google_cloud", "converted_yaral"]
            }
            
            with open(yml_path, 'w') as f:
                f.write("# schema: https://scanner.dev/schema/scanner-detection-rule.v1.json\n")
                yaml.dump(rule_data, f, sort_keys=False, default_flow_style=False, width=1000)
            
            # Add to yaml list for playbook creation
            yaml_files.append(yml_filename)
            to_delete.append(filename) # Delete after conversion

        except Exception as e:
            print(f"Error converting {filename}: {e}")

    # Delete YARAL files
    for f in to_delete:
        try:
            os.remove(os.path.join(RULES_DIR, f))
            print(f"Deleted {f}")
        except OSError:
            pass

    # Update ALL YAML files (formatting + playbooks)
    # Re-list to get everything
    all_yaml = [f for f in os.listdir(RULES_DIR) if f.endswith('.yml')]
    
    for filename in all_yaml:
        rule_path = os.path.join(RULES_DIR, filename)
        playbook_path = os.path.join(PLAYBOOKS_DIR, filename.replace('.yml', '_playbook.yml'))
        
        try:
            with open(rule_path, 'r') as f:
                rule_data = yaml.safe_load(f)
            
            name = rule_data.get('name', '')
            description = rule_data.get('description', '')
            
            # Ensure description format
            if "## Goal" not in description:
                full_desc, goal, strategy, triage = generate_description(name, description)
                rule_data['description'] = BlockScalarString(full_desc)
                
                with open(rule_path, 'w') as f:
                    f.write("# schema: https://scanner.dev/schema/scanner-detection-rule.v1.json\n")
                    yaml.dump(rule_data, f, sort_keys=False, default_flow_style=False, width=1000)
            else:
                # Extract for playbook
                parts = description.split('## Strategy')
                goal = parts[0].replace('## Goal', '').strip()
                rest = parts[1]
                parts2 = rest.split('## Triage and Response')
                strategy = parts2[0].strip()
                triage = parts2[1].strip() if len(parts2) > 1 else ""

            # Create Playbook
            playbook_data = {
                "name": name + " Playbook",
                "description": goal,
                "severity": rule_data.get('severity', 'Medium'),
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
                
        except Exception as e:
            print(f"Error processing YAML {filename}: {e}")

    print("Finished processing Google Cloud rules.")

if __name__ == "__main__":
    main()
