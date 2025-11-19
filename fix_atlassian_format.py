import os
import yaml
import re

RULES_DIR = "/Users/raphaeleastment/Desktop/ScannerDetections/rules/atlassian/rules"

# Custom string class to force block style
class BlockScalarString(str):
    pass

def block_scalar_presenter(dumper, data):
    return dumper.represent_scalar('tag:yaml.org,2002:str', data, style='|')

yaml.add_representer(BlockScalarString, block_scalar_presenter)

def clean_description(description):
    # Split into sections
    sections = {}
    current_section = "Header"
    lines = description.split('\n')
    
    buffer = []
    
    for line in lines:
        line = line.strip()
        if line.startswith('## Goal'):
            if buffer:
                sections[current_section] = buffer
            current_section = "Goal"
            buffer = []
        elif line.startswith('## Strategy'):
            if buffer:
                sections[current_section] = buffer
            current_section = "Strategy"
            buffer = []
        elif line.startswith('## Triage'):
            if buffer:
                sections[current_section] = buffer
            current_section = "Triage"
            buffer = []
        elif line: # Skip empty lines
            buffer.append(line)
            
    if buffer:
        sections[current_section] = buffer

    # Reconstruct
    parts = []
    
    # Goal
    if "Goal" in sections:
        parts.append("## Goal")
        parts.extend(sections["Goal"])
        
    # Strategy
    if "Strategy" in sections:
        if parts: parts.append("") # Add blank line before next section
        parts.append("## Strategy")
        parts.extend(sections["Strategy"])
        
    # Triage
    if "Triage" in sections:
        if parts: parts.append("") # Add blank line before next section
        parts.append("## Triage and Response")
        parts.extend(sections["Triage"])
        
    return "\n".join(parts)

def clean_query(query):
    # Remove empty lines and strip each line
    lines = [line.strip() for line in query.split('\n') if line.strip()]
    return "\n".join(lines)

def main():
    count = 0
    for filename in os.listdir(RULES_DIR):
        if filename.endswith(".yml") or filename.endswith(".yaml"):
            rule_path = os.path.join(RULES_DIR, filename)
            try:
                with open(rule_path, 'r') as f:
                    rule_data = yaml.safe_load(f)
                
                if 'description' in rule_data:
                    cleaned_desc = clean_description(rule_data['description'])
                    rule_data['description'] = BlockScalarString(cleaned_desc)
                
                if 'query_text' in rule_data:
                    cleaned_query = clean_query(rule_data['query_text'])
                    rule_data['query_text'] = BlockScalarString(cleaned_query)
                
                # Write back
                with open(rule_path, 'w') as f:
                    f.write("# schema: https://scanner.dev/schema/scanner-detection-rule.v1.json\n")
                    yaml.dump(rule_data, f, sort_keys=False, default_flow_style=False, width=1000)
                
                print(f"Fixed formatting for {filename}")
                count += 1

            except Exception as e:
                print(f"Error processing {filename}: {e}")

    print(f"Successfully fixed formatting for {count} rules.")

if __name__ == "__main__":
    main()
