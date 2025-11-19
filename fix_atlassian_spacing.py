import os
import yaml

RULES_DIR = "/Users/raphaeleastment/Desktop/ScannerDetections/rules/atlassian/rules"

class PreservedScalarString(str):
    pass

def preserved_scalar_presenter(dumper, data):
    return dumper.represent_scalar('tag:yaml.org,2002:str', data, style='|-')

yaml.add_representer(PreservedScalarString, preserved_scalar_presenter)

def main():
    count = 0
    for filename in os.listdir(RULES_DIR):
        if filename.endswith(".yml") or filename.endswith(".yaml"):
            rule_path = os.path.join(RULES_DIR, filename)
            try:
                with open(rule_path, 'r') as f:
                    rule_data = yaml.safe_load(f)
                
                if 'description' in rule_data:
                    rule_data['description'] = PreservedScalarString(rule_data['description'])
                
                if 'query_text' in rule_data:
                    rule_data['query_text'] = PreservedScalarString(rule_data['query_text'])
                
                # Write back
                with open(rule_path, 'w') as f:
                    f.write("# schema: https://scanner.dev/schema/scanner-detection-rule.v1.json\n")
                    yaml.dump(rule_data, f, sort_keys=False, default_flow_style=False, width=1000)
                
                print(f"Fixed spacing for {filename}")
                count += 1

            except Exception as e:
                print(f"Error processing {filename}: {e}")

    print(f"Successfully fixed spacing for {count} rules.")

if __name__ == "__main__":
    main()
