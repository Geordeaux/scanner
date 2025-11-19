import os
import yaml

RULES_DIR = "/Users/raphaeleastment/Desktop/ScannerDetections/rules/aws/cloudtrail/rules"
HUNTS_DIR = "/Users/raphaeleastment/Desktop/ScannerDetections/rules/aws/cloudtrail/threat-hunting"

# Custom string class to force block style
class BlockScalarString(str):
    pass

def block_scalar_presenter(dumper, data):
    return dumper.represent_scalar('tag:yaml.org,2002:str', data, style='|')

yaml.add_representer(BlockScalarString, block_scalar_presenter)

def main():
    if not os.path.exists(HUNTS_DIR):
        os.makedirs(HUNTS_DIR)

    count = 0
    for filename in os.listdir(RULES_DIR):
        if filename.endswith(".yml") or filename.endswith(".yaml"):
            rule_path = os.path.join(RULES_DIR, filename)
            hunt_filename = os.path.splitext(filename)[0] + "_hunt.yml"
            hunt_path = os.path.join(HUNTS_DIR, hunt_filename)

            try:
                with open(rule_path, 'r') as f:
                    rule_data = yaml.safe_load(f)
                
                name = rule_data.get('name', '')
                description = rule_data.get('description', '')
                query_text = rule_data.get('query_text', '')
                tags = rule_data.get('tags', [])

                # Extract Goal from description
                goal = description
                if "## Goal" in description:
                    parts = description.split('## Strategy')
                    goal = parts[0].replace('## Goal', '').strip()

                hunt_data = {
                    "name": name,
                    "description": BlockScalarString(goal),
                    "query_text": BlockScalarString(query_text),
                    "tags": tags
                }
                
                with open(hunt_path, 'w') as f:
                    f.write("# schema: https://scanner.dev/schema/scanner-threat-hunting-query.v1.json\n")
                    yaml.dump(hunt_data, f, sort_keys=False, default_flow_style=False, width=1000)

                print(f"Generated hunt query for {filename}")
                count += 1

            except Exception as e:
                print(f"Error processing {filename}: {e}")

    print(f"Successfully generated {count} threat hunting queries.")

if __name__ == "__main__":
    main()
