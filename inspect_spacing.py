import yaml

with open('/Users/raphaeleastment/Desktop/ScannerDetections/rules/atlassian/rules/atlassian_addon_installed.yml', 'r') as f:
    data = yaml.safe_load(f)

print(f"Description repr: {repr(data['description'])}")
print(f"Query text repr: {repr(data['query_text'])}")
