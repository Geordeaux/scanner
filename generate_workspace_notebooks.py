import os
import yaml
import json

RULES_DIR = "/Users/raphaeleastment/Desktop/ScannerDetections/rules/google-workspace/rules"
NOTEBOOKS_DIR = "/Users/raphaeleastment/Desktop/ScannerDetections/rules/google-workspace/notebooks"

# Custom string class to force block style
class BlockScalarString(str):
    pass

def block_scalar_presenter(dumper, data):
    return dumper.represent_scalar('tag:yaml.org,2002:str', data, style='|')

yaml.add_representer(BlockScalarString, block_scalar_presenter)

def main():
    if not os.path.exists(NOTEBOOKS_DIR):
        os.makedirs(NOTEBOOKS_DIR)

    count = 0
    for filename in os.listdir(RULES_DIR):
        if filename.endswith(".yml") or filename.endswith(".yaml"):
            rule_path = os.path.join(RULES_DIR, filename)
            notebook_filename = os.path.splitext(filename)[0] + "_notebook.ipynb"
            notebook_path = os.path.join(NOTEBOOKS_DIR, notebook_filename)

            try:
                with open(rule_path, 'r') as f:
                    rule_data = yaml.safe_load(f)
                
                name = rule_data.get('name', '')
                description = rule_data.get('description', '')
                query_text = rule_data.get('query_text', '')
                
                # Extract Goal from description
                goal = description
                if "## Goal" in description:
                    parts = description.split('## Strategy')
                    goal = parts[0].replace('## Goal', '').strip()

                # Notebook Structure
                notebook_content = {
                    "cells": [
                        {
                            "cell_type": "markdown",
                            "metadata": {},
                            "source": [
                                f"# {name}\n",
                                "\n",
                                goal
                            ]
                        },
                        {
                            "cell_type": "markdown",
                            "metadata": {},
                            "source": [
                                "## Detection Query\n",
                                "Execute the following query to find alerts related to this rule."
                            ]
                        },
                        {
                            "cell_type": "code",
                            "execution_count": None,
                            "metadata": {},
                            "outputs": [],
                            "source": [
                                query_text
                            ]
                        },
                        {
                            "cell_type": "markdown",
                            "metadata": {},
                            "source": [
                                "## Investigation Steps\n",
                                "1. **Identify the User**: Who performed the action?\n",
                                "2. **Review Context**: What else did this user do?\n",
                                "3. **Check Location**: Was the action performed from a usual location?\n",
                                "4. **Verify Intent**: Was this action business-justified?"
                            ]
                        },
                        {
                            "cell_type": "code",
                            "execution_count": None,
                            "metadata": {},
                            "outputs": [],
                            "source": [
                                "%ingest.source_type:google_workspace\n",
                                "actor.email: <USER_EMAIL>\n",
                                "| count(action) by action"
                            ]
                        }
                    ],
                    "metadata": {
                        "kernelspec": {
                            "display_name": "Scanner",
                            "language": "python",
                            "name": "scanner"
                        },
                        "language_info": {
                            "codemirror_mode": {
                                "name": "ipython",
                                "version": 3
                            },
                            "file_extension": ".py",
                            "mimetype": "text/x-python",
                            "name": "python",
                            "nbconvert_exporter": "python",
                            "pygments_lexer": "ipython3",
                            "version": "3.8.5"
                        }
                    },
                    "nbformat": 4,
                    "nbformat_minor": 4
                }
                
                with open(notebook_path, 'w') as f:
                    json.dump(notebook_content, f, indent=1)

                print(f"Generated notebook for {filename}")
                count += 1

            except Exception as e:
                print(f"Error processing {filename}: {e}")

    print(f"Successfully generated {count} notebooks.")

if __name__ == "__main__":
    main()
