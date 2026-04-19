# YARA Rule Automation

This project clones the GitHub repositories listed in `repos.txt`, scans YARA
files, groups matched rules by the categories in `category.txt`, detects exact
duplicates, and writes a JSON index.

## Local Usage

Run the full automation with no extra arguments:

```powershell
python yara_rule_automation.py
```

The script will:

- Clone new repositories from `repos.txt` into `repos/`
- Pull updates for existing repositories
- Rebuild categorized rule files under `yara-rules/categories/`
- Write `yara_rule_index.json`
- Detect duplicate YARA files by SHA-256
- Validate YARA syntax automatically if the `yara` CLI is installed

Generated files are ignored by Git so large rule outputs are not committed by
accident.

## GitHub Actions

Use the **Update YARA Rules** workflow from the GitHub Actions tab.

The workflow runs on demand with `workflow_dispatch`, generates the categorized
rules, writes a run summary, and uploads the generated `yara-rules/` directory
plus `yara_rule_index.json` as a downloadable artifact named
`yara-rules-output`.

## Inputs

- `repos.txt`: one GitHub repository URL per line
- `category.txt`: one category name per line

Blank lines and lines starting with `#` are ignored.
