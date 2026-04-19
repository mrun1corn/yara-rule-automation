# YARA Rule Automation

This project clones the GitHub repositories listed in `repos.txt`, scans YARA
files, groups matched rules by the categories in `categories.json`, detects exact
duplicates, and writes a JSON index.

## Local Usage

Run the full automation with no extra arguments:

```powershell
python yara_rule_automation.py
```

The script will:

- Clone new repositories from `repos.txt` into `repos/`
- Pull updates for existing repositories
- Sync categorized rule files under `yara-rules/categories/`
- Write `yara_rule_index.json`
- Detect duplicate YARA files by SHA-256
- Validate YARA syntax automatically if the `yara` CLI is installed

The cloned source repositories under `repos/` are ignored by Git. Generated
rules under `yara-rules/` and `yara_rule_index.json` can be committed; the JSON
index is pretty-printed and tracked with Git LFS because it can grow past
GitHub's normal file size limit.

## GitHub Actions

Use the **Update YARA Rules** workflow from the GitHub Actions tab.

The workflow runs on demand with `workflow_dispatch`, generates the categorized
rules, writes a run summary, uploads the generated `yara-rules/` directory plus
`yara_rule_index.json` as a downloadable artifact named `yara-rules-output`, and
commits changed generated files back to the repository.

Before pushing from a local machine, install Git LFS once:

```powershell
git lfs install
```

By default, generated rule files are synced in place. The script uses the
previous `yara_rule_index.json` to skip unchanged category copies quickly,
overwrites changed files, copies new files, and removes stale files. Use
`--clean-output` only when you want to delete and rebuild the category output
from scratch.

When a source repository's Git HEAD has not changed, the script reuses that
repo's previous index entries instead of scanning every YARA file again. This
keeps repeat workflow runs much faster after the first generated index exists.

## Inputs

- `repos.txt`: one GitHub repository URL per line (blank lines and `#` comments ignored)
- `categories.json`: a JSON dictionary where keys are category names and values are lists of alias terms to match
