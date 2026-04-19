#!/usr/bin/env python3
"""Clone/update YARA repositories and build a categorized YARA ruleset."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import stat
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse


YARA_EXTENSIONS = {".yar", ".yara"}
IGNORED_DIRS = {
    ".git",
    ".hg",
    ".svn",
    ".cache",
    ".idea",
    ".mypy_cache",
    ".pytest_cache",
    ".tox",
    ".venv",
    "__pycache__",
    "dist",
    "node_modules",
    "venv",
}

CATEGORY_ALIASES = {
    "sql_injection": ["sql injection", "sqli", "sql-injection", "sql_injection"],
    "scripting_attacks": [
        "script",
        "scripting",
        "powershell",
        "javascript",
        "jscript",
        "vbscript",
        "vbs",
        "macro",
        "wscript",
        "cscript",
    ],
    "brute_force": ["brute force", "bruteforce", "brute-force", "password spraying"],
    "credential_theft": [
        "credential",
        "credentials",
        "creds",
        "password",
        "passwd",
        "stealer",
        "infostealer",
        "keylogger",
    ],
    "phishing": ["phish", "phishing"],
    "behavioral": ["behavior", "behaviour", "behavioral", "behavioural"],
    "rootkit": ["rootkit", "bootkit"],
    "malware": ["malware", "malicious"],
    "trojans": ["trojan", "trojans", "rat", "backdoor", "remote access"],
    "ransomware": ["ransom", "ransomware", "locker", "encryptor", "cryptolocker"],
    "spyware": ["spyware", "spy", "surveillance"],
    "worms": ["worm", "worms"],
    "autorun": ["autorun", "auto run", "startup", "persistence"],
    "security": ["security", "secops", "defense", "defence"],
}

RULE_TAG_RE = re.compile(r"(?im)^\s*rule\s+[A-Za-z0-9_]+\s*:\s*([^{]+)\{")
META_BLOCK_RE = re.compile(r"(?ims)^\s*meta\s*:\s*(.*?)(?:^\s*(?:strings|condition)\s*:)")
COMMENT_RE = re.compile(r"(?m)//.*?$|/\*.*?\*/", re.DOTALL)


def read_list(path: Path) -> list[str]:
    """Read a newline-delimited list, ignoring blanks and # comments."""
    items = []
    for line in path.read_text(encoding="utf-8-sig").splitlines():
        stripped = line.strip()
        if stripped and not stripped.startswith("#"):
            items.append(stripped)
    return items


def normalize_text(value: str) -> str:
    """Normalize separators and case for category matching."""
    return re.sub(r"[^a-z0-9]+", " ", value.lower()).strip()


def compact_text(value: str) -> str:
    """Normalize text to alphanumeric-only form for compound aliases."""
    return re.sub(r"[^a-z0-9]+", "", value.lower())


def terms_for_category(category: str) -> list[str]:
    terms = {category, normalize_text(category)}
    terms.update(CATEGORY_ALIASES.get(category, []))
    terms.update(CATEGORY_ALIASES.get(normalize_text(category).replace(" ", "_"), []))
    return sorted({term.strip().lower() for term in terms if term.strip()})


def parse_github_repo(url: str) -> tuple[str, str, str]:
    parsed = urlparse(url.strip())
    if parsed.scheme not in {"http", "https"} or parsed.netloc.lower() != "github.com":
        raise ValueError("expected a https://github.com/<owner>/<repo> URL")

    parts = [part for part in parsed.path.strip("/").split("/") if part]
    if len(parts) < 2:
        raise ValueError("expected a https://github.com/<owner>/<repo> URL")

    owner = parts[0]
    repo_name = parts[1].removesuffix(".git")
    repo_id = f"{owner}/{repo_name}"
    canonical_url = f"https://github.com/{repo_id}"
    return owner, repo_name, canonical_url


def log(message: str) -> None:
    print(message, flush=True)


def run_git(args: list[str], cwd: Path | None = None, verbose: bool = False) -> None:
    command = ["git", *args]
    if verbose:
        where = f" in {cwd}" if cwd else ""
        print(f"+ {' '.join(command)}{where}")

    completed = subprocess.run(
        command,
        cwd=cwd,
        check=False,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if completed.returncode != 0:
        detail = (completed.stderr or completed.stdout).strip()
        raise RuntimeError(f"{' '.join(command)} failed: {detail}")


def clone_or_update_repo(repo_url: str, repo_dir: Path, skip_pull: bool, verbose: bool) -> dict:
    owner, repo_name, canonical_url = parse_github_repo(repo_url)
    repo_id = f"{owner}/{repo_name}"
    local_path = repo_dir / f"{owner}__{repo_name}"

    if local_path.exists():
        if not (local_path / ".git").exists():
            return {
                "repo": repo_id,
                "source_url": canonical_url,
                "path": str(local_path),
                "status": "error",
                "error": "local path exists but is not a git repository",
            }
        if skip_pull:
            status = "skipped"
        else:
            run_git(["pull", "--ff-only"], cwd=local_path, verbose=verbose)
            status = "updated"
    else:
        local_path.parent.mkdir(parents=True, exist_ok=True)
        run_git(["clone", canonical_url, str(local_path)], verbose=verbose)
        status = "cloned"

    return {
        "repo": repo_id,
        "source_url": canonical_url,
        "path": str(local_path),
        "status": status,
    }


def iter_yara_files(repo_path: Path) -> list[Path]:
    yara_files = []
    for path in repo_path.rglob("*"):
        if any(part in IGNORED_DIRS for part in path.parts):
            continue
        if path.is_file() and path.suffix.lower() in YARA_EXTENSIONS:
            yara_files.append(path)
    return sorted(yara_files)


def sha256_file(file_path: Path) -> str:
    digest = hashlib.sha256()
    with file_path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def validate_yara_file(file_path: Path, yara_bin: str) -> dict:
    completed = subprocess.run(
        [yara_bin, str(file_path), str(file_path)],
        check=False,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    return {
        "valid": completed.returncode in {0, 1},
        "returncode": completed.returncode,
        "message": (completed.stderr or completed.stdout).strip(),
    }


def extract_matchable_text(file_path: Path, repo_path: Path) -> str:
    try:
        content = file_path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        content = ""

    relative_path = file_path.relative_to(repo_path).as_posix()
    tags = " ".join(match.group(1) for match in RULE_TAG_RE.finditer(content))
    meta_blocks = " ".join(match.group(1) for match in META_BLOCK_RE.finditer(content))
    comments = " ".join(match.group(0) for match in COMMENT_RE.finditer(content))

    return " ".join([relative_path, file_path.name, tags, meta_blocks, comments])


def term_matches(term: str, normalized_haystack: str, compact_haystack: str) -> bool:
    normalized_term = normalize_text(term)
    compact_term = compact_text(term)
    if not normalized_term and not compact_term:
        return False

    if normalized_term:
        pattern = rf"(?<![a-z0-9]){re.escape(normalized_term)}(?![a-z0-9])"
        if re.search(pattern, normalized_haystack):
            return True

    return bool(compact_term and compact_term in compact_haystack)


def classify_file(file_path: Path, repo_path: Path, category_terms: dict[str, list[str]]) -> dict[str, list[str]]:
    matchable_text = extract_matchable_text(file_path, repo_path)
    normalized_haystack = normalize_text(matchable_text)
    compact_haystack = compact_text(matchable_text)

    matches = {}
    for category, terms in category_terms.items():
        matched_terms = [
            term
            for term in terms
            if term_matches(term, normalized_haystack, compact_haystack)
        ]
        if matched_terms:
            matches[category] = sorted(set(matched_terms))
    return matches


def copy_rule_file(source_path: Path, destination_path: Path) -> None:
    destination_path.parent.mkdir(parents=True, exist_ok=True)
    if destination_path.exists():
        os.chmod(destination_path, stat.S_IREAD | stat.S_IWRITE)
    shutil.copy2(source_path, destination_path)
    os.chmod(destination_path, stat.S_IREAD | stat.S_IWRITE)


def make_writable_and_retry(function, path, _exc_info) -> None:
    os.chmod(path, stat.S_IREAD | stat.S_IWRITE)
    function(path)


def make_tree_writable(path: Path) -> None:
    for root, dirs, files in os.walk(path):
        for name in dirs:
            os.chmod(Path(root) / name, stat.S_IREAD | stat.S_IWRITE | stat.S_IEXEC)
        for name in files:
            os.chmod(Path(root) / name, stat.S_IREAD | stat.S_IWRITE)
    os.chmod(path, stat.S_IREAD | stat.S_IWRITE | stat.S_IEXEC)


def reset_rules_dir(rules_dir: Path) -> None:
    if rules_dir.exists():
        make_tree_writable(rules_dir)
        shutil.rmtree(rules_dir, onerror=make_writable_and_retry)
    rules_dir.mkdir(parents=True, exist_ok=True)


def progress_interval(total: int) -> int:
    if total <= 2_000:
        return 250
    if total <= 10_000:
        return 1_000
    return 5_000


def build_index(
    repo_results: list[dict],
    categories: list[str],
    rules_dir: Path,
    copy_rules: bool,
    keep_duplicates: bool,
    validate_rules: bool,
    yara_bin: str,
    validation_note: str,
    progress: bool,
) -> dict:
    category_terms = {category: terms_for_category(category) for category in categories}
    output = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "repo_count": len(repo_results),
        "categories": {category: [] for category in categories},
        "_unmatched": [],
        "duplicates": [],
        "repos": repo_results,
        "errors": [],
        "validation": {
            "enabled": validate_rules,
            "tool": yara_bin if validate_rules else None,
            "note": validation_note,
            "valid_files": 0,
            "invalid_files": 0,
            "skipped_files": 0,
        },
    }
    seen_hashes = {}

    for repo_info in repo_results:
        if repo_info.get("status") == "error":
            output["errors"].append(repo_info)
            continue

        repo_path = Path(repo_info["path"])
        if not repo_path.exists():
            output["errors"].append({**repo_info, "error": "repo path does not exist"})
            continue

        yara_files = iter_yara_files(repo_path)
        repo_matched = 0
        repo_duplicates = 0
        repo_unmatched = 0
        repo_invalid = 0
        interval = progress_interval(len(yara_files))
        if progress:
            log(f"[scan] {repo_info['repo']}: found {len(yara_files)} YARA files")

        for index, yara_file in enumerate(yara_files, start=1):
            relative_path = yara_file.relative_to(repo_path).as_posix()
            file_hash = sha256_file(yara_file)
            first_seen = seen_hashes.get(file_hash)
            duplicate_of = first_seen["path"] if first_seen else None
            base_entry = {
                "repo": repo_info["repo"],
                "source_url": repo_info["source_url"],
                "path": str(yara_file),
                "relative_path": relative_path,
                "sha256": file_hash,
                "size": yara_file.stat().st_size,
                "duplicate": duplicate_of is not None,
            }
            if duplicate_of:
                base_entry["duplicate_of"] = duplicate_of
                output["duplicates"].append(base_entry)
                repo_duplicates += 1
            else:
                seen_hashes[file_hash] = base_entry

            if validate_rules:
                validation = validate_yara_file(yara_file, yara_bin)
                base_entry["validation"] = validation
                if validation["valid"]:
                    output["validation"]["valid_files"] += 1
                else:
                    output["validation"]["invalid_files"] += 1
                    repo_invalid += 1
            else:
                output["validation"]["skipped_files"] += 1

            matches = classify_file(yara_file, repo_path, category_terms)
            if not matches:
                output["_unmatched"].append(base_entry)
                repo_unmatched += 1
                continue

            repo_matched += len(matches)
            repo_folder = repo_info["repo"].replace("/", "__")
            for category, matched_terms in matches.items():
                category_entry = {**base_entry, "matched_terms": matched_terms}
                if copy_rules and (keep_duplicates or not duplicate_of):
                    copied_path = rules_dir / category / repo_folder / relative_path
                    copy_rule_file(yara_file, copied_path)
                    category_entry["copied_path"] = str(copied_path)
                    category_entry["copied"] = True
                else:
                    category_entry["copied"] = False

                output["categories"][category].append(
                    category_entry
                )

            if progress and index % interval == 0:
                log(f"[scan] {repo_info['repo']}: processed {index}/{len(yara_files)} files")

        if progress:
            summary = (
                f"[scan] {repo_info['repo']}: matches={repo_matched}, "
                f"duplicates={repo_duplicates}, unmatched={repo_unmatched}"
            )
            if validate_rules:
                summary += f", invalid={repo_invalid}"
            log(summary)

    return output


def write_json(index: dict, output_path: Path, pretty_json: bool) -> None:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    if pretty_json:
        payload = json.dumps(index, indent=2, sort_keys=True)
    else:
        payload = json.dumps(index, separators=(",", ":"), sort_keys=True)
    output_path.write_text(
        payload + "\n",
        encoding="utf-8",
    )


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Clone/update YARA repos and write categorized YARA files plus a JSON index."
    )
    parser.add_argument("--repos", default="repos.txt", help="Path to repos.txt")
    parser.add_argument("--categories", default="category.txt", help="Path to category.txt")
    parser.add_argument("--repo-dir", default="repos", help="Directory for cloned repos")
    parser.add_argument(
        "--rules-dir",
        default="yara-rules/categories",
        help="Directory for categorized copied YARA files",
    )
    parser.add_argument("--output", default="yara_rule_index.json", help="JSON output path")
    parser.add_argument("--no-copy", action="store_true", help="Only write JSON; do not copy matched rules")
    parser.add_argument("--keep-duplicates", action="store_true", help="Copy duplicate rule files too")
    parser.add_argument(
        "--validate",
        action="store_true",
        help="Require YARA validation and fail if the YARA CLI is not available",
    )
    parser.add_argument("--no-validate", action="store_true", help="Disable automatic YARA validation")
    parser.add_argument("--yara-bin", default="yara", help="YARA executable used for validation")
    parser.add_argument("--skip-pull", action="store_true", help="Do not pull existing repos")
    parser.add_argument("--pretty-json", action="store_true", help="Write indented JSON instead of compact JSON")
    parser.add_argument("--quiet", action="store_true", help="Only print the final summary")
    parser.add_argument("--verbose", action="store_true", help="Also print the exact git commands")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    repos_path = Path(args.repos)
    categories_path = Path(args.categories)
    repo_dir = Path(args.repo_dir)
    rules_dir = Path(args.rules_dir)
    output_path = Path(args.output)

    repos = read_list(repos_path)
    categories = read_list(categories_path)
    progress = not args.quiet

    if not repos:
        raise SystemExit(f"No repositories found in {repos_path}")
    if not categories:
        raise SystemExit(f"No categories found in {categories_path}")

    yara_path = shutil.which(args.yara_bin)
    if args.validate and not yara_path:
        raise SystemExit(
            f"YARA validator not found: {args.yara_bin}. Install YARA or pass --yara-bin."
        )
    validate_rules = bool(yara_path) and not args.no_validate
    validation_note = "YARA CLI found; syntax validation enabled."
    if args.no_validate:
        validation_note = "YARA validation disabled by --no-validate."
    elif not yara_path:
        validation_note = "YARA CLI not found on PATH; syntax validation skipped."

    if progress:
        log("[start] YARA rule automation")
        log(f"[config] repos file: {repos_path} ({len(repos)} repos)")
        log(f"[config] categories file: {categories_path} ({len(categories)} categories)")
        log(f"[config] repo directory: {repo_dir}")
        log(f"[config] category output: {rules_dir}")
        log(f"[config] JSON index: {output_path}")
        log(f"[config] duplicate copying: {'enabled' if args.keep_duplicates else 'disabled'}")
        log(f"[config] {validation_note}")

    repo_results = []
    for index, repo_url in enumerate(repos, start=1):
        try:
            if progress:
                log(f"[repo {index}/{len(repos)}] {repo_url}")
            result = clone_or_update_repo(repo_url, repo_dir, args.skip_pull, args.verbose)
            repo_results.append(result)
            if progress:
                log(f"[repo {index}/{len(repos)}] {result['status']}: {result['path']}")
        except Exception as exc:
            repo_results.append(
                {
                    "repo": repo_url,
                    "source_url": repo_url,
                    "path": "",
                    "status": "error",
                    "error": str(exc),
                }
            )
            if progress:
                log(f"[repo {index}/{len(repos)}] error: {exc}")

    copy_rules = not args.no_copy
    if copy_rules:
        if progress:
            log(f"[output] refreshing categorized rules in {rules_dir}")
        reset_rules_dir(rules_dir)
    elif progress:
        log("[output] copy disabled; JSON index only")

    index = build_index(
        repo_results,
        categories,
        rules_dir,
        copy_rules,
        args.keep_duplicates,
        validate_rules,
        str(yara_path or args.yara_bin),
        validation_note,
        progress,
    )
    if progress:
        log(f"[output] writing JSON index to {output_path}")
    write_json(index, output_path, args.pretty_json)

    matched_count = sum(len(items) for items in index["categories"].values())
    copied_count = sum(
        1 for entries in index["categories"].values() for entry in entries if entry.get("copied")
    )
    category_counts = {
        category: len(entries)
        for category, entries in sorted(index["categories"].items())
        if entries
    }

    print()
    print("Summary")
    print("-------")
    print(f"Wrote {output_path}")
    if copy_rules:
        print(f"Wrote categorized YARA files under {rules_dir}")
    print(f"Repositories processed: {len(repo_results)}")
    print(f"Category matches: {matched_count}")
    print(f"Copied category files: {copied_count}")
    print(f"Duplicate YARA files: {len(index['duplicates'])}")
    print(f"Unmatched YARA files: {len(index['_unmatched'])}")
    print(index["validation"]["note"])
    if validate_rules:
        print(f"Valid YARA files: {index['validation']['valid_files']}")
        print(f"Invalid YARA files: {index['validation']['invalid_files']}")
    if index["errors"]:
        print(f"Errors: {len(index['errors'])}")
        return 1
    if category_counts:
        print("Category counts:")
        for category, count in category_counts.items():
            print(f"  {category}: {count}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
