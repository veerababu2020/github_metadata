#!/usr/bin/env python3
"""
GitHub Repository Metadata Scanner
-------------------------------------
Fetches three layers of metadata for each repo:
  1. Repo metadata       — general info, stats, topics, license
  2. Owner metadata      — owner profile, type (User/Org), bio, location, social info
  3. Commit metadata     — last N commits with author, email, message, date, SHA

Input  : repos.csv  (one column: "repo", values like "owner/name" or full GitHub URL)
Outputs: repo_metadata.csv / repo_metadata.json / repo_metadata.md

No CLI arguments — edit the constants below and run:
    pip install requests
    python github_repo_metadata.py
"""

import csv
import json
import time
import sys
from pathlib import Path
from datetime import datetime

import requests

# ---------------------------------------------------------------------------
# CONFIG — edit these
# ---------------------------------------------------------------------------

PAT_TOKEN = "ghp_hKaOrIxihW3kShYBEdDteUs************6FT"          # GitHub PAT — classic needs 'repo' or 'public_repo' scope
                        # fine-grained needs 'Metadata' read access

INPUT_CSV    = "repos.csv"
OUTPUT_DIR   = "github_scan_reports"   # all output files go here (created automatically)
OUTPUT_CSV   = f"{OUTPUT_DIR}/repo_metadata.csv"
OUTPUT_JSON  = f"{OUTPUT_DIR}/repo_metadata.json"
OUTPUT_MD    = f"{OUTPUT_DIR}/repo_metadata.md"

MAX_COMMITS     = 10     # how many recent commits to pull per repo (max 100)
COMMIT_BRANCH   = ""     # leave blank to use the repo's default branch
REQUEST_TIMEOUT = 15     # seconds per request
RETRY_ON_RATE_LIMIT = True
MAX_RETRIES     = 3

GITHUB_API_BASE = "https://api.github.com"

# ---------------------------------------------------------------------------
# HELPERS
# ---------------------------------------------------------------------------

def build_headers() -> dict:
    h = {
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    if PAT_TOKEN:
        h["Authorization"] = f"Bearer {PAT_TOKEN}"
    return h


def get(url: str, headers: dict, params: dict = None) -> requests.Response:
    """GET with automatic rate-limit retry."""
    attempt = 0
    while True:
        resp = requests.get(url, headers=headers, params=params, timeout=REQUEST_TIMEOUT)
        if resp.status_code == 403 and RETRY_ON_RATE_LIMIT and attempt < MAX_RETRIES:
            reset = resp.headers.get("X-RateLimit-Reset")
            wait = max(int(reset) - int(time.time()) + 2, 5) if reset else 10
            print(f"      [rate limit] waiting {wait}s ...")
            time.sleep(wait)
            attempt += 1
            continue
        return resp


def read_repos_from_csv(path: str) -> list:
    repos = []
    fp = Path(path)
    if not fp.exists():
        print(f"[!] Input file not found: {path}")
        sys.exit(1)

    with open(fp, newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        if "repo" not in (reader.fieldnames or []):
            print("[!] CSV must have a 'repo' column (e.g. owner/name or https://github.com/owner/name)")
            sys.exit(1)
        for row in reader:
            val = (row.get("repo") or "").strip()
            if not val or val.startswith("#"):
                continue
            val = val.replace("https://github.com/", "").rstrip("/")
            if "/" not in val:
                print(f"[!] Skipping malformed entry: {val}")
                continue
            owner, name = val.split("/", 1)
            repos.append((owner.strip(), name.strip()))
    return repos


# ---------------------------------------------------------------------------
# SECTION 1 — REPO METADATA
# ---------------------------------------------------------------------------

def fetch_repo(owner: str, repo: str, headers: dict) -> dict:
    url  = f"{GITHUB_API_BASE}/repos/{owner}/{repo}"
    resp = get(url, headers)
    out  = {
        # identity
        "repo_full_name"   : f"{owner}/{repo}",
        "repo_html_url"    : "",
        "repo_description" : "",
        "repo_homepage"    : "",
        # stats
        "repo_stars"       : "",
        "repo_forks"       : "",
        "repo_watchers"    : "",
        "repo_open_issues" : "",
        "repo_size_kb"     : "",
        # tech
        "repo_language"    : "",
        "repo_topics"      : "",
        "repo_license"     : "",
        "repo_default_branch": "",
        # status
        "repo_visibility"  : "",
        "repo_is_fork"     : "",
        "repo_is_archived" : "",
        "repo_is_template" : "",
        # dates
        "repo_created_at"  : "",
        "repo_updated_at"  : "",
        "repo_pushed_at"   : "",
        # error
        "repo_error"       : "",
    }

    if resp.status_code == 200:
        d = resp.json()
        lic = (d.get("license") or {})
        out.update({
            "repo_html_url"      : d.get("html_url", ""),
            "repo_description"   : d.get("description") or "",
            "repo_homepage"      : d.get("homepage") or "",
            "repo_stars"         : d.get("stargazers_count", ""),
            "repo_forks"         : d.get("forks_count", ""),
            "repo_watchers"      : d.get("watchers_count", ""),
            "repo_open_issues"   : d.get("open_issues_count", ""),
            "repo_size_kb"       : d.get("size", ""),
            "repo_language"      : d.get("language") or "",
            "repo_topics"        : ", ".join(d.get("topics") or []),
            "repo_license"       : lic.get("spdx_id") or "",
            "repo_default_branch": d.get("default_branch", ""),
            "repo_visibility"    : d.get("visibility", ""),
            "repo_is_fork"       : d.get("fork", ""),
            "repo_is_archived"   : d.get("archived", ""),
            "repo_is_template"   : d.get("is_template", ""),
            "repo_created_at"    : d.get("created_at", ""),
            "repo_updated_at"    : d.get("updated_at", ""),
            "repo_pushed_at"     : d.get("pushed_at", ""),
        })
    elif resp.status_code == 404:
        out["repo_error"] = "Not found / no access"
    elif resp.status_code == 401:
        out["repo_error"] = "Unauthorized — check PAT_TOKEN"
    elif resp.status_code == 403:
        out["repo_error"] = "Forbidden / rate-limited"
    else:
        out["repo_error"] = f"HTTP {resp.status_code}"

    return out


# ---------------------------------------------------------------------------
# SECTION 2 — OWNER METADATA
# ---------------------------------------------------------------------------

def fetch_owner(owner: str, headers: dict) -> dict:
    url  = f"{GITHUB_API_BASE}/users/{owner}"
    resp = get(url, headers)
    out  = {
        "owner_login"       : owner,
        "owner_type"        : "",    # User or Organization
        "owner_name"        : "",
        "owner_email"       : "",
        "owner_bio"         : "",
        "owner_company"     : "",
        "owner_location"    : "",
        "owner_blog"        : "",
        "owner_twitter"     : "",
        "owner_html_url"    : "",
        "owner_public_repos": "",
        "owner_followers"   : "",
        "owner_following"   : "",
        "owner_created_at"  : "",
        "owner_updated_at"  : "",
        "owner_error"       : "",
    }

    if resp.status_code == 200:
        d = resp.json()
        out.update({
            "owner_type"        : d.get("type", ""),
            "owner_name"        : d.get("name") or "",
            "owner_email"       : d.get("email") or "",
            "owner_bio"         : d.get("bio") or "",
            "owner_company"     : d.get("company") or "",
            "owner_location"    : d.get("location") or "",
            "owner_blog"        : d.get("blog") or "",
            "owner_twitter"     : d.get("twitter_username") or "",
            "owner_html_url"    : d.get("html_url", ""),
            "owner_public_repos": d.get("public_repos", ""),
            "owner_followers"   : d.get("followers", ""),
            "owner_following"   : d.get("following", ""),
            "owner_created_at"  : d.get("created_at", ""),
            "owner_updated_at"  : d.get("updated_at", ""),
        })
    else:
        out["owner_error"] = f"HTTP {resp.status_code}"

    return out


# ---------------------------------------------------------------------------
# SECTION 3 — COMMIT METADATA
# ---------------------------------------------------------------------------

def fetch_commits(owner: str, repo: str, default_branch: str, headers: dict) -> list:
    """Returns a list of dicts, one per commit."""
    params = {"per_page": min(MAX_COMMITS, 100)}
    if COMMIT_BRANCH:
        params["sha"] = COMMIT_BRANCH
    elif default_branch:
        params["sha"] = default_branch

    url  = f"{GITHUB_API_BASE}/repos/{owner}/{repo}/commits"
    resp = get(url, headers, params=params)

    if resp.status_code != 200:
        return [{
            "commit_sha"            : "",
            "commit_short_sha"      : "",
            "commit_message"        : "",
            "commit_author_name"    : "",
            "commit_author_email"   : "",
            "commit_author_date"    : "",
            "commit_committer_name" : "",
            "commit_committer_email": "",
            "commit_committer_date" : "",
            "commit_html_url"       : "",
            "commit_verified"       : "",
            "commit_error"          : f"HTTP {resp.status_code}",
        }]

    commits = []
    for item in resp.json():
        c    = item.get("commit", {})
        auth = c.get("author") or {}
        comm = c.get("committer") or {}
        ver  = (c.get("verification") or {})
        commits.append({
            "commit_sha"            : item.get("sha", ""),
            "commit_short_sha"      : (item.get("sha") or "")[:7],
            "commit_message"        : (c.get("message") or "").split("\n")[0][:120],
            "commit_author_name"    : auth.get("name", ""),
            "commit_author_email"   : auth.get("email", ""),
            "commit_author_date"    : auth.get("date", ""),
            "commit_committer_name" : comm.get("name", ""),
            "commit_committer_email": comm.get("email", ""),
            "commit_committer_date" : comm.get("date", ""),
            "commit_html_url"       : item.get("html_url", ""),
            "commit_verified"       : ver.get("verified", ""),
            "commit_error"          : "",
        })

    return commits


# ---------------------------------------------------------------------------
# OUTPUT WRITERS
# ---------------------------------------------------------------------------

def write_csv(flat_rows: list, path: str) -> None:
    if not flat_rows:
        return
    fieldnames = list(flat_rows[0].keys())
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(flat_rows)


def write_json(results: list, path: str) -> None:
    """Writes structured JSON: one object per repo containing repo, owner, commits."""
    with open(path, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2)


def write_markdown(results: list, path: str) -> None:
    ts    = datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")
    lines = [
        "# GitHub Repository Scan Report",
        f"Generated: {ts}  |  Repos scanned: {len(results)}",
        "",
    ]

    for r in results:
        repo   = r["repo"]
        owner  = r["owner"]
        commits= r["commits"]

        lines += [
            f"---",
            f"## [{repo['repo_full_name']}]({repo['repo_html_url'] or '#'})",
            "",
        ]

        # Repo summary table
        lines += [
            "### Repository",
            f"| Field | Value |",
            f"|-------|-------|",
            f"| Description | {repo['repo_description']} |",
            f"| Language | {repo['repo_language']} |",
            f"| Stars | {repo['repo_stars']} |",
            f"| Forks | {repo['repo_forks']} |",
            f"| Open Issues | {repo['repo_open_issues']} |",
            f"| License | {repo['repo_license']} |",
            f"| Visibility | {repo['repo_visibility']} |",
            f"| Default Branch | {repo['repo_default_branch']} |",
            f"| Topics | {repo['repo_topics']} |",
            f"| Archived | {repo['repo_is_archived']} |",
            f"| Is Fork | {repo['repo_is_fork']} |",
            f"| Created | {repo['repo_created_at']} |",
            f"| Last Push | {repo['repo_pushed_at']} |",
            f"| Size | {repo['repo_size_kb']} KB |",
            "",
        ]

        # Owner summary table
        lines += [
            "### Owner",
            f"| Field | Value |",
            f"|-------|-------|",
            f"| Login | [{owner['owner_login']}]({owner['owner_html_url'] or '#'}) |",
            f"| Type | {owner['owner_type']} |",
            f"| Name | {owner['owner_name']} |",
            f"| Email | {owner['owner_email']} |",
            f"| Bio | {owner['owner_bio']} |",
            f"| Company | {owner['owner_company']} |",
            f"| Location | {owner['owner_location']} |",
            f"| Blog | {owner['owner_blog']} |",
            f"| Twitter | {owner['owner_twitter']} |",
            f"| Public Repos | {owner['owner_public_repos']} |",
            f"| Followers | {owner['owner_followers']} |",
            f"| Account Created | {owner['owner_created_at']} |",
            "",
        ]

        # Commits table
        lines += [
            f"### Recent Commits (last {len(commits)})",
            "| # | SHA | Author | Email | Date | Message | Verified |",
            "|---|-----|--------|-------|------|---------|----------|",
        ]
        for i, c in enumerate(commits, 1):
            sha_link = f"[{c['commit_short_sha']}]({c['commit_html_url']})" if c['commit_html_url'] else c['commit_short_sha']
            lines.append(
                f"| {i} | {sha_link} | {c['commit_author_name']} | "
                f"{c['commit_author_email']} | {c['commit_author_date'][:10] if c['commit_author_date'] else ''} | "
                f"{c['commit_message'][:60]} | {c['commit_verified']} |"
            )
        lines.append("")

    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))


# ---------------------------------------------------------------------------
# MAIN
# ---------------------------------------------------------------------------

def main() -> None:
    if not PAT_TOKEN:
        print("[!] No PAT_TOKEN set — unauthenticated (60 req/hr, public repos only).")

    Path(OUTPUT_DIR).mkdir(parents=True, exist_ok=True)
    print(f"[*] Output directory: {OUTPUT_DIR}/\n")

    headers    = build_headers()
    repos      = read_repos_from_csv(INPUT_CSV)
    print(f"[*] Loaded {len(repos)} repo(s) from {INPUT_CSV}\n")

    structured = []   # for JSON output
    flat_rows  = []   # for CSV output (one row per commit)

    for i, (owner, repo) in enumerate(repos, start=1):
        print(f"[{i}/{len(repos)}] {owner}/{repo}")

        print("    → repo metadata ...")
        repo_data  = fetch_repo(owner, repo, headers)

        print("    → owner metadata ...")
        owner_data = fetch_owner(owner, headers)

        print(f"    → last {MAX_COMMITS} commits ...")
        commits    = fetch_commits(owner, repo, repo_data.get("repo_default_branch", ""), headers)

        if repo_data.get("repo_error"):
            print(f"    [!] repo: {repo_data['repo_error']}")
        if owner_data.get("owner_error"):
            print(f"    [!] owner: {owner_data['owner_error']}")

        # structured record for JSON
        structured.append({
            "repo"   : repo_data,
            "owner"  : owner_data,
            "commits": commits,
        })

        # flat records for CSV — one row per commit
        for c in commits:
            row = {}
            row.update(repo_data)
            row.update(owner_data)
            row.update(c)
            flat_rows.append(row)

    write_csv(flat_rows, OUTPUT_CSV)
    print(f"\n[+] CSV   → {OUTPUT_CSV}")

    write_json(structured, OUTPUT_JSON)
    print(f"[+] JSON  → {OUTPUT_JSON}")

    write_markdown(structured, OUTPUT_MD)
    print(f"[+] MD    → {OUTPUT_MD}")

    print("\n[*] Scan complete.")


if __name__ == "__main__":
    main()
