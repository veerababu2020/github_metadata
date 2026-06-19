#!/usr/bin/env python3
"""
bulk_trufflehog_scan.py
-----------------------
Reads GitHub repo URLs from a CSV, runs `trufflehog git <url> --json`
for each, and for every finding enriches it with GitHub API metadata:
  - Repo-level  : full_name, html_url, description, forks, size_kb,
                  language, default_branch, visibility, is_archived,
                  created_at, updated_at, pushed_at
  - Owner-level : login, type, name, email, created_at, updated_at
  - Commit-level: sha, short_sha, message, author/committer names+emails+dates,
                  html_url, verification status

PAT TOKEN:
  Set GITHUB_TOKEN to a GitHub Personal Access Token.
  - public repos  → 'public_repo' scope (or no scope, just needs auth for rate-limit)
  - private repos → 'repo' scope
  Without a token: 60 API req/hr. With token: 5000 req/hr.

INPUT CSV FORMAT:
  github_url
  https://github.com/org/repo1
  https://github.com/org/repo2

OUTPUT FILES  (in OUTPUT_DIR/):
  findings.csv       — one row per finding, all metadata columns inline
  repo_metadata.csv  — one row per repo, metadata only
  findings.json      — structured JSON with summary stats
  README.md          — human-readable markdown report
"""

import csv
import json
import re
import ssl
import subprocess
import sys
import urllib.request
import urllib.error
from datetime import datetime
from pathlib import Path
from typing import Optional, Tuple

# ─── CONFIG ───────────────────────────────────────────────────────────────────
GITHUB_TOKEN    = "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"                  # GitHub PAT — set this before running
INPUT_CSV       = "repos.csv"         # CSV with a 'github_url' column
REPOS_COLUMN    = "github_url"        # Column name in INPUT_CSV
OUTPUT_DIR      = "bulk_scan_output"  # Output directory
ONLY_VERIFIED   = False               # True = only emit verified secrets
TRUFFLEHOG_BIN  = "trufflehog"        # Binary name or full path
SCAN_TIMEOUT    = 300                 # Seconds per repo (default 5 min)
# ──────────────────────────────────────────────────────────────────────────────

OUTPUT_CSV      = "findings.csv"
OUTPUT_META_CSV = "repo_metadata.csv"
OUTPUT_JSON     = "findings.json"
OUTPUT_MD       = "README.md"

# ── Exact output columns (matches the spec) ───────────────────────────────────
REPO_FIELDS = [
    "repo",
    "commit",                  # raw commit SHA from TruffleHog finding
    "repo_full_name",
    "repo_html_url",
    "repo_description",
    "repo_forks",
    "repo_size_kb",
    "repo_language",
    "repo_default_branch",
    "repo_visibility",
    "repo_is_archived",
    "repo_created_at",
    "repo_updated_at",
    "repo_pushed_at",
    "repo_error",
]

OWNER_FIELDS = [
    "owner_login",
    "owner_type",
    "owner_name",
    "owner_email",
    "owner_created_at",
    "owner_updated_at",
    "owner_error",
]

COMMIT_FIELDS = [
    "commit_sha",
    "commit_short_sha",
    "commit_message",
    "commit_author_name",
    "commit_author_email",
    "commit_author_date",
    "commit_committer_name",
    "commit_committer_email",
    "commit_committer_date",
    "commit_html_url",
    "commit_verified",
    "commit_error",
]

FINDING_FIELDS = [
    "detector",
    "verified",
    "raw",
    "rawv2",
    "file",
    "line",
    "branch",
    "source_name",
]

CSV_FIELDS = REPO_FIELDS + OWNER_FIELDS + COMMIT_FIELDS + FINDING_FIELDS


# ─── HELPERS ──────────────────────────────────────────────────────────────────

def redact(value: str) -> str:
    if not value:
        return ""
    v = str(value)
    if len(v) <= 8:
        return "*" * len(v)
    return v[:4] + "*" * (len(v) - 8) + v[-4:]


def parse_owner_repo(github_url: str) -> Optional[Tuple[str, str]]:
    m = re.match(
        r"https?://github\.com/([^/]+)/([^/]+?)(?:\.git)?/?$",
        github_url.strip(),
    )
    if m:
        return m.group(1), m.group(2)
    return None


def _ssl_ctx() -> ssl.SSLContext:
    """
    Return an SSL context that works on Windows/Mac where Python's bundled
    certificates may not include the GitHub issuer chain.
    Tries certifi first (most correct), falls back to system certs, then
    finally unverified as a last resort (logs a warning).
    """
    # 1. Try certifi if installed
    try:
        import certifi
        ctx = ssl.create_default_context(cafile=certifi.where())
        return ctx
    except ImportError:
        pass

    # 2. Try system default context
    try:
        ctx = ssl.create_default_context()
        ctx.load_default_certs()
        return ctx
    except Exception:
        pass

    # 3. Last resort — unverified (prints one-time warning)
    print("[WARN] SSL certificate verification disabled — install certifi for proper verification:")
    print("       pip install certifi")
    ctx = ssl._create_unverified_context()
    return ctx


# Build once, reuse for all requests
_SSL_CTX = _ssl_ctx()


def github_get(path: str) -> dict:
    url = f"https://api.github.com{path}"
    req = urllib.request.Request(url)
    req.add_header("Accept", "application/vnd.github+json")
    req.add_header("X-GitHub-Api-Version", "2022-11-28")
    if GITHUB_TOKEN:
        req.add_header("Authorization", f"Bearer {GITHUB_TOKEN}")
    with urllib.request.urlopen(req, timeout=15, context=_SSL_CTX) as resp:
        return json.loads(resp.read().decode())


# ─── REPO METADATA ────────────────────────────────────────────────────────────

def fetch_repo_meta(owner: str, repo: str) -> dict:
    """GET /repos/{owner}/{repo} → flat dict of repo_ + owner_ fields."""
    empty_repo  = {f: "" for f in REPO_FIELDS if f not in ("repo", "commit")}
    empty_owner = {f: "" for f in OWNER_FIELDS}

    try:
        r = github_get(f"/repos/{owner}/{repo}")
    except urllib.error.HTTPError as e:
        empty_repo["repo_error"] = f"http_{e.code}"
        empty_owner["owner_error"] = f"http_{e.code}"
        return {**empty_repo, **empty_owner}
    except Exception as e:
        msg = str(e)[:120]
        empty_repo["repo_error"]   = msg
        empty_owner["owner_error"] = msg
        return {**empty_repo, **empty_owner}

    o = r.get("owner", {})
    owner_login = o.get("login", "")

    # ── Owner detail: GET /users/{login} ──
    owner_name = owner_email = owner_created = owner_updated = ""
    owner_error = ""
    if owner_login:
        try:
            ud = github_get(f"/users/{owner_login}")
            owner_name    = ud.get("name")    or ""
            owner_email   = ud.get("email")   or ""
            owner_created = ud.get("created_at") or ""
            owner_updated = ud.get("updated_at") or ""
        except Exception as e:
            owner_error = str(e)[:80]

    repo_result = {
        "repo_full_name":     r.get("full_name", ""),
        "repo_html_url":      r.get("html_url", ""),
        "repo_description":   (r.get("description") or "").replace("\n", " ")[:200],
        "repo_forks":         str(r.get("forks_count", "")),
        "repo_size_kb":       str(r.get("size", "")),
        "repo_language":      r.get("language") or "",
        "repo_default_branch":r.get("default_branch", ""),
        "repo_visibility":    r.get("visibility", ""),
        "repo_is_archived":   str(r.get("archived", "")),
        "repo_created_at":    r.get("created_at", ""),
        "repo_updated_at":    r.get("updated_at", ""),
        "repo_pushed_at":     r.get("pushed_at", ""),
        "repo_error":         "",
    }
    owner_result = {
        "owner_login":      owner_login,
        "owner_type":       o.get("type", ""),
        "owner_name":       owner_name,
        "owner_email":      owner_email,
        "owner_created_at": owner_created,
        "owner_updated_at": owner_updated,
        "owner_error":      owner_error,
    }
    return {**repo_result, **owner_result}


# ─── COMMIT METADATA ──────────────────────────────────────────────────────────

def fetch_commit_meta(owner: str, repo: str, sha: str) -> dict:
    """GET /repos/{owner}/{repo}/commits/{sha} → flat dict of commit_ fields."""
    empty = {f: "" for f in COMMIT_FIELDS}

    if not sha:
        empty["commit_error"] = "no_sha"
        return empty

    try:
        c = github_get(f"/repos/{owner}/{repo}/commits/{sha}")
    except urllib.error.HTTPError as e:
        empty["commit_error"] = f"http_{e.code}"
        return empty
    except Exception as e:
        empty["commit_error"] = str(e)[:80]
        return empty

    detail   = c.get("commit", {})
    author   = detail.get("author", {})
    comitter = detail.get("committer", {})
    verif    = detail.get("verification", {})
    msg      = detail.get("message", "")

    return {
        "commit_sha":             c.get("sha", ""),
        "commit_short_sha":       c.get("sha", "")[:8],
        "commit_message":         (msg[:200] + "…") if len(msg) > 200 else msg,
        "commit_author_name":     author.get("name", ""),
        "commit_author_email":    author.get("email", ""),
        "commit_author_date":     author.get("date", ""),
        "commit_committer_name":  comitter.get("name", ""),
        "commit_committer_email": comitter.get("email", ""),
        "commit_committer_date":  comitter.get("date", ""),
        "commit_html_url":        c.get("html_url", ""),
        "commit_verified":        str(verif.get("verified", "")),
        "commit_error":           "",
    }


# ─── TRUFFLEHOG ───────────────────────────────────────────────────────────────

def load_repos(csv_path: str, column: str) -> list:
    repos = []
    with open(csv_path, newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        if column not in (reader.fieldnames or []):
            print(f"[ERROR] Column '{column}' not found in {csv_path}")
            print(f"        Available columns: {reader.fieldnames}")
            sys.exit(1)
        for row in reader:
            url = row[column].strip()
            if url:
                repos.append(url)
    return repos


def run_trufflehog(repo_url: str) -> list:
    cmd = [TRUFFLEHOG_BIN, "git", repo_url, "--json", "--no-update"]
    if ONLY_VERIFIED:
        cmd.append("--only-verified")

    print(f"  → {' '.join(cmd)}")

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=SCAN_TIMEOUT,
        )
    except subprocess.TimeoutExpired:
        print(f"  [TIMEOUT] {repo_url} exceeded {SCAN_TIMEOUT}s — skipping")
        return []
    except FileNotFoundError:
        print(f"  [ERROR] '{TRUFFLEHOG_BIN}' not found.")
        print("          Install: https://github.com/trufflesecurity/trufflehog#installation")
        sys.exit(1)

    findings = []
    for line in result.stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            findings.append(json.loads(line))
        except json.JSONDecodeError:
            pass
    return findings


def extract_finding_row(
    repo_url: str,
    finding: dict,
    repo_meta: dict,
    commit_meta: dict,
) -> dict:
    meta = finding.get("SourceMetadata", {}).get("Data", {})
    git_meta = (
        meta.get("Git")
        or meta.get("Github")
        or meta.get("Gitlab")
        or {}
    )

    raw   = finding.get("Raw", "")
    rawv2 = finding.get("RawV2", "")

    row = {
        "repo":   repo_url,
        "commit": git_meta.get("commit", ""),
    }
    row.update(repo_meta)
    row.update(commit_meta)
    row.update({
        "detector":       finding.get("DetectorName", ""),
        "verified":       str(finding.get("Verified", False)),
        "raw":            raw,
        "rawv2":          rawv2,
        "file":           git_meta.get("file", ""),
        "line":           str(git_meta.get("line", "")),
        "branch":         git_meta.get("branch", ""),
        "source_name":    finding.get("SourceName", ""),
    })
    return row


# ─── OUTPUT WRITERS ───────────────────────────────────────────────────────────

def write_findings_csv(rows: list, out_path: Path) -> None:
    with open(out_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=CSV_FIELDS, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)


def write_meta_csv(meta_map: dict, out_path: Path) -> None:
    fields = ["repo_url"] + [f for f in REPO_FIELDS if f not in ("repo","commit")] + OWNER_FIELDS
    with open(out_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        for url, meta in meta_map.items():
            row = {"repo_url": url}
            row.update(meta)
            writer.writerow(row)


def write_json(rows: list, meta_map: dict, stats: dict, out_path: Path) -> None:
    payload = {
        "scan_time":           stats["scan_time"],
        "repos_scanned":       stats["repos_total"],
        "repos_with_findings": stats["repos_with_findings"],
        "total_findings":      stats["total"],
        "verified_findings":   stats["verified"],
        "unverified_findings": stats["unverified"],
        "detector_breakdown":  stats["detectors"],
        "repo_metadata":       meta_map,
        "findings":            rows,
    }
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2)


def write_md(rows: list, meta_map: dict, stats: dict, out_path: Path) -> None:
    lines = [
        "# Bulk TruffleHog Scan Report",
        "",
        f"**Scan time:** {stats['scan_time']}  ",
        f"**Repos scanned:** {stats['repos_total']}  ",
        f"**Repos with findings:** {stats['repos_with_findings']}  ",
        f"**Total findings:** {stats['total']}  ",
        f"**Verified:** {stats['verified']}  ",
        f"**Unverified:** {stats['unverified']}  ",
        "",
        "---",
        "",
        "## Repository Overview",
        "",
        "| Repo | Visibility | Language | Forks | Archived | Pushed |",
        "|------|------------|----------|-------|----------|--------|",
    ]
    for url, m in meta_map.items():
        short = m.get("repo_full_name") or url.replace("https://github.com/", "")
        pushed = (m.get("repo_pushed_at") or "")[:10]
        lines.append(
            f"| [{short}]({url}) "
            f"| {m.get('repo_visibility','')} "
            f"| {m.get('repo_language','')} "
            f"| {m.get('repo_forks','')} "
            f"| {m.get('repo_is_archived','')} "
            f"| {pushed} |"
        )

    lines += [
        "",
        "---",
        "",
        "## Detector Breakdown",
        "",
        "| Detector | Count |",
        "|----------|-------|",
    ]
    for det, cnt in sorted(stats["detectors"].items(), key=lambda x: -x[1]):
        lines.append(f"| {det} | {cnt} |")

    lines += [
        "",
        "---",
        "",
        "## Findings",
        "",
        "| Repo | Detector | Verified | File | Line | Commit SHA | Author | Date | Commit URL |",
        "|------|----------|----------|------|------|------------|--------|------|------------|",
    ]
    for r in rows:
        short_sha   = r.get("commit_short_sha") or r.get("commit","")[:8]
        commit_url  = r.get("commit_html_url","")
        sha_cell    = f"[{short_sha}]({commit_url})" if commit_url else short_sha
        author_date = (r.get("commit_author_date","") or "")[:10]
        short_repo  = (r.get("repo_full_name") or r.get("repo","")).replace("https://github.com/","")
        lines.append(
            f"| {short_repo} "
            f"| {r.get('detector','')} "
            f"| {r.get('verified','')} "
            f"| {r.get('file','')} "
            f"| {r.get('line','')} "
            f"| {sha_cell} "
            f"| {r.get('commit_author_name','')} "
            f"| {author_date} "
            f"| |"
        )

    out_path.write_text("\n".join(lines), encoding="utf-8")


# ─── MAIN ─────────────────────────────────────────────────────────────────────

def main():
    if not Path(INPUT_CSV).exists():
        print(f"[ERROR] Input file not found: {INPUT_CSV}")
        sys.exit(1)

    repos = load_repos(INPUT_CSV, REPOS_COLUMN)
    if not repos:
        print("[ERROR] No repos found in input CSV.")
        sys.exit(1)

    if not GITHUB_TOKEN:
        print("[WARN] GITHUB_TOKEN is empty — metadata fetch will be unauthenticated.")
        print("       Rate limit: 60 req/hr. Set GITHUB_TOKEN for 5000 req/hr.")
    else:
        print(f"[*] Using GitHub PAT (last 4: ...{GITHUB_TOKEN[-4:]})")

    print(f"[*] Loaded {len(repos)} repos from {INPUT_CSV}")
    print(f"[*] Only-verified mode: {ONLY_VERIFIED}")

    out_dir = Path(OUTPUT_DIR)
    out_dir.mkdir(parents=True, exist_ok=True)

    all_rows:    list  = []
    repo_meta_map: dict = {}
    repos_with_findings = 0
    scan_time = datetime.utcnow().isoformat() + "Z"

    # Commit metadata cache — avoid re-fetching same SHA across multiple findings
    commit_cache: dict = {}

    for i, repo_url in enumerate(repos, 1):
        print(f"\n[{i}/{len(repos)}] {repo_url}")

        parsed = parse_owner_repo(repo_url)
        if not parsed:
            print("  [SKIP] Could not parse owner/repo from URL")
            repo_meta_map[repo_url] = {f: "" for f in REPO_FIELDS + OWNER_FIELDS}
            repo_meta_map[repo_url]["repo_error"] = "invalid_url"
            continue

        owner, repo_name = parsed

        # ── Step 1: Repo + owner metadata ──────────────────────────────────
        print("  → Fetching repo/owner metadata...")
        meta = fetch_repo_meta(owner, repo_name)
        repo_meta_map[repo_url] = meta

        if meta.get("repo_error"):
            print(f"  [META ERROR] {meta['repo_error']}")
        else:
            print(
                f"  ✓ {meta.get('repo_visibility','')} | "
                f"{meta.get('repo_language','')} | "
                f"forks:{meta.get('repo_forks','')} | "
                f"archived:{meta.get('repo_is_archived','')} | "
                f"pushed:{(meta.get('repo_pushed_at') or '')[:10]}"
            )

        # ── Step 2: TruffleHog scan ─────────────────────────────────────────
        print("  → Running TruffleHog...")
        findings = run_trufflehog(repo_url)

        if not findings:
            print("  – No findings")
            continue

        repos_with_findings += 1
        print(f"  ✓ {len(findings)} finding(s) — fetching commit metadata...")

        for finding in findings:
            git_meta = (
                finding.get("SourceMetadata", {})
                        .get("Data", {})
                        .get("Git")
                or finding.get("SourceMetadata", {})
                          .get("Data", {})
                          .get("Github")
                or {}
            )
            sha = git_meta.get("commit", "")

            # Cache key = owner/repo + sha
            cache_key = f"{owner}/{repo_name}#{sha}"
            if cache_key not in commit_cache:
                if sha:
                    print(f"    → Commit metadata: {sha[:8]}")
                commit_cache[cache_key] = fetch_commit_meta(owner, repo_name, sha)

            commit_meta = commit_cache[cache_key]
            all_rows.append(extract_finding_row(repo_url, finding, meta, commit_meta))

    # ── Stats ───────────────────────────────────────────────────────────────
    verified_count   = sum(1 for r in all_rows if r.get("verified","").lower() == "true")
    unverified_count = len(all_rows) - verified_count

    detector_counts: dict = {}
    for r in all_rows:
        d = r.get("detector") or "Unknown"
        detector_counts[d] = detector_counts.get(d, 0) + 1

    stats = {
        "scan_time":           scan_time,
        "repos_total":         len(repos),
        "repos_with_findings": repos_with_findings,
        "total":               len(all_rows),
        "verified":            verified_count,
        "unverified":          unverified_count,
        "detectors":           detector_counts,
    }

    # ── Write outputs ────────────────────────────────────────────────────────
    write_findings_csv(all_rows,  out_dir / OUTPUT_CSV)
    write_meta_csv(repo_meta_map, out_dir / OUTPUT_META_CSV)
    write_json(all_rows, repo_meta_map, stats, out_dir / OUTPUT_JSON)
    write_md(all_rows,   repo_meta_map, stats, out_dir / OUTPUT_MD)

    # ── Summary ──────────────────────────────────────────────────────────────
    print("\n" + "=" * 60)
    print("SCAN COMPLETE")
    print("=" * 60)
    print(f"  Repos scanned        : {len(repos)}")
    print(f"  Repos with findings  : {repos_with_findings}")
    print(f"  Total findings       : {len(all_rows)}")
    print(f"  Verified             : {verified_count}")
    print(f"  Unverified           : {unverified_count}")
    print(f"\nOutputs → {out_dir.resolve()}/")
    print(f"  {OUTPUT_CSV}       — findings + all metadata columns")
    print(f"  {OUTPUT_META_CSV}  — repo metadata only")
    print(f"  {OUTPUT_JSON}")
    print(f"  {OUTPUT_MD}")


if __name__ == "__main__":
    main()
