#!/usr/bin/env python3
"""
CodeMender Forensic Log Lookback Hunter (`cm hunt`)

Translates a CodeMender vulnerability finding (Source + Conceptual Exploit Payload + Sink)
into multi-layer forensic queries and executes a historical lookback against:
  1. Google Cloud Logging (`logging.googleapis.com/v2/entries:list`) [Default Active Provider]
  2. Google SecOps / Chronicle (`chronicle.googleapis.com/v1alpha/...:udmSearch`) [Extensible Provider]

Features:
  - Automatic exposure window calculation via `git log -L` / `git blame` on the vulnerable lines.
  - 3-Layer Forensic Hunt:
      * Layer 0: Endpoint Baseline Telemetry Check (verifies logs exist for the route/service)
      * Layer 1: Generalized Ingress Exploit Signature (HTTP/WAF/Request payload patterns)
      * Layer 2/3: Application Error & Host/Container Sink Execution traces
  - Optional `--seed-demo` (`SEED_DEMO_LOGS=true`) mode to inject realistic baseline + exploit
    telemetry into Google Cloud Logging for live customer demonstrations.
  - Generates Cloud Logging filters, Log Analytics (BigQuery) SQL, and Google SecOps YARA-L 2.0 rules.
"""

import base64
import datetime
import json
import os
import re
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request


# ==============================================================================
# CWE-to-Forensic Exploit Pattern Library
# ==============================================================================
CWE_EXPLOIT_PATTERNS = {
    "CWE-78": {
        "name": "OS Command Injection",
        "ingress_regex": r"(;[[:space:]]*(id|whoami|uname|cat|curl|wget|nc|bash|sh)|&&|\|\||%3[bB]|%7[cC]|%26%26|/etc/passwd|/bin/sh)",
        "sink_regex": r"(ping[[:space:]]+-c[[:space:]]+1[[:space:]]+[^;]*;|os\.popen|subprocess\.|/bin/sh[[:space:]]+-c|uid=[0-9]+)",
        "yaral_pattern": r"[;&|\x60$><\n]|%(3b|7c|26|60|24)|\b(id|whoami|cat|curl|wget|nc|bash)\b",
    },
    "CWE-89": {
        "name": "SQL Injection",
        "ingress_regex": r"('([[:space:]]|%20)*(OR|AND|UNION|SELECT|--|#)|UNION([[:space:]]|%20)+ALL([[:space:]]|%20)+SELECT|1[[:space:]]*=[[:space:]]*1|SLEEP\([0-9]+\)|sqlite_master|information_schema)",
        "sink_regex": r"(SequelizeDatabaseError|SQLITE_ERROR|syntax error at or near|unrecognized token|ORA-[0-9]+|error in your SQL syntax)",
        "yaral_pattern": r"('|\b(UNION\s+SELECT|OR\s+1=1|SLEEP\(|information_schema|sqlite_master)\b)",
    },
    "CWE-943": {
        "name": "NoSQL / JavaScript Injection",
        "ingress_regex": r"(\$where|\$ne|\$gt|\$regex|this\.constructor|sleep\([0-9]+\)|'[[:space:]]*\|\|[[:space:]]*'1'[[:space:]]*==[[:space:]]*'1)",
        "sink_regex": r"(MongoError|MongoServerError|\$where|SyntaxError.*unexpected token|BSONObj)",
        "yaral_pattern": r"(\$where|\$ne|\$gt|\$regex|'\s*\|\|\s*')",
    },
    "CWE-94": {
        "name": "Code Injection / RCE",
        "ingress_regex": r"(process\.mainModule|child_process|execSync|eval\(|Function\(|__import__|os\.system|global\.process)",
        "sink_regex": r"(ReferenceError|SyntaxError|child_process|spawnSync|execSync|evalmachine)",
        "yaral_pattern": r"(child_process|mainModule|execSync|__import__|os\.system)",
    },
    "CWE-22": {
        "name": "Path Traversal / Arbitrary File Access",
        "ingress_regex": r"(\.\./|\.\.\\|%2e%2e%2f|%252e%252e|/etc/passwd|/proc/self/environ)",
        "sink_regex": r"(ENOENT|EACCES|FileNotFoundError|PermissionError|\.\./)",
        "yaral_pattern": r"(\.\./|\.\.\\|%2e%2e|/etc/passwd)",
    },
    "CWE-918": {
        "name": "Server-Side Request Forgery (SSRF)",
        "ingress_regex": r"(169\.254\.169\.254|metadata\.google\.internal|127\.0\.0\.1|localhost|0\.0\.0\.0|file://|gopher://)",
        "sink_regex": r"(169\.254\.169\.254|metadata\.google\.internal|ECONNREFUSED|ConnectTimeoutError)",
        "yaral_pattern": r"(169\.254\.169\.254|metadata\.google\.internal|127\.0\.0\.1|localhost|file://)",
    },
    "CWE-611": {
        "name": "XML External Entity (XXE)",
        "ingress_regex": r"(<!DOCTYPE|<!ENTITY|SYSTEM[[:space:]]+['\"]file:|SYSTEM[[:space:]]+['\"]http)",
        "sink_regex": r"(XMLSyntaxError|SAXParseException|EntityRef|<!ENTITY)",
        "yaral_pattern": r"(<!DOCTYPE|<!ENTITY|SYSTEM\s+[\"']file:)",
    },
    "CWE-79": {
        "name": "Cross-Site Scripting (XSS)",
        "ingress_regex": r"(<script|javascript:|onerror[[:space:]]*=|onload[[:space:]]*=|<svg[^>]*onload|<iframe|%3Cscript|script-src[[:space:]]+'self'[[:space:]]+'unsafe-inline')",
        "sink_regex": r"(<script|onerror=|Content-Security-Policy)",
        "yaral_pattern": r"(<script|javascript:|onerror=|onload=|<svg|unsafe-inline)",
    },
    "CWE-284": {
        "name": "Improper Access Control / Authorization Bypass",
        "ingress_regex": r"(delete_all_pastes|delete_paste|edit_paste|systemHealth|admin|__schema)",
        "sink_regex": r"(Unauthorized|Forbidden|PermissionDenied|AccessDenied)",
        "yaral_pattern": r"(delete_all_pastes|delete_paste|edit_paste|systemHealth)",
    },
    "CWE-285": {
        "name": "Improper Authorization",
        "ingress_regex": r"(delete_all_pastes|delete_paste|edit_paste|systemHealth|admin)",
        "sink_regex": r"(Unauthorized|Forbidden|PermissionDenied)",
        "yaral_pattern": r"(delete_all_pastes|delete_paste|edit_paste|systemHealth)",
    },
    "CWE-639": {
        "name": "Insecure Direct Object Reference (IDOR / BOLA)",
        "ingress_regex": r"(delete_paste|edit_paste|coupon|basket|victim_review_id)",
        "sink_regex": r"(Unauthorized|Forbidden|Sequelize)",
        "yaral_pattern": r"(delete_paste|edit_paste|coupon|basket)",
    },
    "CWE-862": {
        "name": "Missing Authorization",
        "ingress_regex": r"(delete_all_pastes|delete_paste|edit_paste|systemHealth|admin|__schema)",
        "sink_regex": r"(Unauthorized|Forbidden|PermissionDenied|SecurityError)",
        "yaral_pattern": r"(delete_all_pastes|delete_paste|edit_paste|systemHealth)",
    },
    "CWE-863": {
        "name": "Incorrect Authorization",
        "ingress_regex": r"(systemHealth|delete_all_pastes|delete_paste|edit_paste|admin|__schema)",
        "sink_regex": r"(SecurityError|Operation Name|Unauthorized|Forbidden|PermissionDenied)",
        "yaral_pattern": r"(systemHealth|delete_all_pastes|delete_paste|edit_paste)",
    },
    "CWE-200": {
        "name": "Information Exposure",
        "ingress_regex": r"(__schema|__type|systemHealth|debug|stacktrace|environ)",
        "sink_regex": r"(Traceback|Exception|Error|stack)",
        "yaral_pattern": r"(__schema|__type|systemHealth|debug)",
    },
}


def get_gcloud_token():
    """Fetches an OAuth2 access token from the active Cloud Run / gcloud identity."""
    try:
        res = subprocess.run(
            ["gcloud", "auth", "print-access-token"],
            capture_output=True,
            text=True,
            check=True,
            timeout=10,
        )
        return res.stdout.strip()
    except Exception as e:
        print(f"⚠️ Could not obtain gcloud access token: {e}", file=sys.stderr)
        return ""


def fetch_issue_context(repo, issue_number="", vuln_id=""):
    """Fetches the GitHub Issue title and body and parses CodeMender metadata + conceptual payload."""
    env = os.environ.copy()
    if os.environ.get("GITHUB_TOKEN") and not env.get("GH_TOKEN"):
        env["GH_TOKEN"] = os.environ["GITHUB_TOKEN"]

    if not issue_number and repo and vuln_id:
        res = subprocess.run(
            ["gh", "issue", "list", "--repo", repo, "--state", "all", "--search", f"in:title {vuln_id}", "--json", "number"],
            capture_output=True,
            text=True,
            env=env,
        )
        if res.returncode == 0 and res.stdout.strip() and res.stdout.strip() != "[]":
            try:
                issue_number = str(json.loads(res.stdout)[0]["number"])
            except Exception:
                pass

    if not issue_number:
        raise RuntimeError(f"Could not locate GitHub Issue for finding '{vuln_id}' in {repo}.")

    res = subprocess.run(
        ["gh", "issue", "view", str(issue_number), "--repo", repo, "--json", "number,title,body,url"],
        capture_output=True,
        text=True,
        env=env,
    )
    if res.returncode != 0:
        raise RuntimeError(f"Failed to fetch Issue #{issue_number} from {repo}: {res.stderr.strip()}")

    issue_data = json.loads(res.stdout)
    body = issue_data.get("body", "")
    title = issue_data.get("title", "")

    # 1. Parse embedded <!-- codemender-finding-metadata ... -->
    meta = {}
    meta_match = re.search(r"<!--\s*codemender-finding-metadata\s*\n(.*?)\n-->", body, re.DOTALL)
    if meta_match:
        try:
            meta = json.loads(meta_match.group(1))
        except Exception:
            pass

    # 2. Extract Vulnerability Analysis (Source, Validation, Sink, Conceptual Exploit Payload)
    analysis_text = ""
    analysis_match = re.search(r"### 🔬 Vulnerability Analysis\s*\n(.*?)(?=\n---\n|\n### |\Z)", body, re.DOTALL)
    if analysis_match:
        analysis_text = analysis_match.group(1).strip()

    # 3. Extract Conceptual Exploit Payload block
    conceptual_payload = ""
    payload_match = re.search(
        r"(?:\*\*|#+\s*)?Conceptual Exploit Payload:?\*?\*?\s*\n+(.*?)(?=\n\n[A-Z][a-z]+[^:\n]*\.|\n---\n|\Z)",
        analysis_text,
        re.DOTALL | re.IGNORECASE,
    )
    if payload_match:
        conceptual_payload = payload_match.group(1).strip()
    elif analysis_text:
        conceptual_payload = analysis_text

    # 4. Extract Source & Sink lines
    source_desc = ""
    src_m = re.search(r"Source:\s*(.+)", analysis_text)
    if src_m:
        source_desc = src_m.group(1).strip()

    sink_desc = ""
    sink_m = re.search(r"Sink:\s*(.+)", analysis_text)
    if sink_m:
        sink_desc = sink_m.group(1).strip()

    # 5. Extract Vulnerable Code Snippet
    snippet_text = ""
    snip_m = re.search(r"### 📄 Vulnerable Code Snippet\s*\n```[^\n]*\n(.*?)```", body, re.DOTALL)
    if snip_m:
        snippet_text = snip_m.group(1).strip()

    return {
        "issue_number": str(issue_data.get("number", issue_number)),
        "issue_url": issue_data.get("url", f"https://github.com/{repo}/issues/{issue_number}"),
        "title": title,
        "body": body,
        "finding_id": meta.get("finding_id") or vuln_id or "unknown",
        "file": meta.get("file", ""),
        "cwe": meta.get("cwe", "CWE-78"),
        "vuln_type": meta.get("vuln_type", "Security Finding"),
        "start_line": meta.get("start_line"),
        "end_line": meta.get("end_line"),
        "analysis": analysis_text,
        "source_desc": source_desc,
        "sink_desc": sink_desc,
        "conceptual_payload": conceptual_payload,
        "snippet": snippet_text,
    }


def calculate_git_exposure_window(workspace_dir, file_path, start_line=None, end_line=None, override_days=None):
    """
    Uses `git log -L` / `git log` on the vulnerable file/lines to identify the commit
    and timestamp when the vulnerable code was introduced.
    """
    now = datetime.datetime.now(datetime.timezone.utc)
    default_days = int(override_days) if override_days else 30
    commit_info = {
        "commit_sha": "HEAD",
        "commit_short": "HEAD",
        "author": "unknown",
        "commit_date_iso": (now - datetime.timedelta(days=default_days)).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "subject": "Repository baseline",
        "age_days": default_days,
        "lookback_days": default_days,
        "start_time_iso": (now - datetime.timedelta(days=default_days)).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "end_time_iso": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
    }

    if not workspace_dir or not os.path.isdir(workspace_dir) or not file_path:
        return commit_info

    cmds = []
    if start_line and end_line:
        cmds.append(["git", "-C", workspace_dir, "log", "-n", "1", f"-L{start_line},{end_line}:{file_path}", "-s", "--format=%H|%aI|%an|%s"])
    cmds.append(["git", "-C", workspace_dir, "log", "-n", "1", "--format=%H|%aI|%an|%s", "--", file_path])

    for cmd in cmds:
        try:
            res = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            if res.returncode == 0 and "|" in res.stdout:
                line = res.stdout.strip().splitlines()[0]
                parts = line.split("|", 3)
                if len(parts) == 4:
                    sha, iso_str, author, subj = parts
                    dt = datetime.datetime.fromisoformat(iso_str.replace("Z", "+00:00")).astimezone(datetime.timezone.utc)
                    age_days = max(1, int((now - dt).total_seconds() // 86400) + 1)
                    # Search at least 14 days (or since commit introduction, capped at 30d for Cloud Logging default bucket unless overridden)
                    if override_days:
                        lookback_days = int(override_days)
                    else:
                        lookback_days = max(14, min(age_days + 1, 30))
                    start_dt = min(dt - datetime.timedelta(hours=1), now - datetime.timedelta(days=lookback_days))
                    # Ensure start_dt stays within 30 days for Cloud Logging default retention unless overridden
                    if not override_days and (now - start_dt).days > 30:
                        start_dt = now - datetime.timedelta(days=30)
                    commit_info.update({
                        "commit_sha": sha,
                        "commit_short": sha[:8],
                        "author": author,
                        "commit_date_iso": dt.strftime("%Y-%m-%dT%H:%M:%SZ"),
                        "subject": subj,
                        "age_days": age_days,
                        "lookback_days": lookback_days,
                        "start_time_iso": start_dt.strftime("%Y-%m-%dT%H:%M:%SZ"),
                    })
                    break
        except Exception:
            pass

    return commit_info


def cl_quote(val):
    """Escapes quotes for safe inclusion inside a double-quoted Google Cloud Logging filter literal."""
    return val.replace('"', '\\"')


def fetch_verified_exploit(repo, issue_number, finding_id, workspace_dir="", artifacts_dir=""):
    """
    Locates and downloads the verified sandbox `exploit.sh` (and `REPORT.md`) generated
    by `/cm verify` from either the local workspace or the `codemender/artifacts` branch.
    """
    env = os.environ.copy()
    if os.environ.get("GITHUB_TOKEN") and not env.get("GH_TOKEN"):
        env["GH_TOKEN"] = os.environ["GITHUB_TOKEN"]

    # 1. Check local workspace `.exploit/exploit.sh` first
    local_candidates = [
        os.path.join(workspace_dir, ".exploit", "exploit.sh") if workspace_dir else "",
        os.path.join(artifacts_dir, "exploit", "exploit.sh") if artifacts_dir else "",
    ]
    for lp in local_candidates:
        if lp and os.path.isfile(lp):
            with open(lp, "r", encoding="utf-8", errors="replace") as f:
                exploit_sh = f.read()
            report_md = ""
            rp = os.path.join(os.path.dirname(lp), "REPORT.md")
            if os.path.isfile(rp):
                with open(rp, "r", encoding="utf-8", errors="replace") as rf:
                    report_md = rf.read()
            subpath = f"verify/issue-{issue_number}-{finding_id}/exploit/exploit.sh" if issue_number else f"verify/{finding_id}/exploit/exploit.sh"
            return {
                "found": True,
                "exploit_sh": exploit_sh,
                "report_md": report_md,
                "artifact_path": subpath,
                "exploit_url": f"https://github.com/{repo}/blob/codemender/artifacts/{subpath}" if repo else subpath,
            }

    # 2. Fetch from `codemender/artifacts` branch on GitHub
    if repo:
        candidate_paths = []
        if issue_number:
            candidate_paths.append(f"verify/issue-{issue_number}-{finding_id}/exploit/exploit.sh")
        candidate_paths.append(f"verify/{finding_id}/exploit/exploit.sh")

        for subpath in candidate_paths:
            res = subprocess.run(
                ["gh", "api", f"repos/{repo}/contents/{subpath}?ref=codemender/artifacts", "--jq", ".content"],
                capture_output=True,
                text=True,
                env=env,
            )
            if res.returncode == 0 and res.stdout.strip():
                try:
                    exploit_sh = base64.b64decode(res.stdout.strip()).decode("utf-8", errors="replace")
                    report_subpath = subpath.replace("/exploit.sh", "/REPORT.md")
                    report_md = ""
                    r_res = subprocess.run(
                        ["gh", "api", f"repos/{repo}/contents/{report_subpath}?ref=codemender/artifacts", "--jq", ".content"],
                        capture_output=True,
                        text=True,
                        env=env,
                    )
                    if r_res.returncode == 0 and r_res.stdout.strip():
                        report_md = base64.b64decode(r_res.stdout.strip()).decode("utf-8", errors="replace")
                    return {
                        "found": True,
                        "exploit_sh": exploit_sh,
                        "report_md": report_md,
                        "artifact_path": subpath,
                        "exploit_url": f"https://github.com/{repo}/blob/codemender/artifacts/{subpath}",
                    }
                except Exception as e:
                    print(f"⚠️ Failed decoding {subpath}: {e}", file=sys.stderr)

    return {
        "found": False,
        "exploit_sh": "",
        "report_md": "",
        "artifact_path": "",
        "exploit_url": "",
    }


def extract_exploit_payload_snippet(exploit_sh):
    """
    Extracts the client exploit payload construction and execution section from `exploit.sh`
    (omitting sandbox target server boilerplate) and returns a clean fenced codeblock.
    """
    s = (exploit_sh or "").replace("\r\n", "\n").strip()
    if not s:
        return "```bash\n# No exploit.sh content available\n```"

    # Case 1: Dedicated client script heredoc (`poc.py`, `client.py`, `exploit.py`, `attack.py`)
    for m in re.finditer(
        r"(?:^|\n)(#[^\n]*\n)?(cat\s+<<\s*['\"]?EOF['\"]?\s*>\s*([^\n]+)\n(.*?)\nEOF)\b",
        s,
        flags=re.DOTALL,
    ):
        comment_hdr = (m.group(1) or "").strip()
        full_heredoc = m.group(2).strip()
        target_file = m.group(3).strip()
        if any(name in target_file.lower() for name in ("poc.", "client.", "exploit.", "attack.")):
            snippet = (f"{comment_hdr}\n{full_heredoc}" if comment_hdr else full_heredoc).strip()
            exec_lines = []
            for line in s[m.end():].splitlines():
                if any(k in line for k in ("poc.", "client.", "exploit.", "Step ", "Executing exploit")):
                    exec_lines.append(line)
            if exec_lines:
                snippet += "\n\n# Execute verified exploit payload:\n" + "\n".join(exec_lines[:8])
            return f"```bash\n{snippet}\n```"

    # Case 2: Inline Node `http.request(...)` client block
    http_req_block = re.search(
        r"(console\.log\([^\n]*Sending[^\n]*\);\s*\n)?\s*const\s+req\s*=\s*http\.request\(\s*\{.*?\}\s*,\s*\(res\)\s*=>\s*\{.*?\n\s*\}\s*\);",
        s,
        flags=re.DOTALL,
    )
    if http_req_block:
        lines = http_req_block.group(0).strip().splitlines()
        if len(lines) > 36:
            lines = lines[:34] + ["  // ... (see full exploit.sh for assertion details)", "});"]
        return "```javascript\n" + "\n".join(lines) + "\n```"

    # Fallback: strip sandbox server.js heredocs and show the main exploit commands
    cleaned = re.sub(
        r"cat\s+<<\s*['\"]?EOF['\"]?\s*>\s*[^\n]*server\.[a-zA-Z0-9_]+\n.*?\nEOF\b",
        "# [Sandbox target server setup omitted — see full exploit.sh]",
        s,
        flags=re.DOTALL,
    )
    lines = cleaned.splitlines()
    if len(lines) > 45:
        lines = lines[:45] + ["# ... (see full exploit.sh artifact)"]
    return "```bash\n" + "\n".join(lines) + "\n```"


def parse_exploit_sh(exploit_sh, report_md=""):
    """
    Parses the verified `exploit.sh` script (and optional `REPORT.md`) to extract:
      - Verified HTTP method (`GET`, `POST`, `PUT`, `DELETE`, `PATCH`)
      - Verified target route (`/file-upload`, `/dataerasure`, `/rest/basket/2`, `/graphql`, etc.)
      - Verified request parameter / form field names (`file`, `layout`, `query`, etc.)
      - Concrete exploit payload tokens (`../../ftp/legal.md`, `exploit.zip`, `/etc/passwd`, etc.)
      - Concrete sink / error indicators (`ftp/legal.md`, `File access not allowed`, etc.)
    """
    s = (exploit_sh or "").replace("\r\n", "\n")
    http_method = None
    route = None

    # 1. Extract target route from client URLs in exploit.sh
    url_matches = re.findall(
        r"https?://(?:127\.0\.0\.1|localhost|0\.0\.0\.0)(?::(?:\$\{?[A-Za-z0-9_]+\}?|\{[A-Za-z0-9_]+\}|[0-9]+))?(/[A-Za-z0-9_/\-\.]+)",
        s,
    )
    if url_matches:
        route = url_matches[0]

    # Look for Node http.request `path: '/...'`
    if not route:
        path_matches = re.findall(r"\bpath:\s*['\"](/[A-Za-z0-9_/\-\.]+)['\"]", s)
        if path_matches:
            route = path_matches[0]

    # Look for server route check `req.url === '/...'` or `urlPath === '/...'`
    if not route:
        srv_matches = re.findall(r"(?:req\.url|urlPath|httpReq\.url)\s*===\s*['\"](/[A-Za-z0-9_/\-\.]+)['\"]", s)
        if srv_matches:
            route = srv_matches[0]

    # 2. Extract HTTP method from client request or server handler
    m_client = re.findall(r"\bmethod\s*[:=]\s*['\"](GET|POST|PUT|DELETE|PATCH)['\"]", s)
    if m_client:
        http_method = m_client[-1].upper()
    if not http_method:
        m_curl = re.findall(r"curl\s+[^\n]*?-X\s*(GET|POST|PUT|DELETE|PATCH)", s)
        if m_curl:
            http_method = m_curl[0].upper()
    if not http_method:
        m_srv = re.findall(r"(?:req|httpReq)\.method\s*(?:===|!==)\s*['\"](GET|POST|PUT|DELETE|PATCH)['\"]", s)
        if m_srv:
            http_method = m_srv[0].upper()

    # 3. Extract concrete exploit payload tokens from exploit.sh
    tokens = []

    def add_tok(t):
        t = (t or "").strip()
        if t and len(t) >= 2 and t not in tokens:
            tokens.append(t)

    # Zip / archive writestr entries (e.g. "../../ftp/legal.md")
    for m in re.findall(r"writestr\(\s*['\"]([^'\"]+)['\"]", s):
        add_tok(m)
    # Traversal sequences (e.g. "../../ftp/legal.md")
    for m in re.findall(r"((?:\.\./)+[A-Za-z0-9_/\-\.]+)", s):
        add_tok(m)
    # Multipart filenames (e.g. "exploit.zip")
    for m in re.findall(r'filename=\\?["\']([^"\'\\]+)\\?["\']', s):
        add_tok(m)
    # Arguments passed to client.py / poc.py in bash steps (e.g. "/etc/passwd", "juice-shop/package.json", "ctf.key")
    for m in re.findall(r'(?:client|poc|exploit)\.py["\']?\s+["\']?\$\{?[A-Za-z0-9_]+\}?["\']?\s+["\']([^"\']+)["\']', s):
        add_tok(m)
    # GraphQL / API operation tokens in exploit.sh
    for m in re.findall(r"\b(system_diagnostics|import_paste|importPaste|system_debug|delete_all_pastes|delete_paste|edit_paste|upload_paste|systemHealth|orderLinesData)\b", s + "\n" + (report_md or "")):
        add_tok(m)
    # Specific IDOR / BOLA route with resource ID (e.g. /rest/basket/2)
    if route and re.search(r"/[0-9]+$", route):
        add_tok(route)

    # 4. Extract parameter / form field names from exploit.sh
    param_names = []
    for m in re.findall(r'json\.dumps\(\s*\{\s*["\']([A-Za-z0-9_]+)["\']', s):
        if m not in param_names:
            param_names.append(m)
    for m in re.findall(r'name=\\?["\']([A-Za-z0-9_]+)\\?["\']', s):
        if m not in param_names:
            param_names.append(m)

    # 5. Extract verified sink / error tokens from exploit.sh
    sink_tokens = []
    for m in re.findall(r"(File access not allowed|Blocked illegal activity|extractZipBuffer|createWriteStream|ftp/legal\.md)", s):
        if m not in sink_tokens:
            sink_tokens.append(m)

    return {
        "http_method": http_method,
        "route": route,
        "param_names": param_names,
        "tokens": tokens,
        "sink_tokens": sink_tokens,
        "snippet_block": extract_exploit_payload_snippet(exploit_sh),
    }


def extract_forensic_signatures(context, project_id, exploit_info=None):
    """
    Builds multi-layer payload search queries directly from the verified `exploit.sh` script
    (enriched with CWE exploit primitives and issue context):
      - Cloud Logging filters (Layers 0, 1, 2/3)
      - Cloud Logging Log Analytics (BigQuery SQL)
      - Google SecOps (Chronicle) YARA-L 2.0 rule
      - Splunk SPL, Graylog/Elastic KQL, Microsoft Sentinel KQL, and Universal Sigma rule
    """
    exploit_info = exploit_info or {}
    payload = context.get("conceptual_payload", "")
    analysis = context.get("analysis", "")
    cwe = (context.get("cwe") or "CWE-78").upper()
    file_path = context.get("file", "app")
    finding_id = context.get("finding_id", "unknown")

    # 1. Use Verified HTTP Method & Route from exploit.sh first, falling back to issue analysis
    http_method = exploit_info.get("http_method") or "POST"
    route = exploit_info.get("route") or ""
    if not route:
        req_match = re.search(r"\b(GET|POST|PUT|DELETE|PATCH|OPTIONS)\s+(/[^\s\"']*)", payload + "\n" + analysis)
        if req_match:
            if not exploit_info.get("http_method"):
                http_method = req_match.group(1).upper()
            route = req_match.group(2).split("?")[0].strip()
        else:
            path_match = re.search(r"(`[/(][a-zA-Z0-9_/\-:]+`|\b/(?:graphql|rest|api|b2b|ftp|profile|login|search|snippets|track-order|file-upload|dataerasure)[a-zA-Z0-9_/\-]*)", analysis)
            if path_match:
                route = path_match.group(1).strip("`")
    if not route:
        route = "/"

    # Normalize trailing slash and parameterized segments (e.g. /dataerasure/ -> /dataerasure, /rest/basket/2 -> /rest/basket)
    clean_route = route.rstrip("/") if len(route) > 1 else route
    base_route = re.sub(r"/(?:[:{][a-zA-Z0-9_]+\}?|[0-9]+)$", "", clean_route) or clean_route

    # 2. Extract target parameter & concrete exploit tokens from exploit.sh
    param_tokens = list(exploit_info.get("param_names") or [])
    for tok in re.findall(r"`([a-zA-Z_][a-zA-Z0-9_]{2,30})`", context.get("source_desc", "")):
        if tok.lower() not in ("post", "get", "put", "delete", "http", "json", "req", "res", "body", "query", "params", "info", "mutate") and tok not in param_tokens:
            param_tokens.append(tok)

    cwe_profile = CWE_EXPLOIT_PATTERNS.get(cwe, CWE_EXPLOIT_PATTERNS["CWE-78"])
    base_ingress_regex = cwe_profile["ingress_regex"].strip("()")
    base_sink_regex = cwe_profile["sink_regex"].strip("()")
    base_yaral_pattern = cwe_profile["yaral_pattern"].strip("()")

    verified_tokens = list(exploit_info.get("tokens") or [])
    for gql_op in re.findall(r"\b(system_diagnostics|import_paste|importPaste|system_debug|delete_all_pastes|delete_paste|edit_paste|upload_paste|systemHealth|orderLinesData)\b", payload + "\n" + analysis):
        if gql_op not in verified_tokens:
            verified_tokens.append(gql_op)

    if verified_tokens:
        escaped_verified = "|".join(re.escape(t) for t in verified_tokens)
        ingress_regex = f"({escaped_verified}|{base_ingress_regex})"
        yaral_pattern = f"({escaped_verified}|{base_yaral_pattern})"
    else:
        ingress_regex = f"({base_ingress_regex})"
        yaral_pattern = f"({base_yaral_pattern})"

    verified_sink_tokens = list(exploit_info.get("sink_tokens") or [])
    if verified_sink_tokens:
        escaped_sink = "|".join(re.escape(t) for t in verified_sink_tokens)
        sink_regex = f"({escaped_sink}|{base_sink_regex})"
    else:
        sink_regex = f"({base_sink_regex})"

    primary_param = param_tokens[0] if param_tokens else ""
    file_basename = os.path.basename(file_path) if file_path else "views.py"

    # 3. Build Cloud Logging Filters (Layers 0, 1, 2/3)
    q_route = cl_quote(base_route)
    q_ingress = cl_quote(ingress_regex)
    q_sink = cl_quote(sink_regex)
    q_file = cl_quote(file_path)
    q_base = cl_quote(file_basename)
    q_param = cl_quote(primary_param)

    # Layer 0: Baseline endpoint traffic check
    baseline_filter = (
        f'(httpRequest.requestUrl:"{q_route}" OR '
        f'jsonPayload.route:"{q_route}" OR '
        f'jsonPayload.url:"{q_route}" OR '
        f'textPayload:"{q_route}")'
    )

    # Layer 1: Verified Exploit Payload + Generalized CWE Ingress signature
    param_clause = f' AND (jsonPayload.request_body:"{q_param}" OR textPayload:"{q_param}" OR httpRequest.requestUrl:"{q_param}")' if primary_param else ""
    ingress_filter = (
        f'{baseline_filter}{param_clause} AND ('
        f'jsonPayload.request_body =~ "{q_ingress}" OR '
        f'textPayload =~ "{q_ingress}" OR '
        f'httpRequest.requestUrl =~ "{q_ingress}")'
    )

    # Layer 2/3: Application Error & Host/Container Sink Execution
    sink_filter = (
        f'((jsonPayload.file:"{q_file}" OR textPayload:"{q_base}" OR jsonPayload.route:"{q_route}") AND '
        f'(severity>=ERROR OR jsonPayload.sink_command =~ "{q_sink}" OR textPayload =~ "{q_sink}"))'
    )

    # 4. Build Cloud Logging Log Analytics (BigQuery SQL) query
    log_analytics_sql = f"""-- Google Cloud Logging: Log Analytics (BigQuery SQL) Payload Search for Finding {finding_id} ({cwe})
SELECT
  timestamp,
  severity,
  http_request.remote_ip AS attacker_ip,
  http_request.request_method AS method,
  http_request.request_url AS url,
  COALESCE(JSON_VALUE(json_payload, '$.request_body'), text_payload) AS payload_evidence,
  JSON_VALUE(json_payload, '$.sink_command') AS sink_execution
FROM
  `{project_id}.global._Default._AllLogs`
WHERE
  timestamp >= TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL 30 DAY)
  AND (
    REGEXP_CONTAINS( IFNULL(http_request.request_url, ''), r'{re.escape(base_route)}' )
    OR REGEXP_CONTAINS( TO_JSON_STRING(json_payload), r'{re.escape(base_route)}' )
    OR REGEXP_CONTAINS( IFNULL(text_payload, ''), r'{re.escape(file_basename)}' )
  )
  AND (
    REGEXP_CONTAINS( TO_JSON_STRING(json_payload), r'{ingress_regex}' )
    OR REGEXP_CONTAINS( IFNULL(text_payload, ''), r'{sink_regex}' )
    OR REGEXP_CONTAINS( IFNULL(http_request.request_url, ''), r'{ingress_regex}' )
  )
ORDER BY
  timestamp DESC
LIMIT 100;"""

    # 5. Build Google SecOps (Chronicle) YARA-L 2.0 Rule for future SecOps integration
    rule_slug = re.sub(r"[^a-zA-Z0-9_]", "_", f"{finding_id}_{cwe}_{file_basename}").lower()
    param_yaral = f"{re.escape(primary_param)}.*" if primary_param else ""
    yaral_rule = f"""rule codemender_retrohunt_{rule_slug} {{
  meta:
    author = "CodeMender Automated Payload Hunter (gemini-4-argon)"
    finding_id = "{finding_id}"
    cwe = "{cwe} ({cwe_profile['name']})"
    vulnerable_file = "{file_path}"
    target_route = "{http_method} {base_route}"
    verified_exploit_tokens = "{', '.join(verified_tokens[:5])}"
    description = "Detects historical or live exploitation of {cwe} in {file_path} based on verified sandbox exploit.sh payload and sink execution."
    severity = "CRITICAL"

  events:
    (
      // Layer 1: Ingress HTTP / WAF / API Gateway request matching verified exploit.sh primitives
      $e.metadata.event_type = "NETWORK_HTTP" and
      re.regex($e.target.url, `{re.escape(base_route)}`) nocase and
      (
        re.regex($e.target.url, `{param_yaral}{yaral_pattern}`) nocase or
        re.regex($e.additional.fields["request_body"], `{param_yaral}{yaral_pattern}`) nocase
      )
    )
    or
    (
      // Layer 3: Host / Container process execution or sink anomaly
      $e.metadata.event_type = "PROCESS_LAUNCH" and
      re.regex($e.target.process.command_line, `{sink_regex}`) nocase
    )

  outcome:
    $risk_score = 95
    $attacker_ip = array_distinct($e.principal.ip)
    $target_uri = array_distinct($e.target.url)
    $command_line = array_distinct($e.target.process.command_line)

  condition:
    $e
}}"""

    # 6. Build Splunk SPL, Graylog / Elastic Lucene, Datadog / Sentinel KQL, and Universal Sigma Rule
    param_spl = f' "{primary_param}"' if primary_param else ""
    splunk_spl = f"""index IN (web, app, proxy, waf, containers) "{base_route}"{param_spl}
| where match(_raw, "(?i){ingress_regex}") OR match(_raw, "(?i){sink_regex}")
| stats count min(_time) as first_seen max(_time) as last_seen values(status) as http_status by src_ip, uri_path, http_method, user_agent
| sort - count"""

    param_lucene = f' AND "{primary_param}"' if primary_param else ""
    graylog_elastic_kql = (
        f'(http.request.path:"{base_route}" OR url.path:"{base_route}" OR request:"{base_route}"){param_lucene} '
        f'AND (message:/{ingress_regex}/ OR event.original:/{ingress_regex}/ OR error.message:/{sink_regex}/)'
    )

    sentinel_kql = f"""union AppRequests, AppExceptions, ContainerLogV2
| where TimeGenerated >= ago(30d)
| where Url has "{base_route}" or LogMessage has "{base_route}" or LogMessage has "{file_basename}"
| where Properties matches regex @"(?i){ingress_regex}" or LogMessage matches regex @"(?i){sink_regex}"
| project TimeGenerated, ClientIP, HttpMethod, Url, ResultCode, LogMessage
| order by TimeGenerated desc"""

    sigma_rule = f"""title: CodeMender Payload Search - {cwe} ({cwe_profile['name']}) in {file_path}
id: {finding_id}-0000-4000-8000-codemender00
status: experimental
description: Detects historical or active exploitation of {cwe} on {http_method} {base_route} ({file_path}) based on CodeMender verified exploit.sh.
author: CodeMender Payload Log Search
date: {datetime.datetime.now(datetime.timezone.utc).strftime('%Y/%m/%d')}
logsource:
  category: webserver
detection:
  selection_route:
    cs-uri-stem|contains: '{base_route}'
  selection_payload:
    c-uri-query|re: '(?i){ingress_regex}'
  selection_body:
    request_body|re: '(?i){ingress_regex}'
  selection_sink:
    error_message|re: '(?i){sink_regex}'
  condition: selection_route and (selection_payload or selection_body or selection_sink)
level: critical
tags:
  - attack.initial_access
  - cwe.{cwe.lower().replace('cwe-', '')}"""

    formatted_payload_block = exploit_info.get("snippet_block")
    if not formatted_payload_block:
        raw_cp = (payload or "").strip()
        fenced_m = re.search(r"(```[^\n]*\n.*?```)", raw_cp, re.DOTALL)
        if fenced_m:
            formatted_payload_block = fenced_m.group(1).strip()
        else:
            raw_cp_clean = re.sub(r"^`((?:GET|POST|PUT|DELETE|PATCH|OPTIONS|HEAD)\s+/[^\n`]+)`$", r"\1", raw_cp, flags=re.MULTILINE)
            lang_hint = "http" if re.search(r"^(GET|POST|PUT|DELETE|PATCH|OPTIONS|HEAD)\s+/", raw_cp_clean, re.MULTILINE) else ("json" if raw_cp_clean.startswith("{") else "text")
            formatted_payload_block = f"```{lang_hint}\n{raw_cp_clean}\n```"

    return {
        "http_method": http_method,
        "base_route": base_route,
        "full_route": clean_route,
        "primary_param": primary_param,
        "verified_tokens": verified_tokens,
        "verified_sink_tokens": verified_sink_tokens,
        "cwe_name": cwe_profile["name"],
        "ingress_regex": ingress_regex,
        "sink_regex": sink_regex,
        "baseline_filter": baseline_filter,
        "ingress_filter": ingress_filter,
        "sink_filter": sink_filter,
        "log_analytics_sql": log_analytics_sql,
        "yaral_rule": yaral_rule,
        "splunk_spl": splunk_spl,
        "graylog_elastic_kql": graylog_elastic_kql,
        "sentinel_kql": sentinel_kql,
        "sigma_rule": sigma_rule,
        "formatted_payload_block": formatted_payload_block,
    }


# ==============================================================================
# Forensic Provider 1: Google Cloud Logging (Active Default)
# ==============================================================================
class CloudLoggingForensicProvider:
    """Executes multi-layer forensic lookbacks natively against Google Cloud Logging REST API."""

    def __init__(self, project_id, token):
        self.project_id = project_id
        self.token = token

    def seed_demo_telemetry(self, context, sigs):
        """
        Writes realistic baseline HTTP logs + 2 simulated exploit log entries matching
        the verified `exploit.sh` payload vector into Google Cloud Logging (`entries:write`)
        for live customer demonstrations.
        """
        if not self.token:
            return False

        now = datetime.datetime.now(datetime.timezone.utc)
        log_name = f"projects/{self.project_id}/logs/codemender-app-telemetry"
        route = sigs["base_route"]
        full_route = sigs.get("full_route") or route
        method = sigs["http_method"]
        finding_id = context["finding_id"]
        file_path = context["file"]
        primary_param = sigs.get("primary_param", "")
        verified_tokens = sigs.get("verified_tokens") or []
        verified_sink_tokens = sigs.get("verified_sink_tokens") or []

        if verified_tokens:
            joined_toks = ", ".join(verified_tokens[:3])
            if primary_param:
                exploit_body = json.dumps({primary_param: verified_tokens[0], "verified_payload_tokens": joined_toks})
            else:
                exploit_body = f"{method} {full_route} (payload: {joined_toks})"
        else:
            conceptual_payload = context.get("conceptual_payload", "").strip()
            payload_lines = [l for l in conceptual_payload.splitlines() if not l.startswith(("GET ", "POST ", "PUT ", "DELETE ", "Content-Type:", "Host:"))]
            exploit_body = " ".join(l.strip() for l in payload_lines if l.strip())
            if not exploit_body:
                exploit_body = f'{{"query": "mutation {{ system_diagnostics(target: \\"127.0.0.1; id\\") {{ result }} }}"}}'

        if verified_sink_tokens:
            sink_trace = f"Runtime sink/error in {file_path}: {verified_sink_tokens[0]} (payload: {verified_tokens[0] if verified_tokens else full_route})"
        elif verified_tokens:
            sink_trace = f"Runtime sink/exception in {file_path} triggered by {verified_tokens[0]} on {method} {full_route}"
        else:
            sink_trace = f"/bin/sh -c ping -c 1 127.0.0.1; id -> uid=0(root) gid=0(root) in {file_path}"

        entries = []
        # 1. Seed 6 benign baseline requests
        benign_ips = ["10.128.0.14", "10.128.0.22", "35.191.12.88"]
        for i in range(6):
            ts = (now - datetime.timedelta(minutes=45 - i * 5)).strftime("%Y-%m-%dT%H:%M:%SZ")
            entries.append({
                "logName": log_name,
                "timestamp": ts,
                "severity": "INFO",
                "resource": {"type": "cloud_run_revision", "labels": {"project_id": self.project_id, "service_name": "demo-app-production"}},
                "httpRequest": {
                    "requestMethod": method,
                    "requestUrl": f"https://app.demo.internal{route}",
                    "status": 200,
                    "remoteIp": benign_ips[i % len(benign_ips)],
                    "userAgent": "Mozilla/5.0 (X11; Linux x86_64) Chrome/130.0.0.0",
                },
                "jsonPayload": {
                    "event": "http_request",
                    "route": route,
                    "finding_ref": finding_id,
                    "request_body": f'{{"status": "benign-request-{i}"}}',
                },
            })

        # 2. Seed 1 attacker request matching verified exploit.sh payload (Layer 1 Ingress match)
        probe_ts = (now - datetime.timedelta(minutes=12)).strftime("%Y-%m-%dT%H:%M:%SZ")
        entries.append({
            "logName": log_name,
            "timestamp": probe_ts,
            "severity": "WARNING",
            "resource": {"type": "cloud_run_revision", "labels": {"project_id": self.project_id, "service_name": "demo-app-production"}},
            "httpRequest": {
                "requestMethod": method,
                "requestUrl": f"https://app.demo.internal{full_route}",
                "status": 200,
                "remoteIp": "198.51.100.77",
                "userAgent": "python-urllib/3.11 (CodeMender-Verify-PoC)",
            },
            "jsonPayload": {
                "event": "http_request",
                "route": full_route,
                "finding_ref": finding_id,
                "remote_ip": "198.51.100.77",
                "request_body": exploit_body,
            },
        })

        # 3. Seed 1 runtime sink / application error trace (Layer 2/3 Sink Execution match)
        sink_ts = (now - datetime.timedelta(minutes=11, seconds=58)).strftime("%Y-%m-%dT%H:%M:%SZ")
        entries.append({
            "logName": log_name,
            "timestamp": sink_ts,
            "severity": "ERROR",
            "resource": {"type": "cloud_run_revision", "labels": {"project_id": self.project_id, "service_name": "demo-app-production"}},
            "httpRequest": {
                "requestMethod": method,
                "requestUrl": f"https://app.demo.internal{full_route}",
                "status": 500,
                "remoteIp": "198.51.100.77",
                "userAgent": "python-urllib/3.11 (CodeMender-Verify-PoC)",
            },
            "jsonPayload": {
                "event": "sink_execution_alert",
                "file": file_path,
                "route": full_route,
                "finding_ref": finding_id,
                "remote_ip": "198.51.100.77",
                "sink_command": sink_trace,
            },
        })

        url = "https://logging.googleapis.com/v2/entries:write"
        req = urllib.request.Request(
            url,
            data=json.dumps({"entries": entries}).encode("utf-8"),
            headers={
                "Authorization": f"Bearer {self.token}",
                "Content-Type": "application/json",
            },
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=15) as resp:
                if resp.status == 200:
                    print(f"✅ Seeded {len(entries)} demo telemetry entries into Google Cloud Logging ({log_name}).")
                    time.sleep(6)  # Allow Cloud Logging indexing propagation
                    return True
        except Exception as e:
            print(f"⚠️ Notice seeding demo logs: {e}", file=sys.stderr)
        return False

    def query_entries(self, filter_expr, start_time_iso, end_time_iso, max_results=50):
        """Queries Google Cloud Logging `entries:list` with the given filter and time bounds."""
        if not self.token:
            return []

        full_filter = f'timestamp >= "{start_time_iso}" AND timestamp <= "{end_time_iso}" AND ({filter_expr})'
        payload = {
            "resourceNames": [f"projects/{self.project_id}"],
            "filter": full_filter,
            "orderBy": "timestamp desc",
            "pageSize": max_results,
        }
        req = urllib.request.Request(
            "https://logging.googleapis.com/v2/entries:list",
            data=json.dumps(payload).encode("utf-8"),
            headers={
                "Authorization": f"Bearer {self.token}",
                "Content-Type": "application/json",
            },
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=20) as resp:
                data = json.loads(resp.read().decode("utf-8"))
                return data.get("entries", [])
        except urllib.error.HTTPError as e:
            err_body = e.read().decode("utf-8", errors="ignore")
            print(f"⚠️ Cloud Logging query HTTP {e.code}: {err_body[:400]}", file=sys.stderr)
            return []
        except Exception as e:
            print(f"⚠️ Cloud Logging query error: {e}", file=sys.stderr)
            return []


# ==============================================================================
# Forensic Provider 2: Google SecOps / Chronicle (Pre-Wired for Future Expansion)
# ==============================================================================
class SecOpsChronicleForensicProvider:
    """
    Pre-wired adapter for Google SecOps (Chronicle) REST API (`chronicle.googleapis.com`).
    Activate by setting `FORENSIC_PROVIDER=secops`, `SECOPS_PROJECT_ID`, `SECOPS_REGION`,
    and `SECOPS_INSTANCE_ID` once a Chronicle instance is provisioned.
    """

    def __init__(self, project_id, region, instance_id, token):
        self.project_id = project_id
        self.region = region or "us"
        self.instance_id = instance_id
        self.token = token
        self.base_url = (
            f"https://{self.region}-chronicle.googleapis.com/v1alpha/"
            f"projects/{self.project_id}/locations/{self.region}/instances/{self.instance_id}"
        )

    def udm_search(self, udm_query, start_time_iso, end_time_iso, limit=50):
        params = urllib.parse.urlencode({
            "query": udm_query,
            "timeRange.startTime": start_time_iso,
            "timeRange.endTime": end_time_iso,
            "limit": limit,
        })
        url = f"{self.base_url}/legacy:legacySearchUdm?{params}"
        req = urllib.request.Request(
            url,
            headers={"Authorization": f"Bearer {self.token}"},
            method="GET",
        )
        with urllib.request.urlopen(req, timeout=30) as resp:
            return json.loads(resp.read().decode("utf-8")).get("events", [])


def format_log_entry_summary(entry):
    """Extracts human-readable forensic fields from a Cloud Logging LogEntry."""
    ts = entry.get("timestamp", "")[:19].replace("T", " ") + " UTC"
    sev = entry.get("severity", "INFO")
    http_req = entry.get("httpRequest", {})
    json_p = entry.get("jsonPayload", {})
    text_p = entry.get("textPayload", "")

    remote_ip = (
        http_req.get("remoteIp")
        or json_p.get("remote_ip")
        or json_p.get("ip")
        or "internal"
    )
    method = http_req.get("requestMethod") or json_p.get("method") or "POST"
    url = http_req.get("requestUrl") or json_p.get("route") or json_p.get("url") or "—"
    evidence = (
        json_p.get("request_body")
        or json_p.get("sink_command")
        or text_p
        or json.dumps(json_p)
    )
    evidence_clean = str(evidence).replace("\n", " ").replace("|", "\\|").strip()
    if len(evidence_clean) > 140:
        evidence_clean = evidence_clean[:137] + "..."

    return {
        "timestamp": ts,
        "severity": sev,
        "remote_ip": remote_ip,
        "target": f"{method} {url}",
        "evidence": evidence_clean,
        "log_name": os.path.basename(entry.get("logName", "app-logs")),
    }


def build_logs_explorer_url(project_id, filter_expr, start_time_iso, end_time_iso):
    escaped_filter = urllib.parse.quote(filter_expr, safe="")
    return (
        f"https://console.cloud.google.com/logs/query;"
        f"query={escaped_filter};"
        f"timeRange={start_time_iso}%2F{end_time_iso}"
        f"?project={project_id}"
    )


def apply_forensic_labels(repo, issue_number):
    env = os.environ.copy()
    if os.environ.get("GITHUB_TOKEN") and not env.get("GH_TOKEN"):
        env["GH_TOKEN"] = os.environ["GITHUB_TOKEN"]

    subprocess.run(
        [
            "gh", "label", "create", "codemender:hunted",
            "--repo", repo,
            "--color", "1d76db",
            "--description", "Payload log search executed by CodeMender",
            "--force",
        ],
        capture_output=True,
        env=env,
    )

    # Remove any legacy presumptive verdict labels if present
    for old_lbl in ("forensics:exploit-detected", "forensics:clean-lookback", "forensics:telemetry-gap"):
        subprocess.run(
            ["gh", "issue", "edit", str(issue_number), "--repo", repo, "--remove-label", old_lbl],
            capture_output=True,
            env=env,
        )

    subprocess.run(
        ["gh", "issue", "edit", str(issue_number), "--repo", repo, "--add-label", "codemender:hunted"],
        capture_output=True,
        env=env,
    )


def main():
    repo = os.environ.get("REPO", "").strip()
    vuln_id = os.environ.get("VULN_ID", "").strip()
    issue_number = os.environ.get("ISSUE_NUMBER", "").strip()
    project_id = os.environ.get("GCP_PROJECT_ID") or os.environ.get("CLOUDSDK_CORE_PROJECT") or "cm-gh-506516"
    workspace_dir = os.environ.get("WORKSPACE_DIR", "/workspace/repo")
    artifacts_dir = os.environ.get("ARTIFACTS_DIR", "/workspace/artifacts")
    override_days = os.environ.get("LOOKBACK_DAYS", "").strip() or None
    seed_demo = os.environ.get("SEED_DEMO_LOGS", "false").lower() in ("true", "1", "yes")

    for arg in sys.argv[1:]:
        if arg == "--seed-demo":
            seed_demo = True
        elif arg.startswith("--days="):
            override_days = arg.split("=", 1)[1]

    os.makedirs(artifacts_dir, exist_ok=True)

    print(f"🕵️‍♂️ Initializing CodeMender Payload Log Hunter for {repo} (Issue #{issue_number or 'auto'}, Finding: {vuln_id})...")
    context = fetch_issue_context(repo, issue_number=issue_number, vuln_id=vuln_id)
    issue_number = context["issue_number"]
    finding_id = context["finding_id"]

    # 0. Require Verification (`exploit.sh`) First
    exploit_data = fetch_verified_exploit(repo, issue_number, finding_id, workspace_dir=workspace_dir, artifacts_dir=artifacts_dir)
    if not exploit_data["found"]:
        print(f"⚠️ Issue #{issue_number} ({finding_id}) has no verified exploit.sh artifact yet. Requiring /cm verify first.")
        if repo and issue_number:
            env = os.environ.copy()
            if os.environ.get("GITHUB_TOKEN") and not env.get("GH_TOKEN"):
                env["GH_TOKEN"] = os.environ["GITHUB_TOKEN"]
            prereq_body = (
                "### Codemender Payload log search\n\n"
                "⚠️ **Verification Required First (`/cm verify`)**\n\n"
                "`/cm hunt` builds its payload log search queries from the verified sandbox exploit script (`exploit.sh`) generated during verification.\n\n"
                "👉 **Next Step:** Comment `/cm verify` on this issue first. Once CodeMender verifies the exploit in the sandbox and generates `exploit.sh`, re-run `/cm hunt` (or `/cm hunt --seed-demo`)."
            )
            subprocess.run(
                ["gh", "issue", "comment", str(issue_number), "--repo", repo, "--body", prereq_body],
                capture_output=True,
                text=True,
                env=env,
            )
        return

    print(f"✅ Loaded verified sandbox exploit script from {exploit_data['artifact_path']}")
    with open(os.path.join(artifacts_dir, "verified-exploit.sh"), "w", encoding="utf-8") as f:
        f.write(exploit_data["exploit_sh"])
    exploit_info = parse_exploit_sh(exploit_data["exploit_sh"], exploit_data.get("report_md", ""))

    # 1. Calculate Exposure Window via git blame / git log -L
    exposure = calculate_git_exposure_window(
        workspace_dir,
        context["file"],
        start_line=context.get("start_line"),
        end_line=context.get("end_line"),
        override_days=override_days,
    )
    print(
        f"📅 Vulnerability Exposure Window: introduced in commit {exposure['commit_short']} "
        f"({exposure['commit_date_iso']}), searching {exposure['lookback_days']} days."
    )

    # 2. Extract Multi-Layer Forensic Queries + YARA-L Rule based on verified exploit.sh
    sigs = extract_forensic_signatures(context, project_id, exploit_info=exploit_info)

    # 3. Execute Cloud Logging Forensic Lookback
    token = get_gcloud_token()
    provider = CloudLoggingForensicProvider(project_id=project_id, token=token)

    if seed_demo:
        print("🧪 Seeding realistic baseline + verified exploit telemetry into Google Cloud Logging (--seed-demo)...")
        provider.seed_demo_telemetry(context, sigs)
        # Refresh end_time_iso to include newly seeded entries
        exposure["end_time_iso"] = (datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(minutes=1)).strftime("%Y-%m-%dT%H:%M:%SZ")

    print("🔎 Running Layer 0 (Baseline Endpoint Telemetry) query against Cloud Logging...")
    baseline_entries = provider.query_entries(sigs["baseline_filter"], exposure["start_time_iso"], exposure["end_time_iso"], max_results=100)

    print("🔎 Running Layer 1 (Verified Exploit Payload & Ingress Primitives) query...")
    ingress_entries = provider.query_entries(sigs["ingress_filter"], exposure["start_time_iso"], exposure["end_time_iso"], max_results=50)

    print("🔎 Running Layer 2/3 (Application Error & Sink Execution) query...")
    sink_entries = provider.query_entries(sigs["sink_filter"], exposure["start_time_iso"], exposure["end_time_iso"], max_results=50)

    total_exploit_matches = len(ingress_entries) + len(sink_entries)

    explorer_ingress_url = build_logs_explorer_url(project_id, sigs["ingress_filter"], exposure["start_time_iso"], exposure["end_time_iso"])
    explorer_sink_url = build_logs_explorer_url(project_id, sigs["sink_filter"], exposure["start_time_iso"], exposure["end_time_iso"])

    # 4. Format Matched Log Entries Table (if any matches found)
    evidence_section = ""
    if total_exploit_matches > 0:
        seen_keys = set()
        rows = []
        for e in ingress_entries + sink_entries:
            s = format_log_entry_summary(e)
            k = (s["timestamp"], s["evidence"])
            if k in seen_keys:
                continue
            seen_keys.add(k)
            rows.append(
                f"| `{s['timestamp']}` | `{s['severity']}` | `{s['remote_ip']}` | `{s['target']}` | `{s['evidence']}` |"
            )
            if len(rows) >= 10:
                break

        evidence_section = (
            "\n#### 📋 Matching Log Entries (Google Cloud Logging)\n\n"
            "| Timestamp | Severity | Source IP | Route / Target | Log Summary |\n"
            "| :--- | :--- | :--- | :--- | :--- |\n"
            + "\n".join(rows)
            + "\n"
        )

    param_display = f"`{sigs['primary_param']}`" if sigs["primary_param"] else "request parameters/body"
    body_logging_note = (
        f"⚠️ *Telemetry Tip:* Standard load balancers often omit HTTP `{sigs['http_method']}` request bodies by default. "
        f"If your edge logs only capture URI paths, check **Layer 2 (Application Error/Audit Logs)** and **Layer 3 (Host/Container Runtime)** below."
        if sigs["http_method"] in ("POST", "PUT", "PATCH")
        else f"💡 *Telemetry Tip:* Because this vector uses `{sigs['http_method']}`, URL query strings are typically logged directly in standard access logs."
    )

    # 5. Save Incident Response Guide & Query Artifacts to ARTIFACTS_DIR (before attach_artifacts.py runs)
    ir_guide_md = f"""# 🧭 Incident Response & Log Hunting Guide — Finding `{finding_id}` (`{context['cwe']}`)

Even if production logs are stored in an external SIEM or log manager (**Splunk, Graylog, Elastic/ELK, Datadog, Microsoft Sentinel, or Google SecOps**), incident responders can search across three telemetry layers from **`{exposure['commit_date_iso'][:10]}`** to present:

1. **🌐 Layer 1 — Edge / WAF / Load Balancer / API Gateway Logs** *(Cloud Armor, Cloudflare, AWS ALB/WAF, Nginx, Envoy)*:
   - **Route Filter:** Look for `{sigs['http_method']}` requests to `{sigs['base_route']}` containing {param_display} combined with verified `exploit.sh` tokens and `{context['cwe']}` payload patterns (`{sigs['ingress_regex']}`).
   - **Probing Activity:** Look for a single source IP generating repeated `400`/`500` status codes or abnormal response latency on `{sigs['base_route']}`.
   - {body_logging_note}
2. **⚙️ Layer 2 — Application & Database Logs** *(Cloud Logging, Datadog APM, Graylog, Splunk, `stdout`/`stderr`)*:
   - **File & Handler Trace:** Search application error logs and stack traces referencing `{context['file']}` (`{os.path.basename(context['file'])}`).
   - **Sink Exceptions:** Search for runtime error signatures matching `{sigs['sink_regex']}`.
3. **🖥️ Layer 3 — Host / Container / EDR Runtime Telemetry** *(Google SecOps EDR, CrowdStrike, Wiz Defend, Falco, GKE Audit)*:
   - **Process & Sink Behavior:** Inspect container/host telemetry for the application runtime spawning unexpected child commands, file reads, or outbound network connections associated with `{context.get('sink_desc') or context['file']}`.
"""
    with open(os.path.join(artifacts_dir, "incident-response-guide.md"), "w", encoding="utf-8") as f:
        f.write(ir_guide_md)

    with open(os.path.join(artifacts_dir, "secops-retrohunt.yaral"), "w", encoding="utf-8") as f:
        f.write(sigs["yaral_rule"] + "\n")

    with open(os.path.join(artifacts_dir, "sigma-rule.yml"), "w", encoding="utf-8") as f:
        f.write(sigs["sigma_rule"] + "\n")

    with open(os.path.join(artifacts_dir, "cloud-logging-queries.sql"), "w", encoding="utf-8") as f:
        f.write(
            f"# Layer 0 Baseline Filter:\n{sigs['baseline_filter']}\n\n"
            f"# Layer 1 Ingress Exploit Filter:\n{sigs['ingress_filter']}\n\n"
            f"# Layer 2/3 Sink & Error Filter:\n{sigs['sink_filter']}\n\n"
            f"{sigs['log_analytics_sql']}\n\n"
            f"# Splunk SPL:\n{sigs['splunk_spl']}\n\n"
            f"# Graylog / Elastic KQL:\n{sigs['graylog_elastic_kql']}\n"
        )

    with open(os.path.join(artifacts_dir, "hunt-results.json"), "w", encoding="utf-8") as f:
        json.dump(
            {
                "finding_id": finding_id,
                "issue_number": issue_number,
                "verified_exploit_path": exploit_data["artifact_path"],
                "exposure_window": exposure,
                "signatures": sigs,
                "counts": {
                    "baseline_entries": len(baseline_entries),
                    "ingress_exploit_matches": len(ingress_entries),
                    "sink_error_matches": len(sink_entries),
                },
            },
            f,
            indent=2,
        )

    # Publish artifacts and get the single-hyperlink markdown block
    hunt_subdir = f"hunt/issue-{issue_number}-{finding_id}"
    attached_md = ""
    attach_script = os.path.join(os.path.dirname(__file__), "attach_artifacts.py")
    if not os.path.exists(attach_script) and os.path.exists("/attach_artifacts.py"):
        attach_script = "/attach_artifacts.py"
    if os.path.exists(attach_script) and repo:
        res = subprocess.run(
            ["python3", attach_script, repo, hunt_subdir, workspace_dir, artifacts_dir],
            capture_output=True,
            text=True,
        )
        if res.returncode == 0 and res.stdout.strip():
            attached_md = f"\n---\n\n{res.stdout.strip()}\n"

    ir_guide_url = (
        f"https://github.com/{repo}/blob/codemender/artifacts/{hunt_subdir}/incident-response-guide.md"
        if repo
        else "docs/FORENSIC_HUNT_AND_SECOPS_GUIDE.md"
    )

    verified_tokens_summary = (
        ", ".join(f"`{t}`" for t in sigs["verified_tokens"][:4])
        if sigs.get("verified_tokens")
        else f"generalized `{context['cwe']}` primitives"
    )

    # 6. Build GitHub Issue Comment
    comment_body = f"""### Codemender Payload log search

| Attribute | Details |
| :--- | :--- |
| **Finding ID** | `{finding_id}` (`{context['cwe']}: {sigs['cwe_name']}`) |
| **Verified Exploit Source** | [`{exploit_data['artifact_path']}`]({exploit_data['exploit_url']}) |
| **Telemetry Backend** | **Google Cloud Logging** (`projects/{project_id}`) |
| **Vulnerable Code Introduced** | Commit `{exposure['commit_short']}` on `{exposure['commit_date_iso']}` (*{exposure['age_days']} day(s) ago*) |
| **Lookback Window Searched** | `{exposure['start_time_iso']}` &rarr; `{exposure['end_time_iso']}` (`{exposure['lookback_days']} days`) |
| **Target Endpoint / File** | `{sigs['http_method']} {sigs['base_route']}` &bull; `{context['file']}` |

#### 🎯 Verified Exploit Payload (`exploit.sh`)
{sigs['formatted_payload_block']}

---

#### 📊 Log Search Summary

| Search Layer | Description | Matching Entries | Cloud Logs Explorer |
| :--- | :--- | :--- | :--- |
| **Layer 0: Baseline Traffic** | All requests hitting `{sigs['base_route']}` | **`{len(baseline_entries)}`** | [🔎 View Baseline]({build_logs_explorer_url(project_id, sigs['baseline_filter'], exposure['start_time_iso'], exposure['end_time_iso'])}) |
| **Layer 1: Ingress Payload Patterns** | Verified `exploit.sh` tokens ({verified_tokens_summary}) + `{context['cwe']}` patterns on `{sigs['base_route']}` | **`{len(ingress_entries)}`** | [🔎 Open Ingress Search]({explorer_ingress_url}) |
| **Layer 2/3: Runtime Sink & Errors** | Exceptions, 500 errors, or sink execution in `{os.path.basename(context['file'])}` | **`{len(sink_entries)}`** | [🔎 Open Sink Search]({explorer_sink_url}) |
{evidence_section}
---

🧭 **[View Incident Response & Log Hunting Guide (`incident-response-guide.md`)]({ir_guide_url})**

<details>
<summary><b>📜 View Ready-to-Run Queries (Cloud Logging, BigQuery SQL, SecOps YARA-L, Splunk SPL, Graylog/Elastic, Sentinel KQL & Sigma)</b></summary>

#### 1. Google Cloud Logging Filter (Layer 1 — Ingress Exploit Signature)
```text
{sigs['ingress_filter']}
```

#### 2. Google Cloud Logging Filter (Layer 2/3 — Sink & Error Signature)
```text
{sigs['sink_filter']}
```

#### 3. Cloud Logging Log Analytics (BigQuery SQL)
```sql
{sigs['log_analytics_sql']}
```

#### 4. Google SecOps (Chronicle) YARA-L 2.0 Retrohunt & Canary Detection Rule
```yara
{sigs['yaral_rule']}
```

#### 5. Splunk Search Processing Language (SPL)
```spl
{sigs['splunk_spl']}
```

#### 6. Graylog / Elastic Security (Lucene / KQL)
```text
{sigs['graylog_elastic_kql']}
```

#### 7. Microsoft Sentinel / Azure Log Analytics / Datadog (KQL)
```kusto
{sigs['sentinel_kql']}
```

#### 8. Universal Sigma Detection Rule (`sigma-rule.yml`)
```yaml
{sigs['sigma_rule']}
```

</details>
{attached_md}
---
*Payload log search executed by CodeMender via Google Cloud Run & Cloud Logging. Tip: comment `/cm hunt --seed-demo` to inject & test live demo telemetry.*"""

    with open(os.path.join(artifacts_dir, "hunt-report.md"), "w", encoding="utf-8") as f:
        f.write(comment_body + "\n")

    if repo and issue_number:
        env = os.environ.copy()
        if os.environ.get("GITHUB_TOKEN") and not env.get("GH_TOKEN"):
            env["GH_TOKEN"] = os.environ["GITHUB_TOKEN"]
        subprocess.run(
            ["gh", "issue", "comment", str(issue_number), "--repo", repo, "--body", comment_body],
            capture_output=True,
            text=True,
            env=env,
        )
        apply_forensic_labels(repo, issue_number)
        print(f"✅ Posted Payload Log Search Report to Issue #{issue_number} on {repo}.")


if __name__ == "__main__":
    main()
