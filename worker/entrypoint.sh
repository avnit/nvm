#!/usr/bin/env bash
set -euo pipefail

# ==============================================================================
# CodeMender (cm) Cloud Run Worker Entrypoint
# ==============================================================================

export DOTNET_ROOT="${DOTNET_ROOT:-/usr/share/dotnet}"
export JAVA_HOME="${JAVA_HOME:-/usr/lib/jvm/java-17-openjdk-amd64}"
export PATH="/usr/share/dotnet:/usr/local/go/bin:/usr/local/bin:${PATH}"
ARTIFACTS_DIR="/workspace/artifacts"
mkdir -p "${ARTIFACTS_DIR}"

echo "================================================================="
echo "🛡️  CodeMender (cm) Security Worker Initializing"
echo "📅 Timestamp: $(date -u +"%Y-%m-%dT%H:%M:%SZ")"
echo "🏢 Project:   ${GCP_PROJECT_ID:-unknown}"
echo "📦 Repo:      ${REPO:-local}"
echo "🔀 Ref / SHA: ${REF:-${HEAD_SHA:-main}}"
echo "================================================================="

# Configure CodeMender Target / Allowlisted Project
if [ -n "${CODEMENDER_PROJECT_ID:-}" ]; then
  echo "🎯 CodeMender Target Project: ${CODEMENDER_PROJECT_ID}"
  export CLOUDSDK_CORE_PROJECT="${CODEMENDER_PROJECT_ID}"
  export GOOGLE_CLOUD_PROJECT="${CODEMENDER_PROJECT_ID}"
  export VERTEX_AI_PROJECT="${CODEMENDER_PROJECT_ID}"
fi

# Configure CodeMender Per-Operation Models:
# - SCAN_MODEL (cm find --deep / --diff): defaults to gemini-4-argon
# - REMEDIATION_MODEL (cm verify / cm fix): defaults to gemini-4-argon
EXPLICIT_MODEL="${CM_EXPLICIT_MODEL:-${VERTEX_AI_MODEL:-${MODEL:-}}}"
export CM_EXPLICIT_MODEL="${EXPLICIT_MODEL}"
SCAN_MODEL="${SCAN_MODEL:-${EXPLICIT_MODEL:-gemini-4-argon}}"
REMEDIATION_MODEL="${REMEDIATION_MODEL:-${EXPLICIT_MODEL:-gemini-4-argon}}"
export SCAN_MODEL
export REMEDIATION_MODEL
echo "🧠 CodeMender Scan Model (find --deep/--diff): ${SCAN_MODEL}"
echo "🧠 CodeMender Remediation Model (verify/fix):  ${REMEDIATION_MODEL}"

# 1. Update cm binary to ensure latest upstream release
echo "🔄 Checking for CodeMender binary updates (cm update)..."
cm update || echo "⚠️ cm update check completed (using pre-baked version)."

echo "🚀 Active CodeMender version: $(cm --version 2>/dev/null || echo 'cm CLI ready')"

# If custom CLI arguments were passed directly to container, execute them
if [ "$#" -gt 0 ] && [ "$1" != "default" ]; then
  echo "Executing direct command: $*"
  exec "$@"
fi

# ==============================================================================
# 2. Automated Fleet / GitHub Action Invocation Handling
# ==============================================================================
COMMAND="${CM_ACTION:-${COMMAND:-all}}"
REPO="${REPO:-}"
REF="${REF:-${HEAD_SHA:-main}}"
HEAD_BRANCH="${HEAD_BRANCH:-}"
BASE_REF="${BASE_REF:-main}"
PR_NUMBER="${PR_NUMBER:-}"
VULN_ID="${VULN_ID:-}"
AUTO_PR="${AUTO_PR:-true}"
ARTIFACTS_BUCKET="${ARTIFACTS_BUCKET:-}"

if [ -z "${REPO}" ]; then
  echo "No REPO specified. Running interactive or container default shell."
  exec bash
fi

# Configure Git with Secret Manager Token (prefer per-owner vaulted PAT if available)
if [ -n "${GITHUB_TOKEN:-}" ]; then
  export GH_TOKEN="${GITHUB_TOKEN}"
  # Auto-accept any pending repository collaborator invitations on the primary service bot account first
  for inv_id in $(gh api /user/repository_invitations --jq '.[].id' 2>/dev/null || true); do
    echo "🤝 Auto-accepting repository collaborator invitation ID ${inv_id}..."
    gh api -X PATCH "/user/repository_invitations/${inv_id}" >/dev/null 2>&1 || true
  done
fi

REPO_OWNER=$(dirname "${REPO}")
if [ -n "${REPO_OWNER}" ] && [ "${REPO_OWNER}" != "." ] && [ "${REPO_OWNER}" != "cloud-gtm" ] && [ "${REPO_OWNER}" != "collinfr" ]; then
  OWNER_PAT=$(gcloud secrets versions access latest --secret="codemender-github-token-${REPO_OWNER}" --project="${GCP_PROJECT_ID:-cm-gh-506516}" 2>/dev/null || echo "")
  if [ -n "${OWNER_PAT}" ]; then
    BOT_CAN_PUSH="false"
    if [ -n "${GITHUB_TOKEN:-}" ]; then
      BOT_CAN_PUSH=$(GH_TOKEN="${GITHUB_TOKEN}" gh api "repos/${REPO}" --jq '.permissions.push // false' 2>/dev/null || echo "false")
    fi
    if [[ "${OWNER_PAT}" == github_pat_* ]] && [ "${BOT_CAN_PUSH}" = "true" ]; then
      echo "🔑 Owner token is fine-grained (github_pat_*); using full-scope collaborator token on '${REPO}' to ensure git push and PR creation succeed."
    elif GH_TOKEN="${OWNER_PAT}" gh api user >/dev/null 2>&1; then
      echo "🔑 Using valid vaulted personal GitHub PAT for repository owner '${REPO_OWNER}'."
      export GITHUB_TOKEN="${OWNER_PAT}"
      export GH_TOKEN="${OWNER_PAT}"
    else
      echo "⚠️ Vaulted personal GitHub PAT for '${REPO_OWNER}' has expired; falling back to collaborator service account token."
    fi
  fi
fi

if [ -n "${GITHUB_TOKEN:-}" ]; then
  export GH_TOKEN="${GITHUB_TOKEN}"
  git config --global url."https://x-access-token:${GITHUB_TOKEN}@github.com/".insteadOf "https://github.com/"
  git config --global user.name "${GIT_USER_NAME:-${GIT_AUTHOR_NAME:-CollinF}}"
  git config --global user.email "${GIT_USER_EMAIL:-${GIT_AUTHOR_EMAIL:-collinf@google.com}}"
  export GIT_AUTHOR_NAME="${GIT_USER_NAME:-${GIT_AUTHOR_NAME:-CollinF}}"
  export GIT_AUTHOR_EMAIL="${GIT_USER_EMAIL:-${GIT_AUTHOR_EMAIL:-collinf@google.com}}"
  export GIT_COMMITTER_NAME="${GIT_USER_NAME:-${GIT_AUTHOR_NAME:-CollinF}}"
  export GIT_COMMITTER_EMAIL="${GIT_USER_EMAIL:-${GIT_AUTHOR_EMAIL:-collinf@google.com}}"
fi

# Clone repository into /workspace/repo
echo "📥 Cloning repository: https://github.com/${REPO} (ref: ${REF})..."
mkdir -p /workspace/repo
cd /workspace/repo
WORKSPACE_DIR="$(pwd)"

if [ ! -d ".git" ]; then
  git clone --single-branch --branch "${REF}" "https://github.com/${REPO}.git" . 2>/dev/null || git clone "https://github.com/${REPO}.git" .
fi
git fetch origin "${REF}" 2>/dev/null || git fetch origin 2>/dev/null || true
git checkout "${REF}" 2>/dev/null || git checkout -b "scan-${REF}" "origin/${REF}" 2>/dev/null || git checkout -b "scan-${REF}" "${REF}" 2>/dev/null || true

echo "📂 Workspace prepared at: $(pwd)"

# If running outer container entrypoint, dynamically delegate to repo's own worker entrypoint if present
if [ -z "${CM_RUN_INNER:-}" ] && [ -f "/workspace/repo/worker/entrypoint.sh" ] && [ "${BASH_SOURCE[0]}" != "/workspace/repo/worker/entrypoint.sh" ]; then
  echo "🚀 Delegating execution to checked-out repository entrypoint: worker/entrypoint.sh..."
  export CM_RUN_INNER=1
  exec bash /workspace/repo/worker/entrypoint.sh "$@"
fi

# Emit structured usage & impact telemetry event to Google Cloud Logging (projects/cm-gh-506516/logs/codemender-usage-metrics)
python3 - << 'PYEOF' 2>/dev/null || true
import datetime, json, os, subprocess, urllib.request
token = subprocess.check_output(["gcloud", "auth", "print-access-token"], text=True, timeout=5).strip()
now_iso = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
repo = os.environ.get("REPO", "")
event = {
    "event_type": "worker_execution",
    "timestamp": now_iso,
    "actor": os.environ.get("ACTOR", "automated"),
    "repo": repo,
    "repo_owner": repo.split("/")[0] if "/" in repo else "",
    "command": os.environ.get("CM_ACTION") or os.environ.get("COMMAND") or "all",
    "scan_mode": os.environ.get("SCAN_MODE", ""),
    "trigger": os.environ.get("TRIGGER", "workflow"),
    "vuln_id": os.environ.get("VULN_ID", ""),
    "issue_number": os.environ.get("ISSUE_NUMBER", ""),
    "pr_number": os.environ.get("PR_NUMBER", ""),
}
payload = {
    "entries": [{
        "logName": "projects/cm-gh-506516/logs/codemender-usage-metrics",
        "timestamp": now_iso,
        "severity": "INFO",
        "resource": {"type": "global", "labels": {"project_id": "cm-gh-506516"}},
        "jsonPayload": event,
    }]
}
req = urllib.request.Request(
    "https://logging.googleapis.com/v2/entries:write",
    data=json.dumps(payload).encode("utf-8"),
    headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
    method="POST",
)
urllib.request.urlopen(req, timeout=8)
PYEOF

# Initialize CodeMender workspace configuration (clean, stateless run)
echo "🔧 Initializing CodeMender workspace (cm init)..."
mkdir -p /root/.codemender
cm init -y || cm init || true

# ==============================================================================
# 3. Execute Requested CodeMender Workflow
# ==============================================================================
echo "⚙️ Executing CodeMender operation: ${COMMAND}..."

# Sanitize command string (e.g. 'all (find -> verify -> fix)' -> 'all')
case "${COMMAND}" in
  find*)
    NORMALIZED_CMD="find"
    ;;
  verify*)
    NORMALIZED_CMD="verify"
    ;;
  fix*)
    NORMALIZED_CMD="fix"
    ;;
  hunt*|lookback*)
    NORMALIZED_CMD="hunt"
    ;;
  all*|scan-all*)
    NORMALIZED_CMD="all"
    ;;
  *)
    NORMALIZED_CMD="${COMMAND}"
    ;;
esac

ISSUES_ALREADY_CREATED="false"

ensure_cmignore() {
  if ! grep -q "worker/\*" .cmignore 2>/dev/null; then
    cat << 'CMIG' >> .cmignore
# Exclude CodeMender worker/scripts scaffold, challenge snippets, and vendor bundles from deep scan
worker/*
scripts/*
.github/*
*Challenge_*.ts
*Challenge_*.sol
juice-shop/data/static/codefixes/*
data/static/codefixes/*
*.component.ts
*.service.ts
*.module.ts
bootstrap.js
bootstrap.min.js
jquery.js
jquery.slim.js
CMIG
    mkdir -p .git/info && grep -qxF ".cmignore" .git/info/exclude 2>/dev/null || echo ".cmignore" >> .git/info/exclude
  fi
}

post_verify_comment_and_artifacts() {
  local TARGET_VULN_ID="$1"
  local TARGET_ISSUE_NUM="${2:-${ISSUE_NUMBER:-}}"
  local VERIFY_STATUS_VAL="${3:-success}"

  if [ -z "${TARGET_ISSUE_NUM}" ] && [ -n "${REPO:-}" ] && [ -n "${TARGET_VULN_ID}" ] && [ -n "${GITHUB_TOKEN:-}" ]; then
    TARGET_ISSUE_NUM=$(GH_TOKEN="${GITHUB_TOKEN}" gh issue list --repo "${REPO}" --state open --search "in:title ${TARGET_VULN_ID}" --json number --jq '.[0].number // empty' 2>/dev/null || echo "")
  fi

  local ATTACH_SCRIPT="./worker/attach_artifacts.py"
  if [ ! -f "${ATTACH_SCRIPT}" ] && [ -f "/attach_artifacts.py" ]; then
    ATTACH_SCRIPT="/attach_artifacts.py"
  fi
  local VERIFY_SUBDIR="verify/${TARGET_ISSUE_NUM:+issue-${TARGET_ISSUE_NUM}-}${TARGET_VULN_ID}"
  rm -f /tmp/cm-attached-artifacts.md
  if [ -f "${ATTACH_SCRIPT}" ]; then
    echo "📦 Collecting and publishing verification & exploit artifacts for ${TARGET_VULN_ID} (${VERIFY_SUBDIR})..."
    python3 "${ATTACH_SCRIPT}" "${REPO}" "${VERIFY_SUBDIR}" "${WORKSPACE_DIR}" "${ARTIFACTS_DIR}" "/tmp/cm-attached-artifacts.md" || true
  fi

  if [ -n "${ARTIFACTS_BUCKET:-}" ]; then
    gcloud storage cp -r "${ARTIFACTS_DIR}/*" "gs://${ARTIFACTS_BUCKET}/${REPO}/${REF}/${VERIFY_SUBDIR}/" 2>/dev/null || true
  fi

  if [ -n "${GITHUB_TOKEN:-}" ]; then
    export GH_TOKEN="${GITHUB_TOKEN}"
    export VERIFY_STATUS="${VERIFY_STATUS_VAL}"
    export SKIP_EXPLOIT_VERIFICATION="${SKIP_EXPLOIT_VERIFICATION:-false}"
    export SKIP_EXPLOIT="${SKIP_EXPLOIT:-false}"
    ISSUE_NUMBER="${TARGET_ISSUE_NUM}" VULN_ID="${TARGET_VULN_ID}" python3 - << 'PYEOF' || true
import os, re, subprocess, json

issue_num = os.environ.get("ISSUE_NUMBER", "")
repo = os.environ.get("REPO", "")
vuln_id = os.environ.get("VULN_ID", "")
ref = os.environ.get("REF", "main")
bucket = os.environ.get("ARTIFACTS_BUCKET", "")
verify_status = os.environ.get("VERIFY_STATUS", "success")
skip_exploit = os.environ.get("SKIP_EXPLOIT_VERIFICATION", "").lower() in ("true", "1", "yes") or os.environ.get("SKIP_EXPLOIT", "").lower() in ("true", "1", "yes")
log_path = "/workspace/artifacts/cm-verify.log"

if not issue_num and repo and vuln_id:
    res = subprocess.run(["gh", "issue", "list", "--repo", repo, "--state", "open", "--search", f"in:title {vuln_id}", "--json", "number"], capture_output=True, text=True)
    if res.returncode == 0 and res.stdout.strip() and res.stdout.strip() != "[]":
        try:
            issue_num = str(json.loads(res.stdout)[0]["number"])
        except Exception:
            pass

if issue_num and os.path.exists(log_path):
    with open(log_path, "r", errors="ignore") as f:
        log_text = f.read()
    
    snippet = log_text[-2500:] if len(log_text) > 2500 else log_text
    sub = f"verify/issue-{issue_num}-{vuln_id}" if issue_num else f"verify/{vuln_id}"
    audit_uri = f"gs://{bucket}/{repo}/{ref}/{sub}/" if bucket else "Cloud Storage"
    
    if "no finding matches prefix" in log_text or "Session FAILED" in log_text or (verify_status != "success" and "error" in log_text.lower()):
        status_badge = "❌ **Verification Failed / Not Found**"
    elif "Finding DISMISSED" in log_text:
        status_badge = "⚪ **Finding Dismissed (Not Present on Branch / Fixed)**"
        subprocess.run(["gh", "issue", "edit", str(issue_num), "--repo", repo, "--remove-label", "codemender:verified"], capture_output=True)
    elif skip_exploit:
        status_badge = "🔬 **Static Verification Completed**"
        subprocess.run(["gh", "label", "create", "codemender:verified", "--repo", repo, "--color", "6f42c1", "--description", "Finding verified statically in secure CodeMender sandbox", "--force"], capture_output=True)
        subprocess.run(["gh", "issue", "edit", str(issue_num), "--repo", repo, "--add-label", "codemender:verified"], capture_output=True)
        print(f"🏷️ Tagged Issue #{issue_num} with 'codemender:verified'")
    elif "Verified" in log_text or "exploitable" in log_text.lower() or verify_status == "success":
        status_badge = "✅ **Exploit Verified in Sandbox**"
        subprocess.run(["gh", "label", "create", "codemender:verified", "--repo", repo, "--color", "6f42c1", "--description", "Exploit verified in secure CodeMender sandbox", "--force"], capture_output=True)
        subprocess.run(["gh", "issue", "edit", str(issue_num), "--repo", repo, "--add-label", "codemender:verified"], capture_output=True)
        print(f"🏷️ Tagged Issue #{issue_num} with 'codemender:verified'")
    else:
        status_badge = "⚠️ **Verification Finished**"

    output_heading = "#### 🔬 Static Code Verification Output:" if skip_exploit else "#### 🧪 Sandbox Exploit Output:"
    mode_desc = "Static Analysis (`--skip-exploit-verification`)" if skip_exploit else "Dynamic Sandbox Exploit Execution"

    attached_md = ""
    raw_attached = ""
    if os.path.exists("/tmp/cm-attached-artifacts.md"):
        try:
            with open("/tmp/cm-attached-artifacts.md", "r", encoding="utf-8", errors="ignore") as af:
                raw_attached = af.read().strip()
            if raw_attached:
                attached_md = f"\n---\n\n{raw_attached}\n"
        except Exception:
            pass

    active_model = os.environ.get("VERTEX_AI_MODEL") or os.environ.get("MODEL") or "gemini-4-argon"

    body = f"""### 🔬 CodeMender Verification Results

| Attribute | Details |
| :--- | :--- |
| **Vulnerability ID** | `{vuln_id}` |
| **Status** | {status_badge} |
| **Mode** | {mode_desc} |
| **Model** | `{active_model}` |
| **Target Branch / Ref** | `{ref}` |
| **Environment** | Cloud Run (us-west1) |
| **Audit Logs** | `{audit_uri}` |

---

{output_heading}
```text
{snippet}
```
{attached_md}
---
*Verified by CodeMender via Cloud Run. Tip: comment `/cm hunt` to run a payload log search based on the verified `exploit.sh`, or `/cm fix` to open a remediation PR.*"""

    subprocess.run(["gh", "issue", "comment", str(issue_num), "--repo", repo, "--body", body], capture_output=True, text=True)
    print(f"✅ Posted verification results and attached artifacts to Issue #{issue_num} on {repo}")

    # Also update the Issue body's Attached CodeMender Artifacts section in-place with the verification bundle (.zip, exploit.sh, PLAN.md, REPORT.md, LOG.md, issue-sarif.json)
    if raw_attached:
        view_res = subprocess.run(["gh", "issue", "view", str(issue_num), "--repo", repo, "--json", "body"], capture_output=True, text=True)
        if view_res.returncode == 0 and view_res.stdout.strip():
            try:
                iss_body = json.loads(view_res.stdout).get("body", "")
                if active_model and f"`{active_model}`" not in iss_body:
                    iss_body = re.sub(
                        r"(\|\s*\*\*Verified by Models\*\*\s*\|\s*)([^\|\n]+)(\|)",
                        lambda m: f"{m.group(1)}{m.group(2).strip()}, `{active_model}` {m.group(3)}",
                        iss_body,
                    )
                if "### 📦 Attached CodeMender Artifacts" in iss_body:
                    new_iss_body = re.sub(
                        r"### 📦 Attached CodeMender Artifacts.*?(?=\n---\n\s*### 🚀 Actions & Remediation|\Z)",
                        raw_attached + "\n",
                        iss_body,
                        flags=re.DOTALL,
                    )
                elif "### 🚀 Actions & Remediation" in iss_body:
                    new_iss_body = iss_body.replace(
                        "### 🚀 Actions & Remediation",
                        f"{raw_attached}\n\n---\n\n### 🚀 Actions & Remediation",
                    )
                else:
                    new_iss_body = iss_body + f"\n\n---\n\n{raw_attached}\n"
                subprocess.run(["gh", "issue", "edit", str(issue_num), "--repo", repo, "--body", new_iss_body], capture_output=True, text=True)
                print(f"✅ Updated Issue #{issue_num} body with attached verification artifacts & .zip bundle")
            except Exception as e:
                print(f"Notice updating issue body: {e}")
PYEOF
  fi
}

author_fix_pr_for_finding() {
  local TARGET_VULN_ID="$1"
  if [ -z "${TARGET_VULN_ID}" ] || [ "${TARGET_VULN_ID}" = "none" ] || [ -z "${GITHUB_TOKEN:-}" ]; then
    return 0
  fi
  export GH_TOKEN="${GITHUB_TOKEN}"
  local ATTACH_SCRIPT="./worker/attach_artifacts.py"
  if [ ! -f "${ATTACH_SCRIPT}" ] && [ -f "/attach_artifacts.py" ]; then
    ATTACH_SCRIPT="/attach_artifacts.py"
  fi
  rm -f /tmp/cm-attached-artifacts.md
  if [ -f "${ATTACH_SCRIPT}" ]; then
    echo "📦 Collecting and publishing fix artifacts for ${TARGET_VULN_ID}..."
    python3 "${ATTACH_SCRIPT}" "${REPO}" "fix/${TARGET_VULN_ID}" "${WORKSPACE_DIR}" "${ARTIFACTS_DIR}" "/tmp/cm-attached-artifacts.md" || true
  fi

  if [ -n "${ARTIFACTS_BUCKET:-}" ]; then
    gcloud storage cp -r "${ARTIFACTS_DIR}/*" "gs://${ARTIFACTS_BUCKET}/${REPO}/${REF}/fix/${TARGET_VULN_ID}/" 2>/dev/null || true
  fi

  # Remove sandbox temporary directories and .cmignore before staging source code patch
  rm -f "${WORKSPACE_DIR}/.cmignore" 2>/dev/null || true
  find "${WORKSPACE_DIR}" -maxdepth 3 -name ".exploit" -o -name ".cm_project" 2>/dev/null | xargs rm -rf 2>/dev/null || true

  local FIX_BRANCH="codemender/fix-${TARGET_VULN_ID}"
  echo "🔀 Creating fix branch and Pull Request: ${FIX_BRANCH}..."
  git checkout -B "${FIX_BRANCH}" 2>/dev/null || git checkout -b "${FIX_BRANCH}" 2>/dev/null || true
  git add -A

  if git diff --cached --quiet; then
    echo "ℹ️ No changes staged for commit by cm fix for ${TARGET_VULN_ID}."
  else
    git commit \
      --author="CodeMender AI [bot] <${GIT_USER_EMAIL:-collinf@google.com}>" \
      -s -m "fix(security): [CodeMender] remediate finding ${TARGET_VULN_ID}

🤖 Autonomously remediated by CodeMender AI Security Agent.
- Finding ID: ${TARGET_VULN_ID}"
    git push -u origin "${FIX_BRANCH}" --force || echo "⚠️ git push failed."

    local CREATE_PR_SCRIPT="./worker/create_pr.py"
    if [ ! -f "${CREATE_PR_SCRIPT}" ] && [ -f "/create_pr.py" ]; then
      CREATE_PR_SCRIPT="/create_pr.py"
    fi
    python3 "${CREATE_PR_SCRIPT}" "${TARGET_VULN_ID}" "${REPO}" "${REF}" "${BASE_REF}" "${FIX_BRANCH}" "${ARTIFACTS_DIR}" || {
      echo "⚠️ Fallback to basic gh pr create..."
      gh pr create \
        --repo "${REPO}" \
        --head "${FIX_BRANCH}" \
        --base "${BASE_REF}" \
        --title "fix(security): remediate CodeMender finding ${TARGET_VULN_ID}" \
        --body "### 🛠️ CodeMender Remediation\nAutomated security fix for finding \`${TARGET_VULN_ID}\`." 2>/dev/null || true
    }
  fi
}

case "${NORMALIZED_CMD}" in
  find)
    TARGET_PATH="${TARGET_PATH:-.}"
    export MODEL="${SCAN_MODEL}"
    export VERTEX_AI_MODEL="${SCAN_MODEL}"
    SCAN_MODEL_FLAG=(--model "${SCAN_MODEL}")
    if [ "${SCAN_MODE:-}" = "diff" ] || [ -n "${PR_NUMBER:-}" ]; then
      echo "🔍 Configuring CodeMender diff scan (--diff) against origin/${BASE_REF:-main}..."
      git fetch origin "${BASE_REF:-main}:refs/remotes/origin/${BASE_REF:-main}" 2>/dev/null || git fetch origin "${BASE_REF:-main}" 2>/dev/null || true
      SCAN_MODE_FLAG=("--diff=origin/${BASE_REF:-main}")
    else
      echo "🔍 Configuring CodeMender deep scan (--deep --deep-workers ${DEEP_WORKERS:-16})..."
      SCAN_MODE_FLAG=(--deep --deep-workers "${DEEP_WORKERS:-16}")
      ensure_cmignore
    fi
    echo "🔍 Running: cm find --bypass-warning -y ${SCAN_MODE_FLAG[*]} ${SCAN_MODEL_FLAG[*]} ${TARGET_PATH} ..."
    cm find --bypass-warning -y "${SCAN_MODE_FLAG[@]}" "${SCAN_MODEL_FLAG[@]}" "${TARGET_PATH}" 2>&1 | tee "${ARTIFACTS_DIR}/cm-find.log" || cm find "${SCAN_MODE_FLAG[@]}" "${SCAN_MODEL_FLAG[@]}" "${TARGET_PATH}" 2>&1 | tee "${ARTIFACTS_DIR}/cm-find.log" || true
    echo "📊 Exporting findings report..."
    cm report --format md > "${ARTIFACTS_DIR}/findings-report.md" 2>/dev/null || true
    cm report --format json > "${ARTIFACTS_DIR}/findings.json" 2>/dev/null || true
    cm report --format sarif > "${ARTIFACTS_DIR}/codemender.sarif" 2>/dev/null || true
    cm report --format html 2>/dev/null || true
    cp /root/.codemender/reports/report.html "${ARTIFACTS_DIR}/report.html" 2>/dev/null || true
    ;;

  verify)
    if [ -z "${VULN_ID}" ] || [ "${VULN_ID}" = "none" ]; then
      echo "❌ Error: VULN_ID is required for verify command."
      exit 1
    fi
    echo "🔍 Resolving/importing finding ID ${VULN_ID} in workspace state..."
    RESOLVE_SCRIPT="./worker/resolve_finding.py"
    if [ ! -f "${RESOLVE_SCRIPT}" ] && [ -f "/resolve_finding.py" ]; then
      RESOLVE_SCRIPT="/resolve_finding.py"
    fi
    RESOLVED_ID=$(python3 "${RESOLVE_SCRIPT}" "${VULN_ID}" "${ISSUE_NUMBER:-}" "${REPO:-}" "${WORKSPACE_DIR}" "${ARTIFACTS_DIR}" | tail -n1 || echo "${VULN_ID}")
    CM_TARGET_ID="${VULN_ID}"
    if [ -n "${RESOLVED_ID}" ] && [ "${RESOLVED_ID}" != "${VULN_ID}" ]; then
      echo "🔄 Auto-mapped finding '${VULN_ID}' -> '${RESOLVED_ID}' from repository findings."
      CM_TARGET_ID="${RESOLVED_ID}"
    fi

    export MODEL="${REMEDIATION_MODEL}"
    export VERTEX_AI_MODEL="${REMEDIATION_MODEL}"
    REMEDIATION_MODEL_FLAG=(--model "${REMEDIATION_MODEL}")

    VERIFY_EXTRA_FLAGS=()
    if [ "${SKIP_EXPLOIT_VERIFICATION:-false}" = "true" ] || [ "${SKIP_EXPLOIT:-false}" = "true" ]; then
      echo "⚡ Static verification mode requested (--skip-exploit-verification)."
      VERIFY_EXTRA_FLAGS+=(--skip-exploit-verification)
    fi

    echo "🔬 Running: cm verify --bypass-warning -y ${VERIFY_EXTRA_FLAGS[*]} ${REMEDIATION_MODEL_FLAG[*]} ${CM_TARGET_ID} ..."
    VERIFY_STATUS="success"
    cm verify --bypass-warning -y "${VERIFY_EXTRA_FLAGS[@]}" "${REMEDIATION_MODEL_FLAG[@]}" "${CM_TARGET_ID}" 2>&1 | tee "${ARTIFACTS_DIR}/cm-verify.log" || cm verify "${VERIFY_EXTRA_FLAGS[@]}" "${REMEDIATION_MODEL_FLAG[@]}" "${CM_TARGET_ID}" 2>&1 | tee "${ARTIFACTS_DIR}/cm-verify.log" || {
      VERIFY_STATUS="failed"
      echo "⚠️ cm verify exited with non-zero status."
    }

    cm report --format md > "${ARTIFACTS_DIR}/findings-report.md" 2>/dev/null || true
    cm report --format json > "${ARTIFACTS_DIR}/findings.json" 2>/dev/null || true
    cm report --format sarif > "${ARTIFACTS_DIR}/codemender.sarif" 2>/dev/null || true
    cm report --format html 2>/dev/null || true
    cp /root/.codemender/reports/report.html "${ARTIFACTS_DIR}/report.html" 2>/dev/null || true

    post_verify_comment_and_artifacts "${VULN_ID}" "${ISSUE_NUMBER:-}" "${VERIFY_STATUS}"
    ;;

  fix)
    if [ -z "${VULN_ID}" ] || [ "${VULN_ID}" = "none" ]; then
      echo "❌ Error: VULN_ID is required for fix command."
      exit 1
    fi
    echo "🔍 Resolving/importing finding ID ${VULN_ID} in workspace state..."
    RESOLVE_SCRIPT="./worker/resolve_finding.py"
    if [ ! -f "${RESOLVE_SCRIPT}" ] && [ -f "/resolve_finding.py" ]; then
      RESOLVE_SCRIPT="/resolve_finding.py"
    fi
    RESOLVED_ID=$(python3 "${RESOLVE_SCRIPT}" "${VULN_ID}" "${ISSUE_NUMBER:-}" "${REPO:-}" "${WORKSPACE_DIR}" "${ARTIFACTS_DIR}" | tail -n1 || echo "${VULN_ID}")
    CM_TARGET_ID="${VULN_ID}"
    if [ -n "${RESOLVED_ID}" ] && [ "${RESOLVED_ID}" != "${VULN_ID}" ]; then
      echo "🔄 Auto-mapped finding '${VULN_ID}' -> '${RESOLVED_ID}' from repository findings."
      CM_TARGET_ID="${RESOLVED_ID}"
    fi

    export MODEL="${REMEDIATION_MODEL}"
    export VERTEX_AI_MODEL="${REMEDIATION_MODEL}"
    REMEDIATION_MODEL_FLAG=(--model "${REMEDIATION_MODEL}")

    echo "🛠️ Running: cm fix --bypass-warning -y ${REMEDIATION_MODEL_FLAG[*]} ${CM_TARGET_ID} ..."
    cm fix --bypass-warning -y "${REMEDIATION_MODEL_FLAG[@]}" "${CM_TARGET_ID}" 2>&1 | tee "${ARTIFACTS_DIR}/cm-fix.log" || cm fix "${REMEDIATION_MODEL_FLAG[@]}" "${CM_TARGET_ID}" 2>&1 | tee "${ARTIFACTS_DIR}/cm-fix.log" || true
    ;;

  hunt)
    echo "🕵️‍♂️ Executing CodeMender Forensic Log Lookback (cm hunt) for ${VULN_ID:-Issue #${ISSUE_NUMBER:-}}..."
    export WORKSPACE_DIR="${WORKSPACE_DIR}"
    export ARTIFACTS_DIR="${ARTIFACTS_DIR}"
    HUNT_SCRIPT="./worker/log_hunt.py"
    if [ ! -f "${HUNT_SCRIPT}" ] && [ -f "/log_hunt.py" ]; then
      HUNT_SCRIPT="/log_hunt.py"
    fi
    python3 "${HUNT_SCRIPT}" 2>&1 | tee "${ARTIFACTS_DIR}/cm-hunt.log"
    ;;

  all)
    echo "🛡️ Running Full CodeMender Pipeline (find -> verify -> fix)..."
    TARGET_PATH="${TARGET_PATH:-.}"
    export MODEL="${SCAN_MODEL}"
    export VERTEX_AI_MODEL="${SCAN_MODEL}"
    SCAN_MODEL_FLAG=(--model "${SCAN_MODEL}")

    IS_PR_DIFF_SCAN="false"
    if [ "${SCAN_MODE:-}" = "diff" ] || [ -n "${PR_NUMBER:-}" ] || ([ -n "${HEAD_BRANCH:-}" ] && [ "${HEAD_BRANCH}" != "main" ] && [ "${HEAD_BRANCH}" != "master" ]); then
      IS_PR_DIFF_SCAN="true"
      echo "🔍 Configuring CodeMender diff scan (--diff) for PR branch: ${HEAD_BRANCH:-${REF}} vs base origin/${BASE_REF:-main}..."
      git fetch origin "${BASE_REF:-main}:refs/remotes/origin/${BASE_REF:-main}" 2>/dev/null || git fetch origin "${BASE_REF:-main}" 2>/dev/null || true
      SCAN_MODE_FLAG=("--diff=origin/${BASE_REF:-main}")
    else
      echo "🔍 Configuring CodeMender deep scan (--deep --deep-workers ${DEEP_WORKERS:-16}) for repository path: ${TARGET_PATH}..."
      SCAN_MODE_FLAG=(--deep --deep-workers "${DEEP_WORKERS:-16}")
      ensure_cmignore
    fi

    echo "🔍 Running: cm find --bypass-warning -y ${SCAN_MODE_FLAG[*]} ${SCAN_MODEL_FLAG[*]} ${TARGET_PATH} ..."
    cm find --bypass-warning -y "${SCAN_MODE_FLAG[@]}" "${SCAN_MODEL_FLAG[@]}" "${TARGET_PATH}" 2>&1 | tee "${ARTIFACTS_DIR}/cm-find.log" || cm find "${SCAN_MODE_FLAG[@]}" "${SCAN_MODEL_FLAG[@]}" "${TARGET_PATH}" 2>&1 | tee "${ARTIFACTS_DIR}/cm-find.log" || true
    echo "📊 Exporting findings report..."
    cm report --format md > "${ARTIFACTS_DIR}/findings-report.md" 2>/dev/null || true
    cm report --format json > "${ARTIFACTS_DIR}/findings.json" 2>/dev/null || true
    cm report --format sarif > "${ARTIFACTS_DIR}/codemender.sarif" 2>/dev/null || true
    cm report --format html 2>/dev/null || true
    cp /root/.codemender/reports/report.html "${ARTIFACTS_DIR}/report.html" 2>/dev/null || true
    
    # Auto-generate summary
    cat <<EOF > "${ARTIFACTS_DIR}/summary.md"
### 🛡️ CodeMender Security Scan Summary
- **Repository:** \`${REPO}\`
- **Ref / SHA:** \`${REF}\`
- **Scan Status:** Completed
- **Timestamp:** $(date -u +"%Y-%m-%d %H:%M:%S UTC")

#### Artifacts Generated:
- [Execution Logs](cm-find.log)
- [HTML Report](report.html)
- [JSON Findings](findings.json)
- [SARIF Report](codemender.sarif)
EOF

    # Sync scan artifacts to GCS early so logs are preserved
    if [ -n "${ARTIFACTS_BUCKET:-}" ] && [ -d "${ARTIFACTS_DIR}" ]; then
      echo "📤 Syncing initial scan artifacts to GCS..."
      gcloud storage cp -r "${ARTIFACTS_DIR}/*" "gs://${ARTIFACTS_BUCKET}/${REPO}/${HEAD_SHA:-${REF}}/" 2>/dev/null || true
    fi

    if [ "${IS_PR_DIFF_SCAN}" = "true" ]; then
      POST_COMMENTS_SCRIPT="./worker/post_pr_comments.py"
      if [ ! -f "${POST_COMMENTS_SCRIPT}" ] && [ -f "/post_pr_comments.py" ]; then
        POST_COMMENTS_SCRIPT="/post_pr_comments.py"
      fi

      # 1. Post Comment 1: FIND STEP (summarizing detected findings or clean status)
      if [ -n "${PR_NUMBER:-}" ] && [ -n "${GITHUB_TOKEN:-}" ]; then
        export GH_TOKEN="${GITHUB_TOKEN}"
        python3 "${POST_COMMENTS_SCRIPT}" find || echo "ℹ️ FIND comment posting encountered non-fatal error."
      fi

      # If running on a feature/PR branch with findings in the PR diff, automatically synthesize fix and push
      if [ -f "${ARTIFACTS_DIR}/findings.json" ]; then
        FINDING_IDS=$(python3 -c "import json, os, subprocess, re

def clean_file_path(p):
    p = str(p).strip()
    for prefix in ['/workspace/repo/', '/workspace/', './']:
        if p.startswith(prefix):
            p = p[len(prefix):]
    return p

try:
    data = json.load(open('${ARTIFACTS_DIR}/findings.json'))
    items = data if isinstance(data, list) else data.get('findings', [])
    base_ref = os.environ.get('BASE_REF', 'main')
    
    subprocess.run(['git', 'fetch', 'origin', f'{base_ref}:refs/remotes/origin/{base_ref}'], capture_output=True)
    res = subprocess.run(['git', 'diff', '-U0', f'origin/{base_ref}...HEAD'], capture_output=True, text=True)
    changed_lines = {}
    current_file = None
    if res.returncode == 0 and res.stdout.strip():
        for line in res.stdout.splitlines():
            if line.startswith('+++ b/'):
                current_file = clean_file_path(line[6:].strip())
                if current_file not in changed_lines:
                    changed_lines[current_file] = set()
            elif line.startswith('@@ ') and current_file:
                m = re.search(r'\+([0-9]+)(?:,([0-9]+))?', line)
                if m:
                    start = int(m.group(1))
                    count = int(m.group(2)) if m.group(2) else 1
                    for l in range(start, start + count):
                        changed_lines[current_file].add(l)

    ids = []
    for x in items:
        fid = str(x.get('FindingID') or x.get('id') or x.get('finding_id') or '')[:8]
        if not fid:
            continue
        file_p = clean_file_path(x.get('file_path') or x.get('File') or x.get('file') or x.get('FilePath') or x.get('path') or '')
        try:
            start_l = int(x.get('StartLine') or x.get('start_line') or 0)
        except (ValueError, TypeError):
            start_l = 0

        # When running on a PR, strictly check if the finding is in the PR diff
        if changed_lines:
            matched_cf = None
            for cf in changed_lines:
                if file_p.endswith(cf) or cf.endswith(file_p):
                    matched_cf = cf
                    break
            if not matched_cf:
                continue
            line_set = changed_lines[matched_cf]
            if line_set and start_l > 0:
                if not any(l in line_set for l in range(max(1, start_l - 5), start_l + 6)):
                    continue
        ids.append(fid)
    print(' '.join(ids))
except Exception:
    pass
" 2>/dev/null || true)

        if [ -n "${FINDING_IDS}" ]; then
          echo "🔍 Discovered findings to remediate in PR: ${FINDING_IDS}"
          PRIMARY_FID=$(echo "${FINDING_IDS}" | awk '{print $1}')

          export MODEL="${REMEDIATION_MODEL}"
          export VERTEX_AI_MODEL="${REMEDIATION_MODEL}"
          REMEDIATION_MODEL_FLAG=(--model "${REMEDIATION_MODEL}")

          echo "🛠️ Synthesizing security fix for PR finding ${PRIMARY_FID} using ${REMEDIATION_MODEL}..."
          cm fix --bypass-warning -y "${REMEDIATION_MODEL_FLAG[@]}" "${PRIMARY_FID}" 2>&1 | tee "${ARTIFACTS_DIR}/cm-fix-${PRIMARY_FID}.log" || true

          # If running on an active PR branch, push remediation directly to the PR branch
          if [ -n "${HEAD_BRANCH:-}" ] && [ "${HEAD_BRANCH}" != "main" ] && [ "${HEAD_BRANCH}" != "master" ] && [ -n "${GITHUB_TOKEN:-}" ] && [ "${AUTO_PR}" = "true" ]; then
            if ! git diff --quiet || [ -n "$(git status --porcelain)" ]; then
              echo "🔀 Staging automated remediation commits for branch: ${HEAD_BRANCH}..."
              git checkout -B "${HEAD_BRANCH}" 2>/dev/null || true
              git add -A
              git commit \
                --author="CodeMender AI [bot] <${GIT_USER_EMAIL:-collinf@google.com}>" \
                -s -m "fix(security): [CodeMender] remediate finding ${PRIMARY_FID}

🤖 Autonomously remediated by CodeMender AI Security Agent in GitHub Actions.
- Finding ID: ${PRIMARY_FID}
- Target Branch: ${HEAD_BRANCH}
- Target: Autonomous PR Security Gate Remediation"
              echo "🚀 Pushing automated remediation directly to PR branch: ${HEAD_BRANCH}..."
              git push origin "${HEAD_BRANCH}" --force || echo "⚠️ Push to ${HEAD_BRANCH} failed."

              # 2. Post Comment 2: FIX STEP (summarizing patch commit and updated branch)
              if [ -n "${PR_NUMBER:-}" ]; then
                export GH_TOKEN="${GITHUB_TOKEN}"
                export PRIMARY_FID="${PRIMARY_FID}"
                echo "🏷️ Tagging PR #${PR_NUMBER} with 'codemender' and 'codemender:auto-fixed'..."
                gh label create "codemender" --repo "${REPO}" --color "0366d6" --description "Detected or acted upon by CodeMender AI" --force 2>/dev/null || true
                gh label create "codemender:auto-fixed" --repo "${REPO}" --color "0075ca" --description "Pull Request automatically patched by CodeMender AI" --force 2>/dev/null || true
                gh pr edit "${PR_NUMBER}" --repo "${REPO}" --add-label "codemender,codemender:auto-fixed" 2>/dev/null || true
                python3 "${POST_COMMENTS_SCRIPT}" fix "${PRIMARY_FID}" || echo "ℹ️ FIX comment posting encountered non-fatal error."
              fi
            fi
          fi
        fi
      fi
    else
      # ========================================================================
      # Full Repository Loop (find -> create issues -> verify -> fix -> PRs)
      # ========================================================================
      if [ -n "${GITHUB_TOKEN:-}" ] && ([ -f "${ARTIFACTS_DIR}/findings.json" ] || [ -f "${ARTIFACTS_DIR}/cm-find.log" ]); then
        export GH_TOKEN="${GITHUB_TOKEN}"
        export MODEL="${SCAN_MODEL}"
        export VERTEX_AI_MODEL="${SCAN_MODEL}"
        ATTACH_SCRIPT="./worker/attach_artifacts.py"
        if [ ! -f "${ATTACH_SCRIPT}" ] && [ -f "/attach_artifacts.py" ]; then
          ATTACH_SCRIPT="/attach_artifacts.py"
        fi
        FIND_SUBDIR="find/${REF}"
        if [ -n "${TARGET_PATH:-}" ] && [ "${TARGET_PATH}" != "." ]; then
          TARGET_SLUG=$(echo "${TARGET_PATH}" | tr '/' '_')
          FIND_SUBDIR="${FIND_SUBDIR}/${TARGET_SLUG}"
        fi
        rm -f /tmp/cm-attached-artifacts.md
        if [ -f "${ATTACH_SCRIPT}" ]; then
          echo "📦 Collecting and publishing scan artifacts to ${REPO}@codemender/artifacts/${FIND_SUBDIR}..."
          python3 "${ATTACH_SCRIPT}" "${REPO}" "${FIND_SUBDIR}" "${WORKSPACE_DIR}" "${ARTIFACTS_DIR}" "/tmp/cm-attached-artifacts.md" || true
        fi

        if [ "${CREATE_ISSUES:-true}" != "false" ]; then
          echo "📋 Step 1/3: Creating/updating GitHub tracking issues from deep scan findings..."
          CREATE_ISSUES_SCRIPT="./worker/create_issues.py"
          if [ ! -f "${CREATE_ISSUES_SCRIPT}" ] && [ -f "/create_issues.py" ]; then
            CREATE_ISSUES_SCRIPT="/create_issues.py"
          fi
          python3 "${CREATE_ISSUES_SCRIPT}" || echo "ℹ️ Issue creation encountered non-fatal error."
          ISSUES_ALREADY_CREATED="true"
        fi
      fi

      if [ -f "${ARTIFACTS_DIR}/findings.json" ]; then
        cp "${ARTIFACTS_DIR}/findings.json" /tmp/cm-baseline-findings.json 2>/dev/null || true
      fi

      if [ -n "${VULN_ID:-}" ] && [ "${VULN_ID}" != "none" ]; then
        ALL_TARGET_IDS="${VULN_ID}"
      elif [ -f "/tmp/cm-baseline-findings.json" ]; then
        ALL_TARGET_IDS=$(python3 - << 'PYEOF' 2>/dev/null || true
import json, os, re

def clean_file_path(path):
    p = str(path or "").strip()
    for prefix in ("/workspace/repo/", "/workspace/", "./"):
        if p.startswith(prefix):
            p = p[len(prefix):]
    p = re.sub(r"^\.?/+", "", p)
    return p

try:
    data = json.load(open("/tmp/cm-baseline-findings.json", "r", encoding="utf-8"))
    items = data if isinstance(data, list) else data.get("findings", [])
    sev_rank = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    candidates = []
    for item in items:
        status_val = str(item.get("Status") or item.get("status") or "OPEN").strip().upper()
        if status_val in ("DISMISSED", "FALSE_POSITIVE", "REJECTED", "IGNORED"):
            continue
        fid = str(item.get("FindingID") or item.get("id") or item.get("finding_id") or "").strip()[:8]
        if not fid:
            continue
        raw_file = clean_file_path(item.get("FilePath") or item.get("file_path") or item.get("file") or item.get("path") or "")
        if raw_file.startswith(("worker/", "scripts/", ".github/")) or raw_file == ".cmignore":
            continue
        sev = str(item.get("Severity") or item.get("severity") or "HIGH").strip().upper()
        sev = re.sub(r"^[🔴🟠🟡🟢⚪ℹ️]\s*", "", sev).strip()
        candidates.append((sev_rank.get(sev, 2), fid))
    candidates.sort(key=lambda x: x[0])
    max_items = int(os.environ.get("MAX_ALL_FINDINGS", "5"))
    seen = []
    for _, fid in candidates:
        if fid not in seen:
            seen.append(fid)
        if len(seen) >= max_items:
            break
    print(" ".join(seen))
except Exception:
    pass
PYEOF
)
      else
        ALL_TARGET_IDS=""
      fi

      if [ -n "${ALL_TARGET_IDS}" ]; then
        echo "🔄 Executing Verify -> Fix -> PR pipeline for findings: ${ALL_TARGET_IDS}"
        export MODEL="${REMEDIATION_MODEL}"
        export VERTEX_AI_MODEL="${REMEDIATION_MODEL}"
        REMEDIATION_MODEL_FLAG=(--model "${REMEDIATION_MODEL}")

        VERIFY_EXTRA_FLAGS=()
        if [ "${SKIP_EXPLOIT_VERIFICATION:-false}" = "true" ] || [ "${SKIP_EXPLOIT:-false}" = "true" ]; then
          VERIFY_EXTRA_FLAGS+=(--skip-exploit-verification)
        fi

        RESOLVE_SCRIPT="./worker/resolve_finding.py"
        if [ ! -f "${RESOLVE_SCRIPT}" ] && [ -f "/resolve_finding.py" ]; then
          RESOLVE_SCRIPT="/resolve_finding.py"
        fi

        for FID in ${ALL_TARGET_IDS}; do
          echo "================================================================="
          echo "🔬 Step 2/3 [Verify]: Verifying finding ${FID}..."
          echo "================================================================="
          git checkout -f "${REF}" 2>/dev/null || true
          git clean -fd -e .cmignore 2>/dev/null || true
          ensure_cmignore
          if [ -f "/tmp/cm-baseline-findings.json" ]; then
            cp /tmp/cm-baseline-findings.json "${ARTIFACTS_DIR}/findings.json" 2>/dev/null || true
          fi

          RESOLVED_ID=$(python3 "${RESOLVE_SCRIPT}" "${FID}" "" "${REPO:-}" "${WORKSPACE_DIR}" "${ARTIFACTS_DIR}" | tail -n1 || echo "${FID}")
          CM_TARGET_ID="${FID}"
          if [ -n "${RESOLVED_ID}" ] && [ "${RESOLVED_ID}" != "${FID}" ]; then
            CM_TARGET_ID="${RESOLVED_ID}"
          fi

          VERIFY_STATUS="success"
          cm verify --bypass-warning -y "${VERIFY_EXTRA_FLAGS[@]}" "${REMEDIATION_MODEL_FLAG[@]}" "${CM_TARGET_ID}" 2>&1 | tee "${ARTIFACTS_DIR}/cm-verify.log" || cm verify "${VERIFY_EXTRA_FLAGS[@]}" "${REMEDIATION_MODEL_FLAG[@]}" "${CM_TARGET_ID}" 2>&1 | tee "${ARTIFACTS_DIR}/cm-verify.log" || {
            VERIFY_STATUS="failed"
            echo "⚠️ cm verify for ${FID} exited with non-zero status."
          }
          cp "${ARTIFACTS_DIR}/cm-verify.log" "${ARTIFACTS_DIR}/cm-verify-${FID}.log" 2>/dev/null || true

          post_verify_comment_and_artifacts "${FID}" "" "${VERIFY_STATUS}"

          echo "================================================================="
          echo "🛠️ Step 3/3 [Fix & PR]: Synthesizing remediation patch for ${FID}..."
          echo "================================================================="
          find "${WORKSPACE_DIR}" -maxdepth 3 -name ".exploit" 2>/dev/null | xargs rm -rf 2>/dev/null || true
          git checkout -f "${REF}" 2>/dev/null || true
          git clean -fd -e .cmignore 2>/dev/null || true
          ensure_cmignore
          if [ -f "/tmp/cm-baseline-findings.json" ]; then
            cp /tmp/cm-baseline-findings.json "${ARTIFACTS_DIR}/findings.json" 2>/dev/null || true
          fi

          cm fix --bypass-warning -y "${REMEDIATION_MODEL_FLAG[@]}" "${CM_TARGET_ID}" 2>&1 | tee "${ARTIFACTS_DIR}/cm-fix.log" || cm fix "${REMEDIATION_MODEL_FLAG[@]}" "${CM_TARGET_ID}" 2>&1 | tee "${ARTIFACTS_DIR}/cm-fix.log" || true
          cp "${ARTIFACTS_DIR}/cm-fix.log" "${ARTIFACTS_DIR}/cm-fix-${FID}.log" 2>/dev/null || true

          author_fix_pr_for_finding "${FID}"

          # Return working copy cleanly to target ref before next finding
          git checkout -f "${REF}" 2>/dev/null || true
          git clean -fd -e .cmignore 2>/dev/null || true
          ensure_cmignore
        done

        if [ -f "/tmp/cm-baseline-findings.json" ]; then
          cp /tmp/cm-baseline-findings.json "${ARTIFACTS_DIR}/findings.json" 2>/dev/null || true
        fi
      else
        echo "ℹ️ No application findings discovered for verify -> fix pipeline."
      fi
    fi
    ;;

  cleanup|reset)
    echo "🧹 Executing Cloud Run Cleanup for repository: ${REPO}..."
    if [ -n "${GITHUB_TOKEN:-}" ]; then
      export GH_TOKEN="${GITHUB_TOKEN}"
      
      echo "🧹 1. Closing and removing open Pull Requests..."
      PRS=$(gh pr list --repo "${REPO}" --state open --json number --jq '.[].number' 2>/dev/null || true)
      for pr in $PRS; do
        echo "Closing PR #${pr}..."
        gh pr close "$pr" --repo "${REPO}" --delete-branch 2>/dev/null || gh pr close "$pr" --repo "${REPO}" || true
      done

      echo "🧹 2. Deleting stale codemender/fix-* branches..."
      BRANCHES=$(gh api "repos/${REPO}/branches" --jq '.[].name | select(startswith("codemender/"))' 2>/dev/null || true)
      for branch in $BRANCHES; do
        echo "Deleting branch ${branch}..."
        gh api -X DELETE "repos/${REPO}/git/refs/heads/${branch}" 2>/dev/null || true
      done

      echo "🧹 3. Deleting or closing all Issues..."
      ISSUES=$(gh issue list --repo "${REPO}" --state all --limit 100 --json number --jq '.[].number' 2>/dev/null || true)
      for issue in $ISSUES; do
        echo "Removing Issue #${issue}..."
        gh issue delete "$issue" --repo "${REPO}" --yes 2>/dev/null || gh issue close "$issue" --repo "${REPO}" || true
      done
      
      echo "✅ Repository cleanup finished successfully."
    else
      echo "⚠️ Error: GITHUB_TOKEN not available in Secret Manager."
      exit 1
    fi
    ;;

  *)
    echo "Executing generic command: ${COMMAND}"
    bash -c "${COMMAND}" || true
    ;;
esac

# Copy CodeMender session logs to artifacts before publishing/attaching
if [ -d /root/.codemender/logs ]; then
  mkdir -p "${ARTIFACTS_DIR}/cm-session-logs"
  cp -r /root/.codemender/logs/* "${ARTIFACTS_DIR}/cm-session-logs/" 2>/dev/null || true
fi

# Automatically create individual GitHub Issues for discovered vulnerabilities (with attached artifacts)
if [ "${ISSUES_ALREADY_CREATED}" != "true" ] && [ "${NORMALIZED_CMD}" != "verify" ] && [ "${NORMALIZED_CMD}" != "fix" ] && [ "${NORMALIZED_CMD}" != "hunt" ] && ([ -f "${ARTIFACTS_DIR}/findings.json" ] || [ -f "${ARTIFACTS_DIR}/cm-find.log" ]) && [ -n "${GITHUB_TOKEN:-}" ]; then
  export GH_TOKEN="${GITHUB_TOKEN}"
  export MODEL="${SCAN_MODEL}"
  export VERTEX_AI_MODEL="${SCAN_MODEL}"
  ATTACH_SCRIPT="./worker/attach_artifacts.py"
  if [ ! -f "${ATTACH_SCRIPT}" ] && [ -f "/attach_artifacts.py" ]; then
    ATTACH_SCRIPT="/attach_artifacts.py"
  fi
  FIND_SUBDIR="find/${REF}"
  if [ -n "${TARGET_PATH:-}" ] && [ "${TARGET_PATH}" != "." ]; then
    TARGET_SLUG=$(echo "${TARGET_PATH}" | tr '/' '_')
    FIND_SUBDIR="${FIND_SUBDIR}/${TARGET_SLUG}"
  fi
  rm -f /tmp/cm-attached-artifacts.md
  if [ -f "${ATTACH_SCRIPT}" ]; then
    echo "📦 Collecting and publishing scan artifacts to ${REPO}@codemender/artifacts/${FIND_SUBDIR}..."
    python3 "${ATTACH_SCRIPT}" "${REPO}" "${FIND_SUBDIR}" "${WORKSPACE_DIR}" "${ARTIFACTS_DIR}" "/tmp/cm-attached-artifacts.md" || true
  fi

  if [ -z "${PR_NUMBER:-}" ] && [ "${SCAN_MODE:-}" != "diff" ] && [ "${CREATE_ISSUES:-true}" != "false" ]; then
    echo "📋 Parsing findings and managing individual GitHub tracking issues..."
    CREATE_ISSUES_SCRIPT="./worker/create_issues.py"
    if [ ! -f "${CREATE_ISSUES_SCRIPT}" ] && [ -f "/create_issues.py" ]; then
      CREATE_ISSUES_SCRIPT="/create_issues.py"
    fi
    python3 "${CREATE_ISSUES_SCRIPT}" || echo "ℹ️ Issue creation encountered non-fatal error."
  else
    echo "ℹ️ Skipping repository issue creation for PR diff scan (findings reported directly on PR #${PR_NUMBER:-diff})."
  fi
fi

# Automatically author Pull Request if fix was executed
if [ "${NORMALIZED_CMD}" = "fix" ] && [ -n "${VULN_ID}" ] && [ "${VULN_ID}" != "none" ] && [ "${AUTO_PR}" = "true" ] && [ -n "${GITHUB_TOKEN:-}" ]; then
  author_fix_pr_for_finding "${VULN_ID}"
fi

# ==============================================================================
# 4. Upload Logs & Artifacts to Google Cloud Storage
# ==============================================================================
if [ -n "${ARTIFACTS_BUCKET}" ]; then
  GCS_DEST="gs://${ARTIFACTS_BUCKET}/${REPO}/${REF}"
  if [ "${NORMALIZED_CMD}" = "verify" ] && [ -n "${VULN_ID:-}" ]; then
    GCS_DEST="${GCS_DEST}/verify/${ISSUE_NUMBER:+issue-${ISSUE_NUMBER}-}${VULN_ID}"
  elif [ "${NORMALIZED_CMD}" = "fix" ] && [ -n "${VULN_ID:-}" ]; then
    GCS_DEST="${GCS_DEST}/fix/${ISSUE_NUMBER:+issue-${ISSUE_NUMBER}-}${VULN_ID}"
  elif [ "${NORMALIZED_CMD}" = "hunt" ] && [ -n "${VULN_ID:-}" ]; then
    GCS_DEST="${GCS_DEST}/hunt/${ISSUE_NUMBER:+issue-${ISSUE_NUMBER}-}${VULN_ID}"
  elif [ -n "${TARGET_PATH:-}" ] && [ "${TARGET_PATH}" != "." ]; then
    TARGET_SLUG=$(echo "${TARGET_PATH}" | tr '/' '_')
    GCS_DEST="${GCS_DEST}/${TARGET_SLUG}"
  fi
  echo "📤 Syncing scan artifacts to GCS: ${GCS_DEST}..."
  gcloud storage cp -r "${ARTIFACTS_DIR}/*" "${GCS_DEST}/" || echo "⚠️ GCS sync encountered non-fatal error."
fi

echo "✅ CodeMender worker task finished successfully."
