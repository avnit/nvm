#!/usr/bin/env python3
"""
CodeMender Impact & Adoption Telemetry Aggregator (`scripts/generate_impact_report.py`)

Tracks and aggregates adoption, Googler usage, customer demo activity, and repository traffic across:
  1. `cloud-gtm/cm-gh-auto` (Demo Builder & Infrastructure Orchestrator)
  2. `cloud-gtm/codemender-actions-demo` (Live Shared Demo & Testbed Repo)
  3. All Personal Googler Demo Repos (`<googler>/<repo>-demo`) via Google Cloud Logging
     (`projects/cm-gh-506516/logs/codemender-usage-metrics`), Cloud Run Job executions, and GCS.

Also snapshots GitHub's 14-day rolling traffic API (`views` and `clones`) into Google Cloud Storage
(`gs://codemender-artifacts-cm-gh-506516/_metrics/traffic-history.json`) so cumulative all-time
views and clones are permanently preserved beyond GitHub's 14-day window.
"""

import collections
import datetime
import json
import os
import subprocess
import sys
import urllib.request

PROJECT_ID = os.environ.get("GCP_PROJECT_ID", "cm-gh-506516")
BUCKET_NAME = os.environ.get("ARTIFACTS_BUCKET", "codemender-artifacts-cm-gh-506516")
PRIMARY_REPOS = [
    "cloud-gtm/cm-gh-auto",
    "cloud-gtm/codemender-actions-demo",
]
BOT_LOGINS = {
    "dependabot[bot]",
    "google-cla[bot]",
    "gtm-github-bot[bot]",
    "github-actions[bot]",
}


def run_gh_json(args, env=None):
    try:
        res = subprocess.run(
            ["gh"] + args,
            capture_output=True,
            text=True,
            env=env or os.environ.copy(),
            timeout=45,
        )
        if res.returncode == 0 and res.stdout.strip():
            return json.loads(res.stdout)
    except Exception as e:
        print(f"⚠️ gh api warning ({' '.join(args[:3])}): {e}", file=sys.stderr)
    return None


def get_gcloud_token():
    try:
        return subprocess.check_output(
            ["gcloud", "auth", "print-access-token"],
            text=True,
            timeout=10,
        ).strip()
    except Exception:
        return ""


def load_and_update_traffic_history(gh_env):
    """
    Fetches 14-day rolling traffic (views & clones) for both primary repos from GitHub API
    and merges daily buckets into `gs://<bucket>/_metrics/traffic-history.json` so all-time
    cumulative views and clones are never lost after 14 days.
    """
    gcs_uri = f"gs://{BUCKET_NAME}/_metrics/traffic-history.json"
    local_tmp = "/tmp/cm-traffic-history.json"
    history = {"repos": {}}

    try:
        res = subprocess.run(
            ["gcloud", "storage", "cp", gcs_uri, local_tmp],
            capture_output=True,
            text=True,
            timeout=15,
        )
        if res.returncode == 0 and os.path.isfile(local_tmp):
            with open(local_tmp, "r", encoding="utf-8") as f:
                history = json.load(f)
    except Exception:
        pass

    summary = {}
    for repo in PRIMARY_REPOS:
        repo_hist = history.setdefault("repos", {}).setdefault(
            repo, {"views_by_day": {}, "clones_by_day": {}, "peak_unique_visitors_14d": 0, "peak_unique_cloners_14d": 0}
        )
        views_data = run_gh_json(["api", f"repos/{repo}/traffic/views"], env=gh_env) or {}
        clones_data = run_gh_json(["api", f"repos/{repo}/traffic/clones"], env=gh_env) or {}

        for v in views_data.get("views", []):
            ts = v.get("timestamp", "")[:10]
            if ts:
                repo_hist["views_by_day"][ts] = {
                    "count": max(v.get("count", 0), repo_hist["views_by_day"].get(ts, {}).get("count", 0)),
                    "uniques": max(v.get("uniques", 0), repo_hist["views_by_day"].get(ts, {}).get("uniques", 0)),
                }

        for c in clones_data.get("clones", []):
            ts = c.get("timestamp", "")[:10]
            if ts:
                repo_hist["clones_by_day"][ts] = {
                    "count": max(c.get("count", 0), repo_hist["clones_by_day"].get(ts, {}).get("count", 0)),
                    "uniques": max(c.get("uniques", 0), repo_hist["clones_by_day"].get(ts, {}).get("uniques", 0)),
                }

        repo_hist["peak_unique_visitors_14d"] = max(
            repo_hist.get("peak_unique_visitors_14d", 0), views_data.get("uniques", 0)
        )
        repo_hist["peak_unique_cloners_14d"] = max(
            repo_hist.get("peak_unique_cloners_14d", 0), clones_data.get("uniques", 0)
        )

        cum_views = sum(d.get("count", 0) for d in repo_hist["views_by_day"].values())
        cum_clones = sum(d.get("count", 0) for d in repo_hist["clones_by_day"].values())

        summary[repo] = {
            "views_14d": views_data.get("count", 0),
            "unique_visitors_14d": views_data.get("uniques", 0),
            "clones_14d": clones_data.get("count", 0),
            "unique_cloners_14d": clones_data.get("uniques", 0),
            "cumulative_views": cum_views,
            "cumulative_clones": cum_clones,
        }

    try:
        with open(local_tmp, "w", encoding="utf-8") as f:
            json.dump(history, f, indent=2)
        subprocess.run(
            ["gcloud", "storage", "cp", local_tmp, gcs_uri],
            capture_output=True,
            text=True,
            timeout=15,
        )
    except Exception:
        pass

    return summary


def query_cloud_logging_usage_events(token):
    """Queries structured usage events from `projects/cm-gh-506516/logs/codemender-usage-metrics`."""
    if not token:
        return []
    payload = {
        "resourceNames": [f"projects/{PROJECT_ID}"],
        "filter": f'logName="projects/{PROJECT_ID}/logs/codemender-usage-metrics"',
        "orderBy": "timestamp desc",
        "pageSize": 500,
    }
    req = urllib.request.Request(
        "https://logging.googleapis.com/v2/entries:list",
        data=json.dumps(payload).encode("utf-8"),
        headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=20) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            return [e.get("jsonPayload", {}) for e in data.get("entries", []) if e.get("jsonPayload")]
    except Exception:
        return []


def collect_workflow_and_actor_stats(gh_env):
    """Collects workflow run counts, onboarding history, and per-Googler activity across both repos."""
    googler_stats = collections.defaultdict(lambda: {
        "cm_gh_auto_runs": 0,
        "demo_repo_runs": 0,
        "demos_built": 0,
        "demo_resets": 0,
        "chatops_commands": 0,
        "last_active": "",
        "workflows_used": set(),
    })
    workflow_totals = collections.Counter()
    onboarding_runs = []

    for repo in PRIMARY_REPOS:
        try:
            res = subprocess.run(
                [
                    "gh", "api", "--paginate", f"repos/{repo}/actions/runs",
                    "--jq", '.workflow_runs[] | {id: .id, name: .name, actor: .actor.login, event: .event, status: .status, conclusion: .conclusion, created_at: .created_at, html_url: .html_url}'
                ],
                capture_output=True,
                text=True,
                env=gh_env,
                timeout=60,
            )
            if res.returncode == 0 and res.stdout.strip():
                for line in res.stdout.strip().splitlines():
                    try:
                        run = json.loads(line)
                    except Exception:
                        continue
                    actor = run.get("actor") or "unknown"
                    if actor in BOT_LOGINS or actor.endswith("[bot]"):
                        continue
                    wf_name = run.get("name") or "Workflow"
                    created_at = (run.get("created_at") or "")[:19].replace("T", " ")

                    workflow_totals[f"{repo} :: {wf_name}"] += 1
                    st = googler_stats[actor]
                    if repo == "cloud-gtm/cm-gh-auto":
                        st["cm_gh_auto_runs"] += 1
                    else:
                        st["demo_repo_runs"] += 1

                    if "Build Demo Environment" in wf_name:
                        st["demos_built"] += 1
                        onboarding_runs.append({
                            "id": run.get("id"),
                            "actor": actor,
                            "conclusion": run.get("conclusion") or run.get("status"),
                            "created_at": created_at,
                            "url": run.get("html_url"),
                        })
                    elif "Recreate Demo" in wf_name or "Reset Demo" in wf_name:
                        st["demo_resets"] += 1
                    elif "ChatOps" in wf_name:
                        st["chatops_commands"] += 1

                    st["workflows_used"].add(wf_name)
                    if created_at > st["last_active"]:
                        st["last_active"] = created_at
        except Exception as e:
            print(f"⚠️ Warning fetching runs for {repo}: {e}", file=sys.stderr)

    return googler_stats, workflow_totals, onboarding_runs


def get_cloud_run_and_gcs_stats():
    """Counts total Cloud Run worker executions and distinct repositories scanned in GCS."""
    cloud_run_execs = 0
    try:
        res = subprocess.run(
            [
                "gcloud", "run", "jobs", "executions", "list",
                "--job=codemender-worker",
                "--region=us-west1",
                f"--project={PROJECT_ID}",
                "--format=value(name)",
            ],
            capture_output=True,
            text=True,
            timeout=20,
        )
        if res.returncode == 0:
            cloud_run_execs = len([l for l in res.stdout.strip().splitlines() if l.strip()])
    except Exception:
        pass

    scanned_repos = []
    try:
        res = subprocess.run(
            ["gcloud", "storage", "ls", f"gs://{BUCKET_NAME}/*/*"],
            capture_output=True,
            text=True,
            timeout=20,
        )
        if res.returncode == 0:
            for line in res.stdout.strip().splitlines():
                line = line.strip().rstrip("/:")
                if line.startswith(f"gs://{BUCKET_NAME}/") and "_metrics" not in line:
                    rel = line[len(f"gs://{BUCKET_NAME}/"):]
                    parts = rel.split("/")
                    if len(parts) == 2 and all(parts):
                        repo_slug = f"{parts[0]}/{parts[1]}"
                        if repo_slug not in scanned_repos:
                            scanned_repos.append(repo_slug)
    except Exception:
        pass

    return cloud_run_execs, sorted(scanned_repos)


def get_demo_repo_issue_metrics(gh_env):
    """Counts open findings, verified exploits, hunted findings, and fix PRs on codemender-actions-demo."""
    metrics = {"total_open_issues": 0, "verified": 0, "hunted": 0, "fix_ready": 0}
    try:
        res = subprocess.run(
            [
                "gh", "issue", "list", "--repo", "cloud-gtm/codemender-actions-demo",
                "--state", "open", "--limit", "200", "--json", "number,labels"
            ],
            capture_output=True,
            text=True,
            env=gh_env,
            timeout=20,
        )
        if res.returncode == 0 and res.stdout.strip():
            issues = json.loads(res.stdout)
            metrics["total_open_issues"] = len(issues)
            for iss in issues:
                lbls = {l.get("name") for l in iss.get("labels", [])}
                if "codemender:verified" in lbls:
                    metrics["verified"] += 1
                if "codemender:hunted" in lbls:
                    metrics["hunted"] += 1
                if "codemender:fix-ready" in lbls:
                    metrics["fix_ready"] += 1
    except Exception:
        pass
    return metrics


def main():
    gh_env = os.environ.copy()
    if os.environ.get("GITHUB_TOKEN") and not gh_env.get("GH_TOKEN"):
        gh_env["GH_TOKEN"] = os.environ["GITHUB_TOKEN"]

    now_str = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    token = get_gcloud_token()

    traffic = load_and_update_traffic_history(gh_env)
    googler_stats, workflow_totals, onboarding_runs = collect_workflow_and_actor_stats(gh_env)
    usage_events = query_cloud_logging_usage_events(token)
    cloud_run_execs, scanned_repos = get_cloud_run_and_gcs_stats()
    issue_metrics = get_demo_repo_issue_metrics(gh_env)

    # Enrich googler_stats from Cloud Logging custom usage events (captures activity inside personal forks too!)
    custom_onboard_events = []
    for ev in usage_events:
        actor = ev.get("actor") or ""
        if actor and actor not in BOT_LOGINS and not actor.endswith("[bot]") and actor != "automated":
            st = googler_stats[actor]
            ts = (ev.get("timestamp") or "")[:19].replace("T", " ")
            if ts > st["last_active"]:
                st["last_active"] = ts
        if ev.get("event_type") == "demo_environment_created":
            custom_onboard_events.append(ev)

    total_unique_googlers = len(googler_stats)
    total_demos_built = sum(s["demos_built"] for s in googler_stats.values())
    total_demo_resets = sum(s["demo_resets"] for s in googler_stats.values())
    total_chatops = sum(s["chatops_commands"] for s in googler_stats.values())

    lines = [
        "# 📊 CodeMender GitHub Demo & Automation — Impact & Adoption Report",
        f"*Last Updated: `{now_str}`*",
        "",
        "## 🎯 Executive Summary (KPIs)",
        "",
        "| Impact Metric | Value | Source / Scope |",
        "| :--- | :--- | :--- |",
        f"| **👥 Active Googlers (Builders & Presenters)** | **`{total_unique_googlers}`** | Unique Googlers triggering workflows across `cm-gh-auto` & `codemender-actions-demo` |",
        f"| **🏗️ Personal Demo Environments Built** | **`{total_demos_built}`** | `Build Demo Environment (Fork & Setup)` runs |",
        f"| **🔄 Live Customer Demo Resets** | **`{total_demo_resets}`** | `Recreate Demo Environment` / `Reset Demo` runs |",
        f"| **💬 Interactive ChatOps Commands (`/cm`)** | **`{total_chatops}`** | `/cm verify`, `/cm hunt`, `/cm fix` executions on issues |",
        f"| **☁️ Cloud Run AI Worker Executions** | **`{cloud_run_execs}+`** | `codemender-worker` jobs executed in `cm-gh-506516` |",
        f"| **📦 Repositories Scanned & Staged in GCS** | **`{len(scanned_repos)}`** | Distinct repositories in `gs://{BUCKET_NAME}/` |",
        f"| **🛡️ Live Demo Repo Findings (`codemender-actions-demo`)** | **`{issue_metrics['total_open_issues']}` open** (`{issue_metrics['verified']}` verified, `{issue_metrics['hunted']}` hunted, `{issue_metrics['fix_ready']}` fix-ready) | Active issues on `cloud-gtm/codemender-actions-demo` |",
        "",
        "---",
        "",
        "## 📈 Repository Traffic & Engagement (`Views` & `Clones`)",
        "> *Note: GitHub's API exposes a rolling 14-day window; daily snapshots are automatically archived to `gs://codemender-artifacts-cm-gh-506516/_metrics/traffic-history.json` to preserve all-time cumulative totals.*",
        "",
        "| Repository | 14-Day Views | 14-Day Unique Visitors | 14-Day Git Clones | 14-Day Unique Cloners | All-Time Tracked Views | All-Time Tracked Clones |",
        "| :--- | :--- | :--- | :--- | :--- | :--- | :--- |",
    ]

    for repo in PRIMARY_REPOS:
        t = traffic.get(repo, {})
        lines.append(
            f"| [`{repo}`](https://github.com/{repo}) | **`{t.get('views_14d', 0)}`** | **`{t.get('unique_visitors_14d', 0)}`** | "
            f"**`{t.get('clones_14d', 0)}`** | **`{t.get('unique_cloners_14d', 0)}`** | "
            f"`{t.get('cumulative_views', 0)}` | `{t.get('cumulative_clones', 0)}` |"
        )

    lines.extend([
        "",
        "---",
        "",
        "## 👥 Googler Adoption & Activity Leaderboard",
        "",
        "| Googler (`@github`) | `cm-gh-auto` Runs | `codemender-actions-demo` Runs | Demos Built | Demo Resets | `/cm` ChatOps | Last Active (UTC) |",
        "| :--- | :--- | :--- | :--- | :--- | :--- | :--- |",
    ])

    sorted_googlers = sorted(
        googler_stats.items(),
        key=lambda kv: (kv[1]["demos_built"] + kv[1]["cm_gh_auto_runs"] + kv[1]["demo_repo_runs"]),
        reverse=True,
    )
    for user, st in sorted_googlers:
        lines.append(
            f"| [`@{user}`](https://github.com/{user}) | `{st['cm_gh_auto_runs']}` | `{st['demo_repo_runs']}` | "
            f"**`{st['demos_built']}`** | `{st['demo_resets']}` | `{st['chatops_commands']}` | `{st['last_active']}` |"
        )

    lines.extend([
        "",
        "---",
        "",
        "## 🏗️ Recent Personal Demo Environment Builds (`onboard-repo.yml`)",
        "",
        "| Timestamp (UTC) | Googler | Status | Run Link |",
        "| :--- | :--- | :--- | :--- |",
    ])
    for ob in onboarding_runs[:15]:
        badge = "✅ `success`" if ob["conclusion"] == "success" else f"⚠️ `{ob['conclusion']}`"
        lines.append(
            f"| `{ob['created_at']}` | [`@{ob['actor']}`](https://github.com/{ob['actor']}) | {badge} | [View Run #{ob['id']}]({ob['url']}) |"
        )

    if custom_onboard_events:
        lines.extend([
            "",
            "### 🏷️ Tagged Customer / Demo Contexts (from Cloud Logging `codemender-usage-metrics`)",
            "",
            "| Timestamp | Googler | Source Repo | Personal Target Repo | Customer / Demo Context |",
            "| :--- | :--- | :--- | :--- | :--- |",
        ])
        for ev in custom_onboard_events[:20]:
            lines.append(
                f"| `{ev.get('timestamp', '')[:19]}` | `@{ev.get('actor', '')}` | `{ev.get('source_repo', '')}` | "
                f"[`{ev.get('target_repo', '')}`](https://github.com/{ev.get('target_repo', '')}) | **`{ev.get('demo_context', 'unspecified')}`** |"
            )

    lines.extend([
        "",
        "---",
        "",
        "## 📦 Repositories Scanned by CodeMender Cloud Run Worker",
        "",
        ", ".join(f"[`{r}`](https://github.com/{r})" for r in scanned_repos) if scanned_repos else "_No repositories recorded yet._",
        "",
    ])

    report_md = "\n".join(lines)
    print(report_md)

    out_path = os.environ.get("IMPACT_REPORT_PATH", "")
    if out_path:
        with open(out_path, "w", encoding="utf-8") as f:
            f.write(report_md + "\n")

    step_summary = os.environ.get("GITHUB_STEP_SUMMARY", "")
    if step_summary:
        with open(step_summary, "a", encoding="utf-8") as f:
            f.write(report_md + "\n")


if __name__ == "__main__":
    main()
