import argparse
import json
import os
import shutil
import stat
import subprocess
import sys
import tempfile
from datetime import date, datetime, timezone

from db import connect, upsert_scan, summary
from enrich import enrich
from ingest import parse_trivy
from models import Finding
from prioritize import prioritize

def sh(cmd: list[str], timeout: int) -> str:
    env = {**os.environ, "GIT_TERMINAL_PROMPT": "0"}
    r = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8", errors="replace",
                       timeout=timeout, env=env)
    if r.returncode != 0:
        raise RuntimeError((r.stderr or r.stdout).strip()[-300:] or f"exit code {r.returncode}")
    return r.stdout

def run_trivy(path: str) -> dict:
    if shutil.which("trivy"):
        cmd = ["trivy", "fs", "--quiet", "--scanners", "vuln", "--format", "json", path]
    else:
        cache = os.path.abspath(".trivy-cache")
        os.makedirs(cache, exist_ok=True)
        cmd = ["docker", "run", "--rm", "-v", f"{path}:/src:ro", "-v", f"{cache}:/root/.cache/",
               "aquasec/trivy:latest", "fs", "--quiet", "--scanners", "vuln", "--format", "json", "/src"]
    return json.loads(sh(cmd, timeout=1200))

def _force_remove(func, path, _exc):
    os.chmod(path, stat.S_IWRITE)
    func(path)

def scan_repo(repo: str) -> list[Finding]:
    tmp = tempfile.mkdtemp(prefix="pp-")
    try:
        dest = os.path.join(tmp, "src")
        sh(["git", "clone", "--depth", "1", "--quiet", f"https://github.com/{repo}.git", dest], timeout=300)
        data = run_trivy(dest)
        if not data.get("Results"):
            raise RuntimeError("no supported dependency files found (is there a lockfile?)")
        return parse_trivy(data, asset=repo)
    finally:
        shutil.rmtree(tmp, onerror=_force_remove)
def read_repos(path: str) -> list[str]:
    with open(path, encoding="utf-8") as f:
        return [l.strip() for l in f if l.strip() and not l.startswith("#")]

def open_keys(conn, assets: set[str]) -> set[tuple]:
    if not assets:
        return set()
    marks = ",".join("?" * len(assets))
    rows = conn.execute(
        f"SELECT asset, cve_id, package FROM findings WHERE resolved_at IS NULL AND asset IN ({marks})",
        tuple(assets))
    return {(r["asset"], r["cve_id"], r["package"]) for r in rows}

def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")

def main() -> None:
    ap = argparse.ArgumentParser(description="Scan a list of repos and record the run")
    ap.add_argument("--repos", default="repos.txt")
    ap.add_argument("--only", help="scan just this owner/name (for testing)")
    ap.add_argument("--date", default=date.today().isoformat())
    args = ap.parse_args()

    repos = [args.only] if args.only else read_repos(args.repos)
    os.makedirs("data", exist_ok=True)
    conn = connect()
    run_id = conn.execute("INSERT INTO runs (started_at, status, repos_total) VALUES (?, 'running', ?)",
                          (now_iso(), len(repos))).lastrowid
    conn.commit()

    ok: list[str] = []
    failed: dict[str, str] = {}
    all_findings: list[Finding] = []
    status, notes = "failed", ""
    new = fixed = open_total = 0
    try:
        for repo in repos:
            print(f"Scanning {repo} ...", flush=True)
            try:
                fs = scan_repo(repo)
            except Exception as e:
                failed[repo] = str(e)
                print(f"  FAILED: {e}", flush=True)
                continue
            ok.append(repo)
            all_findings.extend(fs)
            print(f"  {len(fs)} findings", flush=True)

        before = open_keys(conn, set(ok))
        if all_findings:
            all_findings = prioritize(enrich(all_findings))
        upsert_scan(conn, all_findings, args.date, assets=set(ok))
        after = open_keys(conn, set(ok))
        new, fixed = len(after - before), len(before - after)
        open_total = conn.execute("SELECT COUNT(*) FROM findings WHERE resolved_at IS NULL").fetchone()[0]
        status = "failed" if not ok else ("partial" if failed else "success")
        notes = "; ".join(f"{r}: {m}" for r, m in failed.items())[:500]
    except Exception as e:
        notes = f"crash: {e}"[:500]
        raise
    finally:
        conn.execute("""UPDATE runs SET finished_at=?, status=?, repos_ok=?, open_total=?,
                        new_count=?, resolved_count=?, notes=? WHERE id=?""",
                     (now_iso(), status, len(ok), open_total, new, fixed, notes, run_id))
        conn.commit()

    print(f"\nRun {run_id}: {status} | repos ok {len(ok)}/{len(repos)} | open {open_total} | new {new} | fixed {fixed}")
    summary(conn, args.date)
    if status == "failed":
        sys.exit(1)

if __name__ == "__main__":
    main()