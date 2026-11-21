import re
import subprocess
import sys
from datetime import date
from ingest import load_trivy
from enrich import enrich
from prioritize import prioritize, _version_key

REQ = "demo-app/requirements.txt"

def norm(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name.lower())

def git(*args) -> str:
    r = subprocess.run(["git", *args], capture_output=True, text=True, check=True)
    return r.stdout.strip()

def pick_fix(installed: str, fixed: str) -> str:
    """Trivy may list several fixed versions; prefer the lowest one in the same major version."""
    cands = [c.strip() for c in fixed.split(",") if c.strip()]
    same = [c for c in cands if _version_key(c)[0] == _version_key(installed)[0]]
    return min(same or cands, key=_version_key)

def bump_type(old: str, new: str) -> str:
    o, n = _version_key(old), _version_key(new)
    if o[0] != n[0]:
        return "major"
    return "minor" if o[1:2] != n[1:2] else "patch"

def build_plan(findings) -> list[dict]:
    pkgs = {}
    for f in findings:
        d = pkgs.setdefault(norm(f.package), {"name": f.package, "installed": f.installed_version,
                                              "targets": [], "cves": set(), "priority": "P3"})
        d["cves"].add(f.cve_id)
        d["priority"] = min(d["priority"], f.priority)
        if f.fixed_version:
            d["targets"].append(pick_fix(f.installed_version, f.fixed_version))
    plan = []
    for key, d in pkgs.items():
        if d["targets"]:
            target = max(d["targets"], key=_version_key)
            bump = bump_type(d["installed"], target)
            action = "REVIEW" if bump == "major" else "AUTO"
        else:
            target, bump, action = None, "-", "MANUAL"
        plan.append({**d, "key": key, "target": target, "bump": bump,
                     "action": action, "cve_count": len(d["cves"])})
    return sorted(plan, key=lambda p: (p["priority"], -p["cve_count"]))

def print_plan(plan) -> None:
    print(f"{'ACTION':7} {'PKG':12} {'FROM':10} {'TO':10} {'BUMP':6} {'TIER':4} CVES")
    for p in plan:
        print(f"{p['action']:7} {p['name']:12} {p['installed']:10} {str(p['target']):10} "
              f"{p['bump']:6} {p['priority']:4} {p['cve_count']}")

def pr_body(plan) -> str:
    out = ["## PatchPilot automated dependency upgrades", "",
           "| Package | From | To | Bump | Tier | CVEs fixed |", "|---|---|---|---|---|---|"]
    for p in plan:
        if p["action"] == "AUTO":
            out.append(f"| {p['name']} | {p['installed']} | {p['target']} | {p['bump']} | "
                       f"{p['priority']} | {p['cve_count']} |")
    held = [p for p in plan if p["action"] != "AUTO"]
    if held:
        out += ["", "### Not included (needs a human)"]
        for p in held:
            why = "major upgrade, possible breaking changes" if p["action"] == "REVIEW" else "no fix available"
            out.append(f"- {p['name']} {p['installed']}: {why} ({p['cve_count']} CVEs, {p['priority']})")
    out += ["", "### Merge gate", "- [ ] CI tests pass", "- [ ] Re-scan shows the listed CVEs resolved"]
    return "\n".join(out) + "\n"

def apply_auto(plan) -> None:
    auto = {p["key"]: p for p in plan if p["action"] == "AUTO"}
    if not auto:
        print("Nothing eligible for automatic upgrade.")
        return
    if git("status", "--porcelain"):
        sys.exit("Working tree is not clean. Commit or stash your changes first.")
    original = git("rev-parse", "--abbrev-ref", "HEAD")
    branch = f"patchpilot/auto-{date.today().isoformat()}"
    git("checkout", "-b", branch)
    lines = []
    with open(REQ, encoding="utf-8") as fh:
        for line in fh.read().splitlines():
            m = re.match(r"^([A-Za-z0-9_.\-]+)==(\S+)$", line.strip())
            if m and norm(m.group(1)) in auto:
                line = f"{m.group(1)}=={auto[norm(m.group(1))]['target']}"
            lines.append(line)
    with open(REQ, "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines) + "\n")
    git("add", REQ)
    git("commit", "-m", f"PatchPilot: upgrade {len(auto)} vulnerable dependencies")
    with open(f"data/pr_{date.today().isoformat()}.md", "w", encoding="utf-8") as fh:
        fh.write(pr_body(plan))
    git("checkout", original)
    print(f"Created branch {branch} with {len(auto)} upgrades. PR text: data/pr_{date.today().isoformat()}.md")

if __name__ == "__main__":
    fs = prioritize(enrich(load_trivy("data/scan_demo.json")))
    plan = build_plan(fs)
    print_plan(plan)
    if "--apply" in sys.argv:
        apply_auto(plan)
    else:
        print("\nDry run. Add --apply to create the branch.")