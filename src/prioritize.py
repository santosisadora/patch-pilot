import re
from collections import defaultdict
from models import Finding

SLA_DAYS = {"P0": 3, "P1": 7, "P2": 30, "P3": 90}

def score(f: Finding) -> None:
    fixable = f.fixed_version is not None
    if f.in_kev:
        f.priority = "P0"
        f.reason = "Actively exploited (CISA KEV)" + ("" if fixable else "; no fix available, mitigate")
    elif f.epss >= 0.5:
        f.priority = "P1"
        f.reason = f"Very high exploit probability (EPSS {f.epss:.2f})"
    elif f.severity == "CRITICAL" and f.epss >= 0.1:
        f.priority = "P1"
        f.reason = f"Critical severity and elevated EPSS ({f.epss:.2f})"
    elif f.severity in ("CRITICAL", "HIGH") or f.epss >= 0.1:
        f.priority = "P2"
        f.reason = f"{f.severity} severity, EPSS {f.epss:.2f}"
    else:
        f.priority = "P3"
        f.reason = f"Low exploit likelihood (EPSS {f.epss:.3f})"

def _version_key(v: str):
    return [int(p) if p.isdigit() else 0 for p in re.split(r"[.\-+~:]", v)]

def group_by_package(findings: list[Finding]) -> list[dict]:
    groups = defaultdict(list)
    for f in findings:
        groups[(f.asset, f.package, f.installed_version)].append(f)
    out = []
    for (asset, pkg, installed), fs in groups.items():
        fixes = [f.fixed_version for f in fs if f.fixed_version]
        target = max(fixes, key=_version_key) if fixes else None
        top = min(fs, key=lambda x: x.priority)  # "P0" < "P1" < ...
        out.append({
            "asset": asset, "package": pkg, "installed": installed,
            "target_version": target, "cve_count": len(fs),
            "priority": top.priority, "reason": top.reason,
            "sla_days": SLA_DAYS[top.priority],
        })
    return sorted(out, key=lambda g: (g["priority"], -g["cve_count"]))

def prioritize(findings: list[Finding]) -> list[Finding]:
    for f in findings:
        score(f)
    return findings

if __name__ == "__main__":
    from ingest import load_trivy
    from enrich import enrich
    fs = prioritize(enrich(load_trivy("data/scan.json")))
    tiers = defaultdict(int)
    for f in fs:
        tiers[f.priority] += 1
    print("Findings per tier:", dict(sorted(tiers.items())))
    print("\nTop 10 upgrade actions:")
    for g in group_by_package(fs)[:10]:
        print(f"{g['priority']} {g['package']:20} {g['installed']:>14} -> {str(g['target_version']):>14} "
              f"fixes {g['cve_count']} CVEs | SLA {g['sla_days']}d | {g['reason']}")