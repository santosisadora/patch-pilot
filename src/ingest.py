import json
from models import Finding

def load_trivy(path: str) -> list[Finding]:
    with open(path) as f:
        data = json.load(f)
    asset = data.get("ArtifactName", "unknown")
    findings = []
    for result in data.get("Results", []):
        for v in result.get("Vulnerabilities") or []:
            findings.append(Finding(
                cve_id=v["VulnerabilityID"],
                package=v["PkgName"],
                installed_version=v["InstalledVersion"],
                fixed_version=v.get("FixedVersion"),
                severity=v.get("Severity", "UNKNOWN"),
                asset=asset,
            ))
    return findings

if __name__ == "__main__":
    fs = load_trivy("data/scan.json")
    print(f"{len(fs)} findings")
    no_fix = sum(1 for f in fs if not f.fixed_version)
    print(f"{no_fix} with no fixed version")
    counts = {}
    for f in fs:
        counts[f.severity] = counts.get(f.severity, 0) + 1
    print(counts)
    for f in fs[:5]:
        print(f)