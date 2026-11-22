import json
from models import Finding

def parse_trivy(data: dict, asset: str | None = None) -> list[Finding]:
    asset = asset or data.get("ArtifactName", "unknown")
    findings = []
    for result in data.get("Results") or []:
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

def load_trivy(path: str) -> list[Finding]:
    with open(path, encoding="utf-8") as f:
        return parse_trivy(json.load(f))

if __name__ == "__main__":
    fs = load_trivy("data/scan.json")
    print(f"{len(fs)} findings")
    counts = {}
    for f in fs:
        counts[f.severity] = counts.get(f.severity, 0) + 1
    print(counts)