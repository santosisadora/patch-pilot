import json
import os
import requests
from models import Finding

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_URL = "https://api.first.org/data/v1/epss"
KEV_CACHE = "data/kev.json"

def load_kev() -> set[str]:
    if not os.path.exists(KEV_CACHE):
        r = requests.get(KEV_URL, timeout=30)
        r.raise_for_status()
        with open(KEV_CACHE, "w") as f:
            f.write(r.text)
    with open(KEV_CACHE) as f:
        data = json.load(f)
    return {v["cveID"] for v in data["vulnerabilities"]}

def fetch_epss(cve_ids: list[str], chunk_size: int = 50) -> dict[str, tuple[float, float]]:
    scores = {}
    for i in range(0, len(cve_ids), chunk_size):
        chunk = cve_ids[i:i + chunk_size]
        r = requests.get(EPSS_URL, params={"cve": ",".join(chunk)}, timeout=30)
        r.raise_for_status()
        for row in r.json().get("data", []):
            scores[row["cve"]] = (float(row["epss"]), float(row["percentile"]))
    return scores

def enrich(findings: list[Finding]) -> list[Finding]:
    kev = load_kev()
    unique_cves = sorted({f.cve_id for f in findings})
    epss = fetch_epss(unique_cves)
    for f in findings:
        f.in_kev = f.cve_id in kev
        f.epss, f.epss_percentile = epss.get(f.cve_id, (0.0, 0.0))
    return findings

if __name__ == "__main__":
    from ingest import load_trivy
    fs = enrich(load_trivy("data/scan.json"))
    print(f"{sum(f.in_kev for f in fs)} findings in KEV")
    print("Top 10 by EPSS:")
    for f in sorted(fs, key=lambda x: x.epss, reverse=True)[:10]:
        print(f"{f.cve_id:18} {f.package:20} sev={f.severity:8} epss={f.epss:.3f} kev={f.in_kev}")