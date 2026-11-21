import argparse
from datetime import date
from ingest import load_trivy
from enrich import enrich
from prioritize import prioritize
from db import connect, upsert_scan, summary
from export import export
from remediate import build_plan, print_plan, apply_auto

TOTAL = 6

def step(n: int, msg: str) -> None:
    print(f"\n[{n}/{TOTAL}] {msg}", flush=True)

def main() -> None:
    ap = argparse.ArgumentParser(description="Patch Pilot: vulnerability-to-patch pipeline")
    ap.add_argument("--scan", default="data/scan_demo.json", help="Trivy JSON report")
    ap.add_argument("--date", default=date.today().isoformat(), help="scan date (YYYY-MM-DD)")
    ap.add_argument("--apply", action="store_true", help="create the remediation branch")
    args = ap.parse_args()

    step(1, f"Ingesting {args.scan}")
    findings = load_trivy(args.scan)
    print(f"    {len(findings)} findings")

    step(2, "Enriching with CISA KEV and EPSS")
    findings = enrich(findings)
    print(f"    {sum(f.in_kev for f in findings)} in KEV")

    step(3, "Prioritizing")
    prioritize(findings)
    tiers = {}
    for f in findings:
        tiers[f.priority] = tiers.get(f.priority, 0) + 1
    print(f"    {dict(sorted(tiers.items()))}")

    step(4, "Storing results and computing metrics")
    conn = connect()
    upsert_scan(conn, findings, args.date)
    summary(conn, args.date)

    step(5, "Exporting data for the dashboard")
    export(args.date)

    step(6, "Planning remediation")
    plan = build_plan(findings)
    print_plan(plan)
    if args.apply:
        apply_auto(plan)
    else:
        print("\nDry run. Add --apply to create the remediation branch.")

if __name__ == "__main__":
    main()