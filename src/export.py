import csv
from datetime import date
from db import connect
from prioritize import SLA_DAYS

def export(today: str) -> None:
    conn = connect()
    today_d = date.fromisoformat(today)
    rows = conn.execute("SELECT * FROM findings").fetchall()

    with open("data/findings.csv", "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["asset", "cve_id", "package", "installed_version", "fixed_version", "severity",
                    "priority", "reason", "in_kev", "epss", "first_seen", "last_seen", "resolved_at",
                    "status", "age_days", "sla_days", "sla_breached"])
        for r in rows:
            end = date.fromisoformat(r["resolved_at"]) if r["resolved_at"] else today_d
            age = (end - date.fromisoformat(r["first_seen"])).days
            sla = SLA_DAYS[r["priority"]]
            w.writerow([r["asset"], r["cve_id"], r["package"], r["installed_version"],
                        r["fixed_version"] or "", r["severity"], r["priority"], r["reason"],
                        r["in_kev"], r["epss"], r["first_seen"], r["last_seen"], r["resolved_at"] or "",
                        "Resolved" if r["resolved_at"] else "Open", age, sla, int(age > sla)])

    dates = sorted({r["first_seen"] for r in rows}
                   | {r["resolved_at"] for r in rows if r["resolved_at"]}
                   | {today})
    trend = [(d, sum(1 for r in rows
                     if r["first_seen"] <= d and (r["resolved_at"] is None or r["resolved_at"] > d)))
             for d in dates]

    with open("data/trend.csv", "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["date", "open_count"])
        w.writerows(trend)
    print("Wrote data/findings.csv and data/trend.csv")

if __name__ == "__main__":
    export(date.today().isoformat())