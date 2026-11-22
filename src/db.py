import sqlite3
import sys
from datetime import date
from models import Finding
from ingest import load_trivy
from enrich import enrich
from prioritize import prioritize, SLA_DAYS

DB = "data/patchpilot.db"

SCHEMA = """
CREATE TABLE IF NOT EXISTS findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    asset TEXT NOT NULL,
    cve_id TEXT NOT NULL,
    package TEXT NOT NULL,
    installed_version TEXT,
    fixed_version TEXT,
    severity TEXT,
    priority TEXT,
    reason TEXT,
    in_kev INTEGER,
    epss REAL,
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL,
    resolved_at TEXT,
    UNIQUE(asset, cve_id, package)
);

CREATE TABLE IF NOT EXISTS runs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    started_at TEXT NOT NULL,
    finished_at TEXT,
    status TEXT NOT NULL,
    repos_total INTEGER,
    repos_ok INTEGER,
    open_total INTEGER,
    new_count INTEGER,
    resolved_count INTEGER,
    notes TEXT
);
"""

def connect() -> sqlite3.Connection:
    conn = sqlite3.connect(DB)
    conn.row_factory = sqlite3.Row
    conn.executescript(SCHEMA)
    return conn

def upsert_scan(conn, findings: list[Finding], scan_date: str, assets: set[str] | None = None) -> None:
    seen = set()
    for f in findings:
        seen.add((f.asset, f.cve_id, f.package))
        conn.execute("""
            INSERT INTO findings (asset, cve_id, package, installed_version, fixed_version,
                                  severity, priority, reason, in_kev, epss, first_seen, last_seen)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(asset, cve_id, package) DO UPDATE SET
                installed_version=excluded.installed_version,
                fixed_version=excluded.fixed_version,
                severity=excluded.severity,
                priority=excluded.priority,
                reason=excluded.reason,
                in_kev=excluded.in_kev,
                epss=excluded.epss,
                last_seen=excluded.last_seen,
                resolved_at=NULL
        """, (f.asset, f.cve_id, f.package, f.installed_version, f.fixed_version,
              f.severity, f.priority, f.reason, int(f.in_kev), f.epss, scan_date, scan_date))
    # anything open for these assets that is missing from this scan is considered fixed
    for asset in (assets if assets is not None else {f.asset for f in findings}):
        rows = conn.execute(
            "SELECT id, cve_id, package FROM findings WHERE asset=? AND resolved_at IS NULL", (asset,)
        ).fetchall()
        for r in rows:
            if (asset, r["cve_id"], r["package"]) not in seen:
                conn.execute("UPDATE findings SET resolved_at=? WHERE id=?", (scan_date, r["id"]))
    conn.commit()

def summary(conn, today: str) -> None:
    print("Open findings by priority:")
    for r in conn.execute("""SELECT priority, COUNT(*) AS n FROM findings
                             WHERE resolved_at IS NULL GROUP BY priority ORDER BY priority"""):
        print(f"  {r['priority']}: {r['n']}")

    today_d = date.fromisoformat(today)
    breaches = {}
    for r in conn.execute("SELECT priority, first_seen FROM findings WHERE resolved_at IS NULL"):
        age = (today_d - date.fromisoformat(r["first_seen"])).days
        if age > SLA_DAYS[r["priority"]]:
            breaches[r["priority"]] = breaches.get(r["priority"], 0) + 1
    print("SLA breaches:", dict(sorted(breaches.items())) or "none")

    row = conn.execute("""SELECT COUNT(*) AS n,
                                 AVG(julianday(resolved_at) - julianday(first_seen)) AS mttr
                          FROM findings WHERE resolved_at IS NOT NULL""").fetchone()
    mttr = f"{row['mttr']:.1f} days" if row["n"] else "n/a (nothing resolved yet)"
    print(f"Resolved: {row['n']} | MTTR: {mttr}")

if __name__ == "__main__":
    scan_date = sys.argv[1] if len(sys.argv) > 1 else date.today().isoformat()
    path = sys.argv[2] if len(sys.argv) > 2 else "data/scan.json"
    fs = prioritize(enrich(load_trivy(path)))
    conn = connect()
    upsert_scan(conn, fs, scan_date)
    summary(conn, scan_date)