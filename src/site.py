import html
import os
from datetime import date

from db import connect
from prioritize import SLA_DAYS
from scan_repos import read_repos

esc = html.escape
STATUS_COLORS = {"success": "#1f9d55", "partial": "#d98a00", "failed": "#d64545", "running": "#6b7685"}

CSS = """
:root{--bg:#f6f7f9;--card:#fff;--ink:#1c2430;--mute:#6b7685;--line:#e6e9ee}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--ink);font:15px/1.5 system-ui,"Segoe UI",sans-serif}
.wrap{max-width:1040px;margin:0 auto;padding:28px 20px 60px}
header{margin-bottom:20px}
h1{margin:0 0 4px;font-size:26px}
.sub{color:var(--mute);font-size:13px}
.badge{display:inline-block;padding:2px 10px;border-radius:99px;font-size:12px;font-weight:600;color:#fff}
.banner{display:none;background:#fdecec;border:1px solid #f3b9b9;color:#8a1f1f;padding:10px 14px;border-radius:8px;margin-bottom:16px;font-weight:600}
.tiles{display:grid;grid-template-columns:repeat(auto-fit,minmax(130px,1fr));gap:12px;margin-bottom:20px}
.tile{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:14px 16px}
.tile .v{font-size:28px;font-weight:650;line-height:1.2}
.tile .k{font-size:11px;color:var(--mute);text-transform:uppercase;letter-spacing:.05em}
.card{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:16px 18px;margin-bottom:18px}
h2{font-size:15px;margin:0 0 12px}
table{border-collapse:collapse;width:100%;font-size:13px}
th{color:var(--mute);font-weight:600;text-align:left;font-size:12px}
th,td{padding:7px 8px;border-bottom:1px solid var(--line)}
tr:last-child td{border-bottom:0}
.num{text-align:right;font-variant-numeric:tabular-nums}
.row{display:flex;align-items:center;gap:10px;margin:6px 0;font-size:13px}
.lbl{width:110px;color:var(--mute)}
.bar{height:12px;border-radius:6px;background:#2c7be5}
.pill{display:inline-block;padding:1px 8px;border-radius:99px;font-size:12px;font-weight:600;color:#fff}
.p0{background:#d64545}.p1{background:#e8743b}.p2{background:#d9a300}.p3{background:#8a94a3}
.mono{font-family:ui-monospace,Consolas,monospace;font-size:12px}
.mute{color:var(--mute)}
footer{color:var(--mute);font-size:12px;margin-top:24px}
"""

def fmt_ts(iso):
    return (iso or "").replace("T", " ")[:16] + " UTC" if iso else "-"

def pill(tier):
    return f'<span class="pill {esc(tier.lower())}">{esc(tier)}</span>'

def badge(status):
    return f'<span class="badge" style="background:{STATUS_COLORS.get(status, "#6b7685")}">{esc(status)}</span>'

def bars(pairs):
    top = max([n for _, n in pairs] + [1])
    return "".join(
        f'<div class="row"><span class="lbl">{esc(str(l))}</span>'
        f'<div class="bar" style="width:{max(n / top * 60, 0.5):.1f}%"></div><span>{n}</span></div>'
        for l, n in pairs)

def collect(conn, repos):
    today = date.today()
    last_run = conn.execute("SELECT * FROM runs ORDER BY id DESC LIMIT 1").fetchone()
    last_ok = conn.execute("SELECT finished_at FROM runs WHERE status IN ('success','partial') "
                           "ORDER BY id DESC LIMIT 1").fetchone()
    open_rows = conn.execute("SELECT priority, first_seen, in_kev FROM findings WHERE resolved_at IS NULL").fetchall()
    tiers = {p: 0 for p in SLA_DAYS}
    breaches = 0
    for r in open_rows:
        tiers[r["priority"]] = tiers.get(r["priority"], 0) + 1
        if (today - date.fromisoformat(r["first_seen"])).days > SLA_DAYS.get(r["priority"], 90):
            breaches += 1
    mttr = conn.execute("SELECT COUNT(*) AS n, AVG(julianday(resolved_at) - julianday(first_seen)) AS m "
                        "FROM findings WHERE resolved_at IS NOT NULL").fetchone()
    per_repo = {r["asset"]: r for r in conn.execute("""
        SELECT asset,
               SUM(resolved_at IS NULL) AS open_n,
               SUM(resolved_at IS NULL AND priority='P0') AS p0,
               SUM(resolved_at IS NULL AND priority='P1') AS p1,
               SUM(resolved_at IS NULL AND priority='P2') AS p2,
               SUM(resolved_at IS NULL AND priority='P3') AS p3,
               SUM(resolved_at IS NOT NULL) AS fixed_n
        FROM findings GROUP BY asset""")}
    return {
        "last_run": last_run, "last_ok": last_ok["finished_at"] if last_ok else "",
        "open": len(open_rows), "tiers": tiers, "breaches": breaches,
        "kev_open": sum(r["in_kev"] or 0 for r in open_rows),
        "resolved": mttr["n"], "mttr": mttr["m"],
        "repos": list(dict.fromkeys(repos + list(per_repo))), "per_repo": per_repo,
        "runs": conn.execute("SELECT * FROM runs ORDER BY id DESC LIMIT 14").fetchall(),
        "top": conn.execute("""SELECT asset, package, installed_version, fixed_version, cve_id, priority, epss
                               FROM findings WHERE resolved_at IS NULL
                               ORDER BY priority, epss DESC LIMIT 15""").fetchall(),
    }

def render(d):
    lr = d["last_run"]
    if lr:
        head = (f'Last run {badge(lr["status"])} {esc(fmt_ts(lr["finished_at"] or lr["started_at"]))}'
                f' &middot; {lr["repos_ok"] or 0}/{lr["repos_total"]} repos scanned')
        new, fixed = lr["new_count"] or 0, lr["resolved_count"] or 0
    else:
        head, new, fixed = "No runs recorded yet", 0, 0
    mttr = f'{d["mttr"]:.1f} d' if d["resolved"] else "n/a"
    tiles = [("Open findings", d["open"]), ("New (last run)", new), ("Fixed (last run)", fixed),
             ("Fixed all time", d["resolved"]), ("Open in KEV", d["kev_open"]),
             ("SLA breaches", d["breaches"]), ("MTTR", mttr)]
    tiles_html = "".join(f'<div class="tile"><div class="v">{v}</div><div class="k">{k}</div></div>' for k, v in tiles)

    repo_rows = ""
    for repo in d["repos"]:
        r = d["per_repo"].get(repo)
        vals = [r[k] or 0 for k in ("open_n", "p0", "p1", "p2", "p3", "fixed_n")] if r else [0] * 6
        repo_rows += f'<tr><td>{esc(repo)}</td>' + "".join(f'<td class="num">{v}</td>' for v in vals) + "</tr>"

    top_rows = "".join(
        f'<tr><td>{esc(r["asset"].split("/")[-1])}</td><td>{esc(r["package"])}</td>'
        f'<td class="mono">{esc(r["installed_version"] or "")}</td>'
        f'<td class="mono">{esc(r["fixed_version"] or "no fix")}</td>'
        f'<td class="mono">{esc(r["cve_id"])}</td><td>{pill(r["priority"])}</td>'
        f'<td class="num">{(r["epss"] or 0) * 100:.0f}%</td></tr>' for r in d["top"])

    run_rows = "".join(
        f'<tr><td>{r["id"]}</td><td>{esc(fmt_ts(r["finished_at"] or r["started_at"]))}</td><td>{badge(r["status"])}</td>'
        f'<td class="num">{r["repos_ok"] or 0}/{r["repos_total"] or 0}</td><td class="num">{r["open_total"] or 0}</td>'
        f'<td class="num">{r["new_count"] or 0}</td><td class="num">{r["resolved_count"] or 0}</td>'
        f'<td class="mute">{esc(r["notes"] or "")}</td></tr>' for r in d["runs"])

    trend = bars([(f'run {r["id"]}', r["open_total"] or 0) for r in reversed(d["runs"])])

    return f"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>Patch Pilot status</title>
<style>{CSS}</style></head><body data-last-ok="{esc(d['last_ok'])}"><div class="wrap">
<header><h1>Patch Pilot</h1><div class="sub">{head}</div></header>
<div id="stale" class="banner"></div>
<div class="tiles">{tiles_html}</div>
<div class="card"><h2>Open findings by priority</h2>{bars([(k, v) for k, v in sorted(d['tiers'].items())])}</div>
<div class="card"><h2>Repositories</h2><table><tr><th>Repository</th><th class="num">Open</th><th class="num">P0</th>
<th class="num">P1</th><th class="num">P2</th><th class="num">P3</th><th class="num">Fixed</th></tr>{repo_rows}</table></div>
<div class="card"><h2>Fix these first</h2><table><tr><th>Repo</th><th>Package</th><th>Installed</th><th>Fixed in</th>
<th>CVE</th><th>Tier</th><th class="num">EPSS</th></tr>{top_rows}</table></div>
<div class="card"><h2>Open findings after each run</h2>{trend}</div>
<div class="card"><h2>Run history</h2><table><tr><th>#</th><th>Finished</th><th>Status</th><th class="num">Repos</th>
<th class="num">Open</th><th class="num">New</th><th class="num">Fixed</th><th>Notes</th></tr>{run_rows}</table></div>
<footer>Generated automatically from scan results. Priority combines CISA KEV, EPSS, and severity.</footer>
</div><script>
(function(){{var b=document.getElementById('stale'),t=document.body.dataset.lastOk;
if(!t){{b.textContent='No successful run recorded yet.';b.style.display='block';return;}}
var h=(Date.now()-new Date(t).getTime())/36e5;
if(h>26){{b.textContent='No successful run in the last '+Math.round(h)+' hours. The pipeline may have stopped.';b.style.display='block';}}}})();
</script></body></html>"""

if __name__ == "__main__":
    data = collect(connect(), read_repos("repos.txt"))
    os.makedirs("site", exist_ok=True)
    with open("site/index.html", "w", encoding="utf-8") as f:
        f.write(render(data))
    print("Wrote site/index.html")