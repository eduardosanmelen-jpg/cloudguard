"""Report renderers: console, JSON, and a self-contained HTML dashboard."""
from __future__ import annotations

import html
import json

from .models import ScanResult, Severity

SEV_COLORS = {"CRITICAL": "#d7263d", "HIGH": "#f46036", "MEDIUM": "#e2a400", "LOW": "#2e86ab"}
ANSI = {"CRITICAL": "\033[41;97m", "HIGH": "\033[91m", "MEDIUM": "\033[93m", "LOW": "\033[94m"}
RESET = "\033[0m"


def to_json(result: ScanResult) -> str:
    return json.dumps(result.to_dict(), indent=2)


def to_console(result: ScanResult, color: bool = True) -> str:
    c = (lambda sev, s: f"{ANSI[sev]}{s}{RESET}") if color else (lambda sev, s: s)
    lines = [
        "",
        f"  CloudGuard scan - account {result.account_id} - regions: {', '.join(result.regions)}",
        f"  Security score: {result.score}/100 (grade {result.grade})   "
        f"checks: {result.checks_run}   resources: {result.resources_scanned}",
        "  " + "   ".join(c(k, f"{k}: {v}") for k, v in result.counts().items()),
        "",
    ]
    for f in result.sorted_findings():
        lines.append(f"  {c(f.severity.value, f'[{f.severity.value:^8}]')} {f.check_id:<8} {f.title}")
        lines.append(f"  {'':10} {f.resource}")
    if not result.findings:
        lines.append("  No findings - nice work.")
    lines.append("")
    return "\n".join(lines)


def to_html(result: ScanResult) -> str:
    e = html.escape
    counts = result.counts()
    score = result.score
    ring = "#2a9d8f" if score >= 80 else "#e2a400" if score >= 60 else "#d7263d"

    by_service: dict = {}
    for f in result.findings:
        by_service[f.service] = by_service.get(f.service, 0) + 1
    max_svc = max(by_service.values()) if by_service else 1
    svc_bars = "".join(
        f'<div class="bar-row"><span>{e(s)}</span><div class="bar"><i style="width:{n / max_svc * 100:.0f}%"></i></div><b>{n}</b></div>'
        for s, n in sorted(by_service.items(), key=lambda kv: -kv[1])
    ) or '<p class="muted">No findings.</p>'

    rows = []
    for f in result.sorted_findings():
        rows.append(f"""
<details class="finding" data-sev="{f.severity.value}">
  <summary>
    <span class="pill" style="--c:{SEV_COLORS[f.severity.value]}">{f.severity.value}</span>
    <span class="cid">{e(f.check_id)}</span>
    <span class="title">{e(f.title)}</span>
    <span class="svc">{e(f.service)} &middot; {e(f.region)}</span>
  </summary>
  <div class="body">
    <p><b>Resource</b><br><code>{e(f.resource)}</code></p>
    <p><b>Why it matters</b><br>{e(f.description)}</p>
    <p><b>Remediation</b><br><code class="fix">{e(f.remediation)}</code></p>
    {f'<p class="muted">Maps to {e(f.cis)} (CIS AWS Foundations Benchmark)</p>' if f.cis else ''}
  </div>
</details>""")

    filters = "".join(
        f'<button data-f="{s.value}" style="--c:{SEV_COLORS[s.value]}">{s.value.title()} <b>{counts[s.value]}</b></button>'
        for s in Severity)

    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>CloudGuard Report</title>
<style>
:root{{--bg:#f6f7f9;--card:#fff;--ink:#14181f;--muted:#5f6b7a;--line:#e3e7ec;--code:#f0f2f5}}
@media (prefers-color-scheme:dark){{:root{{--bg:#0e1116;--card:#161b22;--ink:#e6edf3;--muted:#8b98a8;--line:#262d36;--code:#1f252e}}}}
*{{box-sizing:border-box}}body{{margin:0;background:var(--bg);color:var(--ink);font:15px/1.5 -apple-system,BlinkMacSystemFont,"Segoe UI",Inter,sans-serif}}
.wrap{{max-width:1040px;margin:0 auto;padding:32px 16px}}
header{{display:flex;justify-content:space-between;align-items:flex-end;flex-wrap:wrap;gap:8px;margin-bottom:24px}}
h1{{margin:0;font-size:26px;letter-spacing:-.02em}}h1 span{{color:#2a9d8f}}.muted{{color:var(--muted)}}
.grid{{display:grid;grid-template-columns:240px 1fr 1fr;gap:16px;margin-bottom:24px}}
@media (max-width:820px){{.grid{{grid-template-columns:1fr}}}}
.card{{background:var(--card);border:1px solid var(--line);border-radius:14px;padding:20px}}
.card h3{{margin:0 0 12px;font-size:13px;text-transform:uppercase;letter-spacing:.06em;color:var(--muted)}}
.score{{display:flex;flex-direction:column;align-items:center}}
.ring{{width:150px;height:150px;border-radius:50%;display:grid;place-items:center;
background:conic-gradient({ring} {score * 3.6}deg,var(--line) 0)}}
.ring div{{width:122px;height:122px;border-radius:50%;background:var(--card);display:grid;place-items:center;text-align:center}}
.ring b{{font-size:40px;line-height:1}}.ring small{{color:var(--muted)}}
.sev{{display:grid;grid-template-columns:1fr 1fr;gap:10px}}
.sev div{{border-left:4px solid var(--c);padding:6px 10px;background:var(--code);border-radius:6px}}
.sev b{{display:block;font-size:26px}}
.bar-row{{display:grid;grid-template-columns:90px 1fr 24px;gap:8px;align-items:center;margin:6px 0;font-size:14px}}
.bar{{height:10px;background:var(--code);border-radius:5px;overflow:hidden}}.bar i{{display:block;height:100%;background:#2a9d8f}}
.filters{{display:flex;gap:8px;flex-wrap:wrap;margin-bottom:12px}}
.filters button{{border:1px solid var(--line);background:var(--card);color:var(--ink);border-radius:999px;padding:6px 14px;cursor:pointer;font:inherit}}
.filters button.on{{border-color:var(--c,#2a9d8f);box-shadow:inset 0 0 0 1px var(--c,#2a9d8f)}}
.finding{{background:var(--card);border:1px solid var(--line);border-radius:12px;margin-bottom:8px}}
.finding summary{{display:grid;grid-template-columns:92px 72px 1fr auto;gap:12px;align-items:center;padding:14px 16px;cursor:pointer;list-style:none}}
.finding summary::-webkit-details-marker{{display:none}}
@media (max-width:640px){{.finding summary{{grid-template-columns:auto 1fr}}.svc,.cid{{display:none}}}}
.pill{{background:var(--c);color:#fff;font-size:11px;font-weight:700;border-radius:6px;padding:3px 0;text-align:center;letter-spacing:.04em}}
.cid{{font-family:ui-monospace,Menlo,monospace;color:var(--muted);font-size:13px}}.title{{font-weight:600}}.svc{{color:var(--muted);font-size:13px}}
.body{{padding:0 16px 14px;border-top:1px solid var(--line)}}
code{{font-family:ui-monospace,Menlo,monospace;font-size:13px;background:var(--code);padding:2px 6px;border-radius:5px;word-break:break-all}}
code.fix{{display:block;padding:10px 12px;white-space:pre-wrap}}
footer{{margin-top:32px;font-size:13px}}
</style></head><body><div class="wrap">
<header>
  <div><h1>Cloud<span>Guard</span> security report</h1>
  <div class="muted">AWS account {e(result.account_id)} &middot; {e(', '.join(result.regions))} &middot; {e(result.started_at)}</div></div>
  <div class="muted">{result.checks_run} checks &middot; {result.resources_scanned} resources scanned</div>
</header>
<div class="grid">
  <div class="card score"><h3>Posture score</h3><div class="ring"><div><span><b>{score}</b><br><small>grade {result.grade}</small></span></div></div></div>
  <div class="card"><h3>Findings by severity</h3><div class="sev">
    {''.join(f'<div style="--c:{SEV_COLORS[k]}"><b>{v}</b>{k.title()}</div>' for k, v in counts.items())}
  </div></div>
  <div class="card"><h3>Findings by service</h3>{svc_bars}</div>
</div>
<div class="filters"><button data-f="ALL" class="on">All <b>{len(result.findings)}</b></button>{filters}</div>
{''.join(rows) or '<div class="card">No findings. This account passes every check.</div>'}
<footer class="muted">Generated by CloudGuard. Checks map to the CIS AWS Foundations Benchmark where applicable.</footer>
</div>
<script>
document.querySelectorAll('.filters button').forEach(b=>b.onclick=()=>{{
  document.querySelectorAll('.filters button').forEach(x=>x.classList.toggle('on',x===b));
  document.querySelectorAll('.finding').forEach(f=>f.style.display=(b.dataset.f==='ALL'||f.dataset.sev===b.dataset.f)?'':'none');
}});
</script></body></html>"""
