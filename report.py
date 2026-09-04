import os
from datetime import datetime, timezone

TEMPLATE = """<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<title>Provenance scan report</title>
<style>
body {{ font-family: -apple-system, sans-serif; margin: 2rem auto; max-width:90rem; color: #222; }}
h1 {{ font-size: 1.5rem; }}
.meta {{ color: #666; font-size: 0.9rem; margin-bottom: 2rem; }}
.summary span {{ display: inline-block; margin-right: 2rem; font-size: 1.1rem; }}
table {{ border-collapse: collapse; width: 100%; margin-top: 2rem; }}
th, td {{ text-align: left; padding: 0.6rem; border-bottom: 1px solid #ddd; vertical-align: top; }}
th {{ background: #f5f5f5; font-weight: 600; }}
.FAIL {{ color: #a32d2d; font-weight: 600; }}
.PASS {{ color: #3b6d11; font-weight: 600; }}
.ERROR {{ color: #854f0b; font-weight: 600; }}
.evidence {{ font-family: monospace; font-size: 0.85rem; color: #555; }}
</style>
</head>
<body>
<h1>Provenance scan report</h1>
<div class="meta">Generated {timestamp} &middot; {control_count} controls evaluated</div>
<div class="summary">
<span class="PASS">{passed} passed</span>
<span class="FAIL">{failed} failed</span>
<span class="ERROR">{errors} errors</span>
</div>
<table>
<tr><th>Control</th><th>Status</th><th>Severity</th><th>Resource</th><th>Evidence</th><th>Frameworks</th><th>Risk and remediation</th></tr>
{rows}
</table>
</body>
</html>
"""

ROW = """<tr>
<td>{control_id}<br><span class="evidence">{title}</span></td>
<td class="{status}">{status}</td>
<td>{severity}</td>
<td class="evidence">{resource}</td>
<td class="evidence">{evidence}</td>
<td class="evidence">{frameworks}</td>
<td class="evidence">{explanation}</td>
</tr>"""


def write(findings, control_count, path="output/report.html"):
    os.makedirs(os.path.dirname(path), exist_ok=True)

    rows = []
    for f in findings:
        fw = f.get("frameworks", {})
        fw_text = "<br>".join(f"{k}: {v}" for k, v in fw.items()) or "unmapped"
        rows.append(ROW.format(
            control_id=f["control_id"],
            title=f["title"],
            status=f["status"],
            severity=f["severity"],
            resource=f["resource"],
            evidence=f["evidence"],
            frameworks=fw_text,
            explanation=f.get("explanation", ""),
        ))

    html = TEMPLATE.format(
        timestamp=datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
        control_count=control_count,
        passed=sum(1 for f in findings if f["status"] == "PASS"),
        failed=sum(1 for f in findings if f["status"] == "FAIL"),
        errors=sum(1 for f in findings if f["status"] == "ERROR"),
        rows="\n".join(rows),
    )

    with open(path, "w") as fh:
        fh.write(html)

    return path
