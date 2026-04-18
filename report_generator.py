"""HTML coverage heatmap for MITRE ATT&CK Detection Rules Library."""
import os
from collections import defaultdict
from html import escape


TACTIC_ORDER = [
    "Reconnaissance", "Resource Development", "Initial Access", "Execution",
    "Persistence", "Privilege Escalation", "Defense Evasion", "Credential Access",
    "Discovery", "Lateral Movement", "Collection", "Command and Control",
    "Exfiltration", "Impact",
]


def generate_coverage_html(rules: list, output_path: str):
    os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)
    by_tactic = defaultdict(list)
    for r in rules:
        by_tactic[r["tactic"]].append(r)

    sev_color = {"CRITICAL": "#ff3b30", "HIGH": "#ff9500", "MEDIUM": "#ffcc00", "LOW": "#34c759"}

    cols = []
    tactics = [t for t in TACTIC_ORDER if t in by_tactic] + \
              [t for t in by_tactic if t not in TACTIC_ORDER]
    for tac in tactics:
        items = sorted(by_tactic[tac], key=lambda r: (r["technique"], r["id"]))
        cards = []
        for r in items:
            c = sev_color.get(r["severity"], "#888")
            cards.append(f"""
              <div class='tech' style='border-left:4px solid {c}'>
                <div class='id'>{escape(r['id'])} &middot; <span class='t'>{escape(r['technique'])}</span></div>
                <div class='tl'>{escape(r['title'])}</div>
                <div class='meta'><span class='sev' style='background:{c}'>{escape(r['severity'])}</span> {escape(r['data_source'])}</div>
              </div>""")
        cols.append(f"""
          <div class='col'>
            <div class='h'>{escape(tac)}<span class='count'>{len(items)}</span></div>
            {''.join(cards)}
          </div>""")

    html = f"""<!DOCTYPE html><html><head><meta charset="utf-8"><title>MITRE ATT&amp;CK Coverage</title>
<style>
:root {{ color-scheme: dark; }}
body {{ background:#0d1117; color:#e6edf3; font-family:ui-sans-serif,system-ui,"Segoe UI",Roboto,sans-serif; margin:0; padding:24px; }}
h1 {{ margin:0 0 6px; }}
.subtitle {{ color:#8b949e; margin-bottom:18px; font-size:13px; }}
.board {{ display:grid; grid-template-columns: repeat({len(tactics)}, minmax(220px, 1fr)); gap:10px; overflow-x:auto; }}
.col {{ background:#161b22; border:1px solid #30363d; border-radius:8px; padding:8px; }}
.h {{ font-weight:700; margin:4px 0 8px; color:#e6edf3; display:flex; justify-content:space-between; align-items:center; }}
.count {{ color:#8b949e; font-size:12px; font-weight:400; }}
.tech {{ background:#0d1117; border:1px solid #30363d; border-radius:6px; padding:8px; margin:6px 0; }}
.tech .id {{ font-size:11px; color:#8b949e; }}
.tech .id .t {{ color:#58a6ff; }}
.tech .tl {{ font-size:13px; margin:3px 0; }}
.tech .meta {{ font-size:11px; color:#8b949e; margin-top:4px; display:flex; gap:6px; align-items:center; flex-wrap:wrap; }}
.sev {{ color:#fff; padding:1px 6px; border-radius:3px; font-size:10px; font-weight:700; }}
.foot {{ color:#8b949e; margin-top:20px; font-size:12px; text-align:center; }}
</style></head><body>
  <h1>MITRE ATT&amp;CK Coverage Map</h1>
  <div class="subtitle">{len(rules)} rules across {len(tactics)} tactics &middot; Detection Rules Library (CyberEnthusiastic)</div>
  <div class="board">{''.join(cols)}</div>
  <div class="foot">Hover a rule in the source library for Sigma / Splunk / Elastic / KQL translations.</div>
</body></html>"""
    with open(output_path, "w", encoding="utf-8") as fh:
        fh.write(html)
