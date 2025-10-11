import csv
import json
import os
from typing import Dict, Any, List
from jinja2 import Template
from datetime import datetime

class OutputManager:
    def __init__(self, outdir: str):
        self.outdir = outdir
        os.makedirs(self.outdir, exist_ok=True)
        self._alerts_json: List[Dict[str,Any]] = []
        self._alerts_csv_rows: List[List[str]] = []
        self._notes_dir = os.path.join(self.outdir, "notes")
        os.makedirs(self._notes_dir, exist_ok=True)

    def record_result(self, msg_id: str, summary: Dict[str,str], verdict: Dict[str,Any], features: Dict[str,Any]):
        note_file = os.path.join("notes", f"{msg_id}.md")
        row = [
            msg_id,
            summary.get("date",""),
            summary.get("from",""),
            summary.get("subject",""),
            verdict["severity"],
            str(verdict["score"]),
            ",".join(verdict["rule_hits"]),
            ",".join(features.get("indicators",{}).get("domains",[])),
            ",".join([u.get("raw") for u in features.get("urls",[])])
        ]
        self._alerts_csv_rows.append(row)

        obj = {
            "id": msg_id,
            "date": summary.get("date",""),
            "from": summary.get("from",""),
            "subject": summary.get("subject",""),
            "score": verdict["score"],
            "severity": verdict["severity"],
            "rule_hits": verdict["rule_hits"],
            "indicators": {
                "domains": features.get("indicators",{}).get("domains",[]),
                "urls": [u.get("raw") for u in features.get("urls",[])]
            },
            "note_file": note_file
        }
        self._alerts_json.append(obj)
        self._write_note(msg_id, summary, verdict, features, note_file)
        return obj

    def _write_note(self, msg_id: str, summary, verdict, features, note_file):
        p = os.path.join(self._notes_dir, f"{msg_id}.md")
        bullets = "\n".join([f"- {r}" for r in verdict["reasons"][:3]]) or "- No high-confidence rule reasons."
        md = f"""# {summary.get('subject','(no subject)')}
**From:** {summary.get('from','')}  
**Date:** {summary.get('date','')}

**Severity:** {verdict['severity']} ({verdict['score']})  
**Top reasons:**  
{bullets}

## Indicators
**Domains:** {", ".join(features.get("indicators",{}).get("domains",[]))}  
**URLs:**  
{os.linesep.join([u.get('raw') for u in features.get('urls',[])])}
"""
        with open(p, "w", encoding="utf-8") as f:
            f.write(md)

    def finalize(self):
        # JSON
        with open(os.path.join(self.outdir, "alerts.json"), "w", encoding="utf-8") as f:
            json.dump(self._alerts_json, f, indent=2)
        # CSV
        with open(os.path.join(self.outdir, "alerts.csv"), "w", encoding="utf-8", newline="") as f:
            w = csv.writer(f)
            w.writerow(["id","date","from","subject","severity","score","rule_hits","domains","urls"])  # header
            for row in self._alerts_csv_rows:
                w.writerow(row)

HTML_TEMPLATE = """<!doctype html>
<html>
<head>
  <meta charset="utf-8">
  <title>B9-Phish Report</title>
  <style>
    body { font-family: system-ui, -apple-system, Segoe UI, Roboto, Helvetica, Arial, sans-serif; margin: 2rem; }
    table { border-collapse: collapse; width: 100%; }
    th, td { border: 1px solid #ddd; padding: 8px; }
    th { background: #f6f6f6; cursor: pointer; }
    tr:hover { background: #fafafa; }
    .High { color: #b30000; font-weight: 600; }
    .Review { color: #b36b00; font-weight: 600; }
    .Pass { color: #2b7a0b; font-weight: 600; }
  </style>
</head>
<body>
  <h1>B9-Phish Report</h1>
  <p>Generated at {{ now }}</p>
  <table id="tbl">
    <thead>
      <tr>
        <th onclick="sortTable(0)">Severity</th>
        <th onclick="sortTable(1)">Score</th>
        <th onclick="sortTable(2)">Date</th>
        <th onclick="sortTable(3)">From</th>
        <th onclick="sortTable(4)">Subject</th>
        <th onclick="sortTable(5)">Rule Hits</th>
        <th onclick="sortTable(6)">Domains</th>
      </tr>
    </thead>
    <tbody>
    {% for a in alerts %}
      <tr>
        <td class="{{ a.severity }}">{{ a.severity }}</td>
        <td>{{ a.score }}</td>
        <td>{{ a.date }}</td>
        <td>{{ a.from }}</td>
        <td>{{ a.subject }}</td>
        <td>{{ a.rule_hits|join(", ") }}</td>
        <td>{{ a.indicators.domains|join(", ") }}</td>
      </tr>
    {% endfor %}
    </tbody>
  </table>
<script>
function sortTable(n) {
  var table, rows, switching, i, x, y, shouldSwitch, dir, switchcount = 0;
  table = document.getElementById("tbl");
  switching = true;
  dir = "asc"; 
  while (switching) {
    switching = false;
    rows = table.rows;
    for (i = 1; i < (rows.length - 1); i++) {
      shouldSwitch = false;
      x = rows[i].getElementsByTagName("TD")[n];
      y = rows[i + 1].getElementsByTagName("TD")[n];
      if (dir == "asc") {
        if (x.innerHTML.toLowerCase() > y.innerHTML.toLowerCase()) {
          shouldSwitch = true;
          break;
        }
      } else if (dir == "desc") {
        if (x.innerHTML.toLowerCase() < y.innerHTML.toLowerCase()) {
          shouldSwitch = true;
          break;
        }
      }
    }
    if (shouldSwitch) {
      rows[i].parentNode.insertBefore(rows[i + 1], rows[i]);
      switching = true;
      switchcount ++; 
    } else {
      if (switchcount == 0 && dir == "asc") {
        dir = "desc";
        switching = true;
      }
    }
  }
}
</script>
</body>
</html>
"""

def build_html_report(outpath: str, alerts_path: str="./outputs/alerts.json"):
    if not os.path.exists(alerts_path):
        raise FileNotFoundError("alerts.json not found. Run a scan first.")
    with open(alerts_path, "r", encoding="utf-8") as f:
        alerts = json.load(f)
    t = Template(HTML_TEMPLATE)
    html = t.render(alerts=alerts, now=datetime.utcnow().isoformat()+"Z")
    os.makedirs(os.path.dirname(outpath), exist_ok=True)
    with open(outpath, "w", encoding="utf-8") as f:
        f.write(html)
