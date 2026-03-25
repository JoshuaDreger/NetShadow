import html
from datetime import datetime

_RISK_COLORS = {
    "Critical": "#c0392b",
    "High":     "#e67e22",
    "Medium":   "#f1c40f",
    "Low":      "#2980b9",
    "Clean":    "#27ae60",
    "Unknown":  "#95a5a6",
}

_CSS = """
body { font-family: Arial, sans-serif; margin: 0; background: #1a1a2e; color: #e0e0e0; }
.container { max-width: 1200px; margin: 0 auto; padding: 24px; }
h1 { color: #00d2ff; margin-bottom: 4px; }
.meta { color: #888; font-size: 0.9em; margin-bottom: 24px; }
.summary-box { background: #16213e; border-left: 4px solid #00d2ff; padding: 16px 20px;
               border-radius: 4px; margin-bottom: 32px; line-height: 1.6; }
table { width: 100%; border-collapse: collapse; background: #16213e; border-radius: 8px;
        overflow: hidden; font-size: 0.9em; }
th { background: #0f3460; padding: 12px 10px; text-align: left; color: #00d2ff;
     cursor: pointer; user-select: none; white-space: nowrap; }
th:hover { background: #1a4a80; }
td { padding: 10px; border-bottom: 1px solid #2a2a4a; vertical-align: top; word-break: break-word; }
tr:last-child td { border-bottom: none; }
tr:hover td { background: rgba(255,255,255,0.04); }
.badge { display: inline-block; padding: 3px 10px; border-radius: 12px; font-weight: bold;
         font-size: 0.82em; color: #fff; white-space: nowrap; }
.dist { display: flex; flex-wrap: wrap; gap: 12px; margin-top: 32px; }
.dist-item { background: #16213e; border-radius: 8px; padding: 16px 24px; text-align: center;
             border-top: 4px solid; min-width: 110px; }
.dist-item .count { font-size: 2em; font-weight: bold; }
.dist-item .label { font-size: 0.85em; color: #aaa; }
"""

_SORT_JS = """
function sortTable(col) {
  const tbl = document.getElementById('risktable');
  const rows = Array.from(tbl.querySelectorAll('tbody tr'));
  const asc = tbl.dataset.sortCol === String(col) && tbl.dataset.sortDir === 'asc';
  rows.sort((a, b) => {
    const av = a.cells[col].textContent.trim();
    const bv = b.cells[col].textContent.trim();
    return asc ? bv.localeCompare(av) : av.localeCompare(bv);
  });
  tbl.querySelector('tbody').append(...rows);
  tbl.dataset.sortCol = col;
  tbl.dataset.sortDir = asc ? 'desc' : 'asc';
}
"""


def _badge(risk: str) -> str:
    color = _RISK_COLORS.get(risk, _RISK_COLORS["Unknown"])
    return f'<span class="badge" style="background:{color}">{html.escape(risk)}</span>'


def _dist_card(risk: str, count: int) -> str:
    color = _RISK_COLORS.get(risk, _RISK_COLORS["Unknown"])
    return (
        f'<div class="dist-item" style="border-top-color:{color}">'
        f'<div class="count" style="color:{color}">{count}</div>'
        f'<div class="label">{html.escape(risk)}</div>'
        f'</div>'
    )


def generate_html(
    pcap_filename: str,
    scored_ips: list[dict],
    executive_summary: str,
) -> str:
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    total = len(scored_ips)

    # Risk distribution
    dist: dict[str, int] = {r: 0 for r in list(_RISK_COLORS.keys())}
    for ip in scored_ips:
        key = ip.get("risk_level", "Unknown")
        dist[key] = dist.get(key, 0) + 1

    # Table rows
    rows = []
    for ip in scored_ips:
        vt_det = ip.get("malicious", 0)
        vt_tot = ip.get("total", 0)
        vt_str = f"{vt_det}/{vt_tot}" if vt_tot else "N/A"
        rows.append(
            f"<tr>"
            f"<td><code>{html.escape(ip.get('ip',''))}</code></td>"
            f"<td>{html.escape(ip.get('hostname','Unknown'))}</td>"
            f"<td>{html.escape(ip.get('country','Unknown'))}</td>"
            f"<td>{html.escape(ip.get('org','Unknown'))}</td>"
            f"<td style='text-align:center'>{html.escape(vt_str)}</td>"
            f"<td>{_badge(ip.get('risk_level','Unknown'))}</td>"
            f"<td>{html.escape(ip.get('reasoning',''))}</td>"
            f"</tr>"
        )

    rows_html = "\n".join(rows)

    dist_cards = "\n".join(
        _dist_card(r, c) for r, c in dist.items() if c > 0
    )

    headers = ["IP", "Hostname", "Country", "Org", "VT Detections", "Risk Level", "Reasoning"]
    header_cells = "".join(
        f'<th onclick="sortTable({i})">{h} &#8597;</th>'
        for i, h in enumerate(headers)
    )

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>NetShadow Report — {html.escape(pcap_filename)}</title>
<style>{_CSS}</style>
</head>
<body>
<div class="container">
  <h1>&#127941; NetShadow Threat Analysis</h1>
  <div class="meta">
    File: <strong>{html.escape(pcap_filename)}</strong> &nbsp;|&nbsp;
    Generated: <strong>{timestamp}</strong> &nbsp;|&nbsp;
    External endpoints: <strong>{total}</strong>
  </div>

  <h2 style="color:#00d2ff">Executive Summary</h2>
  <div class="summary-box">{html.escape(executive_summary)}</div>

  <h2 style="color:#00d2ff">Endpoint Risk Table</h2>
  <table id="risktable" data-sort-col="" data-sort-dir="">
    <thead><tr>{header_cells}</tr></thead>
    <tbody>{rows_html}</tbody>
  </table>

  <h2 style="color:#00d2ff">Risk Distribution</h2>
  <div class="dist">{dist_cards}</div>
</div>
<script>{_SORT_JS}</script>
</body>
</html>
"""
