from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

from jinja2 import Environment, select_autoescape

from deep_scout.reporting.base import Finding

_TEMPLATE_STR = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Deep-Scout Report — {{ org }}</title>
<style>
  * { margin: 0; padding: 0; box-sizing: border-box; }
  body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #0d1117; color: #c9d1d9; padding: 1.5rem; }
  a { color: #58a6ff; text-decoration: none; }
  a:hover { text-decoration: underline; }

  .header { display: flex; justify-content: space-between; align-items: flex-start; margin-bottom: 1.5rem; flex-wrap: wrap; gap: 1rem; }
  .header-left h1 { color: #f0f6fc; font-size: 1.6rem; }
  .header-left h1 span { color: #58a6ff; }
  .header-left .subtitle { color: #8b949e; font-size: 0.85rem; margin-top: 0.3rem; }
  .header-right { text-align: right; color: #8b949e; font-size: 0.8rem; }
  .header-right .version { color: #484f58; }

  .summary-cards { display: grid; grid-template-columns: repeat(auto-fit, minmax(120px, 1fr)); gap: 0.8rem; margin-bottom: 1.5rem; }
  .card { background: #161b22; border: 1px solid #30363d; border-radius: 8px; padding: 1rem; text-align: center; cursor: pointer; transition: border-color .15s, background .15s; }
  .card:hover { border-color: #58a6ff88; background: #1c2128; }
  .card.active { border-color: #58a6ff; background: #1c2128; }
  .card .num { font-size: 1.8rem; font-weight: 700; }
  .card .label { font-size: 0.75rem; color: #8b949e; margin-top: 0.2rem; text-transform: uppercase; letter-spacing: 0.04em; }
  .card .num.critical { color: #f85149; }
  .card .num.high { color: #d29922; }
  .card .num.medium { color: #58a6ff; }
  .card .num.low { color: #8b949e; }

  .controls { display: flex; gap: 0.8rem; margin-bottom: 1.2rem; flex-wrap: wrap; align-items: center; }
  .filter-btn { background: #21262d; border: 1px solid #30363d; color: #c9d1d9; padding: 0.4rem 1rem; border-radius: 6px; cursor: pointer; font-size: 0.8rem; font-weight: 500; transition: all .15s; }
  .filter-btn:hover { border-color: #58a6ff88; }
  .filter-btn.active { background: #1f6feb22; border-color: #1f6feb; color: #58a6ff; }
  .search-input { background: #0d1117; border: 1px solid #30363d; color: #c9d1d9; padding: 0.4rem 0.8rem; border-radius: 6px; font-size: 0.8rem; flex: 1; min-width: 180px; }
  .search-input:focus { outline: none; border-color: #58a6ff; }
  .finding-count { color: #8b949e; font-size: 0.85rem; margin-left: auto; }

  .finding { background: #161b22; border: 1px solid #30363d; border-radius: 8px; margin-bottom: 0.5rem; overflow: hidden; }
  .finding-header { display: grid; grid-template-columns: 90px 1fr 1.5fr 60px 1.2fr 70px 30px; gap: 0.5rem; padding: 0.7rem 1rem; cursor: pointer; align-items: center; font-size: 0.85rem; transition: background .1s; }
  .finding-header:hover { background: #1c2128; }
  .finding-header .severity-badge { display: inline-block; padding: 0.15rem 0.5rem; border-radius: 10px; font-size: 0.7rem; font-weight: 600; text-transform: uppercase; text-align: center; letter-spacing: 0.03em; }
  .severity-critical { background: #f8514922; color: #f85149; border: 1px solid #f8514944; }
  .severity-high { background: #d2992222; color: #d29922; border: 1px solid #d2992244; }
  .severity-medium { background: #58a6ff22; color: #58a6ff; border: 1px solid #58a6ff44; }
  .severity-low { background: #8b949e22; color: #8b949e; border: 1px solid #8b949e44; }
  .finding-header .repo { color: #58a6ff; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
  .finding-header .file { font-family: 'SF Mono', 'Fira Code', 'Consolas', monospace; font-size: 0.8rem; color: #f0f6fc; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
  .finding-header .line { color: #8b949e; text-align: center; }
  .finding-header .secret-type { color: #f0f6fc; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
  .finding-header .method-badge { font-size: 0.7rem; color: #8b949e; background: #0d1117; padding: 0.15rem 0.4rem; border-radius: 4px; text-align: center; }
  .finding-header .expand-icon { color: #484f58; text-align: center; font-size: 0.8rem; transition: transform .15s; }
  .finding-header .expand-icon.open { transform: rotate(90deg); }

  .finding-body { display: none; border-top: 1px solid #21262d; padding: 1rem 1.2rem; background: #0d1117; }
  .finding-body.open { display: block; }

  .remediation-box { background: #161b22; border: 1px solid #30363d; border-radius: 8px; padding: 1rem; margin-bottom: 1rem; }
  .remediation-box h3 { font-size: 0.85rem; color: #f0f6fc; margin-bottom: 0.6rem; }
  .remediation-box h3 .icon { margin-right: 0.4rem; }
  .risk-box { background: #f8514911; border: 1px solid #f8514944; border-radius: 6px; padding: 0.8rem; margin-bottom: 0.8rem; }
  .risk-box .risk-label { font-size: 0.7rem; text-transform: uppercase; color: #f85149; font-weight: 600; letter-spacing: 0.05em; margin-bottom: 0.3rem; }
  .risk-box .risk-text { font-size: 0.85rem; color: #c9d1d9; line-height: 1.5; }
  .steps { list-style: none; padding: 0; margin-bottom: 0.8rem; }
  .steps li { font-size: 0.85rem; color: #c9d1d9; padding: 0.4rem 0; border-bottom: 1px solid #21262d; display: flex; align-items: flex-start; gap: 0.5rem; }
  .steps li:last-child { border-bottom: none; }
  .steps li .step-num { color: #58a6ff; font-weight: 600; min-width: 1.5rem; }
  .btn-row { display: flex; gap: 0.6rem; flex-wrap: wrap; margin-bottom: 0.8rem; }
  .btn { display: inline-flex; align-items: center; gap: 0.3rem; padding: 0.45rem 1rem; border-radius: 6px; font-size: 0.8rem; font-weight: 500; cursor: pointer; border: 1px solid; transition: all .15s; text-decoration: none; }
  .btn-danger { background: #f8514922; border-color: #f8514944; color: #f85149; }
  .btn-danger:hover { background: #f8514944; border-color: #f8514988; }
  .btn-secondary { background: #21262d; border-color: #30363d; color: #c9d1d9; }
  .btn-secondary:hover { border-color: #58a6ff88; }
  .btn-copy { background: #21262d; border-color: #30363d; color: #c9d1d9; padding: 0.3rem 0.6rem; font-size: 0.75rem; }
  .btn-copy:hover { border-color: #58a6ff88; }
  .btn-copy.copied { border-color: #3fb950; color: #3fb950; }

  .git-cleanup { background: #0d1117; border: 1px solid #30363d; border-radius: 6px; padding: 0.6rem 0.8rem; margin-bottom: 0.8rem; display: flex; align-items: center; justify-content: space-between; gap: 0.5rem; flex-wrap: wrap; }
  .git-cleanup code { font-family: 'SF Mono', 'Fira Code', 'Consolas', monospace; font-size: 0.8rem; color: #f0f6fc; word-break: break-all; }

  .prevention-list { list-style: disc; padding-left: 1.2rem; margin-bottom: 0; }
  .prevention-list li { font-size: 0.82rem; color: #8b949e; padding: 0.2rem 0; }

  .context-box { background: #161b22; border: 1px solid #30363d; border-radius: 8px; padding: 0.8rem; margin-bottom: 1rem; }
  .context-box h4 { font-size: 0.75rem; color: #8b949e; text-transform: uppercase; letter-spacing: 0.05em; margin-bottom: 0.5rem; }
  .context-code { font-family: 'SF Mono', 'Fira Code', 'Consolas', monospace; font-size: 0.82rem; color: #f0f6fc; background: #0d1117; padding: 0.5rem; border-radius: 4px; overflow-x: auto; white-space: pre-wrap; word-break: break-all; }

  .meta-row { display: flex; gap: 1.5rem; font-size: 0.82rem; color: #8b949e; flex-wrap: wrap; }
  .meta-row span strong { color: #c9d1d9; }

  .empty-state { text-align: center; padding: 3rem; color: #484f58; }
  .empty-state .big-icon { font-size: 3rem; margin-bottom: 1rem; }

  .footer { margin-top: 2rem; color: #484f58; font-size: 0.75rem; text-align: center; border-top: 1px solid #21262d; padding-top: 1.5rem; }

  @media (max-width: 768px) {
    .finding-header { grid-template-columns: 70px 1fr 60px; gap: 0.3rem; }
    .finding-header .file, .finding-header .secret-type, .finding-header .method-badge { display: none; }
    body { padding: 0.8rem; }
  }
</style>
</head>
<body>

<div class="header">
  <div class="header-left">
    <h1>🔐 Deep-Scout <span>Report</span></h1>
    <p class="subtitle">Organization: <strong>{{ org }}</strong> &middot; {{ timestamp }}</p>
  </div>
  <div class="header-right">
    <div>deep-scout-github v1.0.0</div>
    <div class="version">Scan ID: {{ scan_id }}</div>
  </div>
</div>

<div class="summary-cards" id="summaryCards">
  <div class="card active" data-filter="all" onclick="filterSeverity('all')">
    <div class="num">{{ findings|length }}</div>
    <div class="label">Total Findings</div>
  </div>
  {% for sev, label in [('critical', 'Critical'), ('high', 'High'), ('medium', 'Medium'), ('low', 'Low')] %}
  <div class="card" data-filter="{{ sev }}" onclick="filterSeverity('{{ sev }}')">
    <div class="num {{ sev }}">{{ summary.get(sev, 0) }}</div>
    <div class="label">{{ label }}</div>
  </div>
  {% endfor %}
</div>

<div class="controls">
  <button class="filter-btn active" data-filter="all" onclick="filterSeverity('all')">All</button>
  <button class="filter-btn" data-filter="critical" onclick="filterSeverity('critical')">Critical</button>
  <button class="filter-btn" data-filter="high" onclick="filterSeverity('high')">High</button>
  <button class="filter-btn" data-filter="medium" onclick="filterSeverity('medium')">Medium</button>
  <button class="filter-btn" data-filter="low" onclick="filterSeverity('low')">Low</button>
  <input class="search-input" type="text" placeholder="Search by repo or secret type..." oninput="filterFindings()" id="searchInput">
  <span class="finding-count" id="findingCount">{{ findings|length }} finding(s)</span>
</div>

{% if findings %}
<div id="findingsContainer">
  {% for f in findings %}
  <div class="finding" data-severity="{{ f.severity }}" data-repo="{{ f.repository }}" data-type="{{ f.secret_type }}">
    <div class="finding-header" onclick="toggleFinding(this)">
      <span class="severity-badge severity-{{ f.severity }}">{{ f.severity }}</span>
      <span class="repo" title="{{ f.repository }}">{{ f.repository }}</span>
      <span class="file" title="{{ f.file_path }}">{{ f.file_path }}</span>
      <span class="line">{{ f.line_number }}</span>
      <span class="secret-type" title="{{ f.secret_type }}">{{ f.secret_type }}</span>
      <span class="method-badge">{{ f.detection_method }}</span>
      <span class="expand-icon">▶</span>
    </div>
    <div class="finding-body">
      {% if f.remediation %}
      <div class="remediation-box">
        <h3><span class="icon">🛡️</span>Remediation Guide</h3>
        <div class="risk-box">
          <div class="risk-label">Risk Assessment</div>
          <div class="risk-text">{{ f.remediation.risk }}</div>
        </div>

        <h3 style="font-size:0.8rem; color:#c9d1d9; margin-bottom:0.4rem;">Immediate Steps</h3>
        <ul class="steps">
          {% for step in f.remediation.immediate_steps %}
          <li><span class="step-num">Step {{ loop.index }}</span> {{ step }}</li>
          {% endfor %}
        </ul>

        {% if f.remediation.revoke_urls and f.remediation.revoke_urls[0] not in _na_urls %}
        <div class="btn-row">
          {% for url in f.remediation.revoke_urls %}
          <a class="btn btn-danger" href="{{ url }}" target="_blank" rel="noopener">🚨 Revoke at {{ url.split('//')[1].split('/')[0] }}</a>
          {% endfor %}
        </div>
        {% endif %}

        {% if f.remediation.git_cleanup_command and f.remediation.git_cleanup_command != "N/A" %}
        <h3 style="font-size:0.8rem; color:#c9d1d9; margin-bottom:0.4rem;">Git History Cleanup</h3>
        <div class="git-cleanup">
          <code>{{ f.remediation.git_cleanup_command }}</code>
          <button class="btn btn-copy" onclick="copyToClipboard(this, '{{ f.remediation.git_cleanup_command }}')">Copy</button>
        </div>
        {% endif %}

        {% if f.remediation.prevention_tips %}
        <h3 style="font-size:0.8rem; color:#c9d1d9; margin-bottom:0.4rem;">Prevention Tips</h3>
        <ul class="prevention-list">
          {% for tip in f.remediation.prevention_tips %}
          <li>{{ tip }}</li>
          {% endfor %}
        </ul>
        {% endif %}
      </div>
      {% endif %}

      {% if f.context_line %}
      <div class="context-box">
        <h4>Code Context</h4>
        <div class="context-code">{{ f.context_line }}</div>
      </div>
      {% endif %}

      <div class="meta-row">
        <span>Detection: <strong>{{ f.detection_method }}</strong></span>
        <span>Confidence: <strong>{{ (f.confidence * 100)|int }}%</strong></span>
        {% if f.commit_hash %}<span>Commit: <strong>{{ f.commit_hash[:10] }}</strong></span>{% endif %}
        {% if f.author %}<span>Author: <strong>{{ f.author }}</strong></span>{% endif %}
      </div>
    </div>
  </div>
  {% endfor %}
</div>
{% else %}
<div class="empty-state">
  <div class="big-icon">✅</div>
  <p>No secrets found. Your organization is clean.</p>
</div>
{% endif %}

<div class="footer">
  deep-scout-github v1.0.0 &mdash; {{ org }} &mdash; Scan duration: {{ duration_seconds }}s &mdash; Generated {{ timestamp }}
</div>

<script>
let currentFilter = 'all';

function toggleFinding(header) {
  const body = header.nextElementSibling;
  const icon = header.querySelector('.expand-icon');
  body.classList.toggle('open');
  icon.classList.toggle('open');
}

function filterSeverity(severity) {
  currentFilter = severity;
  document.querySelectorAll('#summaryCards .card').forEach(c => c.classList.toggle('active', c.dataset.filter === severity));
  document.querySelectorAll('.controls .filter-btn').forEach(b => b.classList.toggle('active', b.dataset.filter === severity));
  filterFindings();
}

function filterFindings() {
  const search = (document.getElementById('searchInput').value || '').toLowerCase();
  const findings = document.querySelectorAll('.finding');
  let visible = 0;
  findings.forEach(f => {
    const sevMatch = currentFilter === 'all' || f.dataset.severity === currentFilter;
    const searchMatch = !search || f.dataset.repo.toLowerCase().includes(search) || f.dataset.type.toLowerCase().includes(search);
    const match = sevMatch && searchMatch;
    f.style.display = match ? '' : 'none';
    if (match) visible++;
  });
  document.getElementById('findingCount').textContent = visible + ' finding(s)';
}

function copyToClipboard(btn, text) {
  navigator.clipboard.writeText(text).then(() => {
    btn.textContent = 'Copied!';
    btn.classList.add('copied');
    setTimeout(() => { btn.textContent = 'Copy'; btn.classList.remove('copied'); }, 2000);
  }).catch(() => {
    const ta = document.createElement('textarea');
    ta.value = text;
    document.body.appendChild(ta);
    ta.select();
    document.execCommand('copy');
    document.body.removeChild(ta);
    btn.textContent = 'Copied!';
    btn.classList.add('copied');
    setTimeout(() => { btn.textContent = 'Copy'; btn.classList.remove('copied'); }, 2000);
  });
}
</script>
</body>
</html>
"""

_NA_URL_PREFIXES = frozenset([
    "N/A",
    "N/A — depends on the token issuer",
    "N/A — depends on the specific secret identified",
    "N/A — depends on your auth provider",
    "N/A — use gpg",
    "N/A — server-side removal required",
    "N/A — server-side revocation required",
])


def build_html_report(findings: list[Finding], org: str, scan_duration: float) -> str:
    summary = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for f in findings:
        summary[f.severity] = summary.get(f.severity, 0) + 1

    sorted_findings = sorted(
        findings,
        key=lambda f: {"critical": 0, "high": 1, "medium": 2, "low": 3}.get(f.severity, 4),
    )

    scan_id = f"ds-{datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S')}-{abs(hash(str(findings))):x}"

    env = Environment(autoescape=True)
    template = env.from_string(_TEMPLATE_STR)

    def _is_not_na(url: str) -> bool:
        return not any(url.startswith(prefix) for prefix in _NA_URL_PREFIXES)
    _na_urls_list = list(_NA_URL_PREFIXES)

    html = template.render(
        org=org,
        timestamp=datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
        scan_id=scan_id,
        findings=sorted_findings,
        summary=summary,
        duration_seconds=round(scan_duration, 1),
        _na_urls=_na_urls_list,
    )
    return html


def write_html_report(html: str, output_path: str):
    Path(output_path).write_text(html)
