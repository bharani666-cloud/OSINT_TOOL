"""Human-readable HTML report generator."""

from __future__ import annotations

import html
import json
from pathlib import Path
from typing import Any

from models import CollectionResult, utc_now_iso

_CONFIDENCE_COLORS = {
    "HIGH": "#1a7f37",
    "MEDIUM": "#9a6700",
    "LOW": "#cf222e",
    "INFO": "#57606a",
}

_STYLE = """
body { font-family: -apple-system, Segoe UI, Roboto, Arial, sans-serif; margin: 0; background: #f6f8fa; color: #1f2328; }
header { background: #0d1117; color: #fff; padding: 24px 32px; }
header h1 { margin: 0 0 4px 0; font-size: 22px; }
header p { margin: 2px 0; color: #c9d1d9; font-size: 13px; }
.container { max-width: 1000px; margin: 24px auto; padding: 0 16px 48px; }
.banner { background: #fff8c5; border: 1px solid #d4a72c; padding: 12px 16px; border-radius: 6px; margin-bottom: 24px; font-size: 13px; }
.card { background: #fff; border: 1px solid #d0d7de; border-radius: 8px; padding: 16px 20px; margin-bottom: 16px; }
.summary-grid { display: flex; gap: 16px; flex-wrap: wrap; }
.summary-grid .stat { flex: 1; min-width: 120px; text-align: center; }
.summary-grid .stat .num { font-size: 28px; font-weight: 700; }
.summary-grid .stat .label { font-size: 12px; color: #57606a; }
table { width: 100%; border-collapse: collapse; font-size: 13px; }
th, td { text-align: left; padding: 8px 10px; border-bottom: 1px solid #eaeef2; vertical-align: top; }
th { background: #f6f8fa; }
.badge { display: inline-block; padding: 2px 8px; border-radius: 10px; color: #fff; font-size: 11px; font-weight: 600; }
pre { white-space: pre-wrap; word-break: break-word; font-size: 12px; margin: 0; }
.error-row td { background: #fff5f5; }
footer { text-align: center; color: #57606a; font-size: 12px; margin-top: 32px; }
"""


def _esc(value: Any) -> str:
    return html.escape(str(value)) if value is not None else ""


def _confidence_badge(level: str) -> str:
    color = _CONFIDENCE_COLORS.get(level, "#57606a")
    return f'<span class="badge" style="background:{color}">{_esc(level)}</span>'


def write_html_report(
    output_path: Path,
    case_id: str,
    inputs: dict[str, Any],
    result: CollectionResult,
    reference: str | None = None,
) -> Path:
    rows = []
    for f in result.findings:
        rows.append(
            f"""
            <tr>
                <td>{_esc(f.category)}</td>
                <td>{_esc(f.source)}</td>
                <td>{f'<a href="{_esc(f.source_url)}" target="_blank" rel="noopener">link</a>' if f.source_url else '—'}</td>
                <td>{_esc(f.collection_method)}</td>
                <td>{_confidence_badge(f.confidence.value)}</td>
                <td>{_esc(f.collected_at)}</td>
                <td><pre>{_esc(json.dumps(f.data, indent=2, default=str))}</pre></td>
            </tr>
            """
        )

    error_rows = []
    for e in result.errors:
        error_rows.append(
            f"""
            <tr class="error-row">
                <td>{_esc(e.source)}</td>
                <td>{_esc(e.message)}</td>
                <td>{_esc(e.occurred_at)}</td>
            </tr>
            """
        )

    inputs_rows = "".join(
        f"<tr><td>{_esc(k)}</td><td>{_esc(v)}</td></tr>" for k, v in inputs.items() if v
    )

    doc = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8" />
<title>OSINT Report — {_esc(case_id)}</title>
<style>{_STYLE}</style>
</head>
<body>
<header>
    <h1>Authorized OSINT Investigation Report</h1>
    <p>Case ID: {_esc(case_id)}{f" &middot; Reference: {_esc(reference)}" if reference else ""}</p>
    <p>Generated: {_esc(utc_now_iso())}</p>
</header>
<div class="container">
    <div class="banner">
        <strong>Scope &amp; limitations:</strong> This report contains only information that was
        publicly available or returned by an officially authorized API/credential supplied by the
        investigator. No authentication, CAPTCHA, rate limit, or other access control was bypassed
        to produce this report. Username-based correlations are heuristic; a matching username
        alone is <strong>not</strong> proof that two accounts belong to the same person — see the
        confidence level on each row.
    </div>

    <div class="card">
        <h2>Summary</h2>
        <div class="summary-grid">
            <div class="stat"><div class="num">{result.sources_queried}</div><div class="label">Sources Queried</div></div>
            <div class="stat"><div class="num">{len(result.findings)}</div><div class="label">Findings</div></div>
            <div class="stat"><div class="num">{len(result.errors)}</div><div class="label">Errors</div></div>
        </div>
    </div>

    <div class="card">
        <h2>Investigation Inputs</h2>
        <table>{inputs_rows or '<tr><td colspan="2">None supplied</td></tr>'}</table>
    </div>

    <div class="card">
        <h2>Findings</h2>
        <table>
            <thead><tr><th>Category</th><th>Source</th><th>Source URL</th><th>Method</th><th>Confidence</th><th>Collected At</th><th>Data</th></tr></thead>
            <tbody>{''.join(rows) or '<tr><td colspan="7">No findings.</td></tr>'}</tbody>
        </table>
    </div>

    <div class="card">
        <h2>Errors / Skipped Sources</h2>
        <table>
            <thead><tr><th>Source</th><th>Message</th><th>Occurred At</th></tr></thead>
            <tbody>{''.join(error_rows) or '<tr><td colspan="3">No errors.</td></tr>'}</tbody>
        </table>
    </div>

    <div class="card">
        <h2>Methodology</h2>
        <p>Data was collected exclusively from public sources and officially authorized APIs
        (using investigator-supplied credentials where required). DNS/WHOIS lookups used standard
        resolution protocols. No private, login-walled, or access-controlled content was accessed.
        Any source requiring a credential that was not configured is listed as "skipped" above
        rather than omitted silently.</p>
    </div>
</div>
<footer>Authorized OSINT Tool &middot; For lawful investigative use only</footer>
</body>
</html>
"""
    output_path.write_text(doc, encoding="utf-8")
    return output_path
