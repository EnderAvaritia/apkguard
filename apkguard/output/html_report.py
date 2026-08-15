"""自包含 HTML 报告渲染模块：把 ``Report.to_dict()`` 渲染为可离线分享的
中英双语单文件 HTML 报告（内嵌全部 CSS/JS，无任何外部资源依赖，双击即可打开）。

``render_html`` 只依赖 Python 标准库，输入为报告字典（见 ``apkguard.engine.models.Report.to_dict``），
任何字段缺失或为空时均优雅降级为 ``-`` / ``无 / None``，不会抛出异常。

用法 / Usage::

    from apkguard.output.html_report import render_html, write_html_report

    html = render_html(report.to_dict())
    write_html_report(report.to_dict(), "report.html")
"""
from __future__ import annotations

import html
from datetime import datetime
from pathlib import Path
from typing import Any

# --- 内嵌样式表 / Embedded stylesheet（深色石板主题，类 VirusTotal 风格）---
_CSS = """
*{box-sizing:border-box;margin:0;padding:0}
html{-webkit-text-size-adjust:100%}
body{background:#0f172a;color:#e2e8f0;line-height:1.6;font-family:system-ui,-apple-system,"Segoe UI","Microsoft YaHei","PingFang SC","Noto Sans SC",sans-serif;padding:28px 16px 56px}
.wrap{max-width:1080px;margin:0 auto}
.mono{font-family:ui-monospace,SFMono-Regular,Consolas,"Courier New",monospace}
a{color:#38bdf8}
.card{background:#1e293b;border:1px solid #334155;border-radius:12px;padding:20px 22px;margin-bottom:18px;box-shadow:0 1px 3px rgba(0,0,0,.35)}
.card-title{font-size:17px;font-weight:650;color:#f1f5f9;margin-bottom:14px;display:flex;align-items:center;gap:8px;letter-spacing:.2px}
.card-title .count{background:#334155;color:#cbd5e1;font-size:12px;font-weight:600;padding:1px 9px;border-radius:999px}
.card-title::before{content:"";width:4px;height:16px;border-radius:2px;background:#38bdf8;display:inline-block}
.badge{display:inline-block;padding:2px 10px;border-radius:999px;font-size:12px;font-weight:600;white-space:nowrap}
.sev-critical{background:#dc2626;color:#fff}
.sev-high{background:#ea580c;color:#fff}
.sev-medium{background:#ca8a04;color:#1c1917}
.sev-low,.sev-info{background:#475569;color:#e2e8f0}
.badge-ok{background:#16a34a;color:#fff}
.badge-bad{background:#dc2626;color:#fff}
.badge-warn{background:#d97706;color:#fff}
.badge-muted{background:#475569;color:#e2e8f0}
.file-badge{background:#0ea5e9;color:#fff;font-size:13px;padding:3px 12px}
.header-card{padding:24px 26px}
.header-top{display:flex;align-items:center;gap:16px;margin-bottom:18px}
.logo{width:44px;height:44px;flex:none;color:#38bdf8;filter:drop-shadow(0 0 8px rgba(56,189,248,.35))}
.header-title h1{font-size:22px;font-weight:700;color:#f8fafc;line-height:1.3}
.header-sub{color:#94a3b8;font-size:14px;margin-top:2px}
.header-sub .dot{margin:0 6px;color:#475569}
.header-badges{margin-left:auto}
.meta-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:10px 18px;border-top:1px solid #334155;padding-top:16px}
.meta-item{display:flex;flex-direction:column;gap:1px;min-width:0}
.meta-label{font-size:11px;text-transform:uppercase;letter-spacing:.5px;color:#64748b}
.meta-value{font-size:13.5px;color:#e2e8f0;word-break:break-all}
.meta-sha{grid-column:1/-1;flex-direction:row;align-items:center;gap:10px}
.meta-sha .meta-label{flex:none}
.copy-btn{flex:none;background:#334155;color:#cbd5e1;border:1px solid #475569;border-radius:6px;font-size:12px;padding:3px 10px;cursor:pointer}
.copy-btn:hover{background:#475569;color:#fff}
.risk-card{padding:0;overflow:hidden;border-left-width:6px}
.risk-clean{border-left-color:#22c55e}
.risk-suspicious{border-left-color:#f59e0b}
.risk-malicious{border-left-color:#ef4444}
.risk-main{display:flex;gap:26px;align-items:center;padding:22px 26px}
.risk-score-wrap{text-align:center;flex:none}
.risk-score{font-size:52px;font-weight:800;line-height:1}
.risk-clean .risk-score{color:#22c55e}
.risk-suspicious .risk-score{color:#f59e0b}
.risk-malicious .risk-score{color:#ef4444}
.risk-label{font-size:15px;font-weight:650;margin-top:6px;color:#f1f5f9}
.risk-meta{flex:1;min-width:0}
.risk-title{font-size:13px;color:#94a3b8;margin-bottom:10px}
.risk-bar{height:10px;background:#0f172a;border-radius:999px;overflow:hidden;margin-bottom:10px}
.risk-bar-fill{height:100%;border-radius:999px;transition:width .4s ease}
.risk-clean .risk-bar-fill{background:#22c55e}
.risk-suspicious .risk-bar-fill{background:#f59e0b}
.risk-malicious .risk-bar-fill{background:#ef4444}
.risk-threshold{font-size:13px;color:#cbd5e1;margin-bottom:4px}
.risk-profile{font-size:12px;color:#64748b}
.empty{border:1px dashed #475569;border-radius:8px;padding:18px;text-align:center;color:#94a3b8;font-size:14px}
.toolbar{display:flex;flex-wrap:wrap;gap:8px;align-items:center;margin-bottom:12px}
.sev-filters{display:flex;gap:6px;flex-wrap:wrap}
.sev-btn{background:#334155;color:#cbd5e1;border:1px solid #475569;border-radius:6px;font-size:12px;padding:4px 11px;cursor:pointer}
.sev-btn.active{background:#0ea5e9;border-color:#0ea5e9;color:#fff;font-weight:600}
.toolbar input[type="search"]{flex:1;min-width:180px;background:#0f172a;border:1px solid #475569;color:#e2e8f0;border-radius:6px;font-size:13px;padding:6px 10px;font-family:inherit}
.toolbar input[type="search"]::placeholder{color:#64748b}
.toolbar-btn{background:#334155;color:#cbd5e1;border:1px solid #475569;border-radius:6px;font-size:12px;padding:6px 10px;cursor:pointer}
.toolbar-btn:hover{background:#475569;color:#fff}
.findings-table{width:100%;border-collapse:collapse;font-size:13.5px}
.findings-table th{text-align:left;font-size:11px;text-transform:uppercase;letter-spacing:.5px;color:#64748b;padding:8px 10px;border-bottom:1px solid #334155;white-space:nowrap}
.findings-table td{padding:12px 10px;border-bottom:1px solid #2b3a55;vertical-align:top}
.frow:hover td{background:#22314d}
.ftitle{font-weight:650;color:#f1f5f9}
.ftitle-en{font-size:12.5px;color:#94a3b8;margin:2px 0 6px}
.fdesc-body{color:#cbd5e1;font-size:13px}
.score{display:inline-block;min-width:30px;text-align:center;background:#0f172a;border:1px solid #334155;border-radius:6px;font-weight:700;padding:2px 6px;color:#f59e0b}
details.evidence summary{cursor:pointer;color:#38bdf8;font-size:12.5px;user-select:none}
details.evidence pre{background:#0d1424;border:1px solid #334155;border-radius:8px;padding:12px;margin-top:8px;font-size:12px;color:#cbd5e1;white-space:pre-wrap;word-break:break-all;max-height:320px;overflow:auto}
.perm-badge{display:inline-block;background:#312e81;color:#c7d2fe;border:1px solid #4338ca;border-radius:6px;font-size:12.5px;padding:4px 10px;margin:0 6px 8px 0}
.perm-count{font-size:12.5px;color:#94a3b8;margin-bottom:10px}
.ep-table{width:100%;border-collapse:collapse;font-size:13.5px}
.ep-table th{text-align:left;font-size:11px;text-transform:uppercase;letter-spacing:.5px;color:#64748b;padding:8px 10px;border-bottom:1px solid #334155}
.ep-table td{padding:10px;border-bottom:1px solid #2b3a55;word-break:break-all}
tr.ep-sus td{background:rgba(239,68,68,.08)}
tr.ep-sus td:first-child{color:#fca5a5;font-weight:650}
.kind-badge{background:#0f172a;border:1px solid #475569;color:#94a3b8}
.ep-score{font-weight:700}
.ep-score.sus{color:#ef4444}
.feature-badge{display:inline-block;background:#7f1d1d;color:#fecaca;border:1px solid #b91c1c;border-radius:4px;font-size:12px;padding:2px 8px;margin:0 4px 4px 0}
.feature-ok{background:#14532d;color:#bbf7d0;border-color:#16a34a}
.kv-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(230px,1fr));gap:10px 22px;margin-top:12px}
.kv{display:flex;flex-direction:column;gap:1px;min-width:0}
.kv-label{font-size:11px;text-transform:uppercase;letter-spacing:.5px;color:#64748b}
.kv-value{font-size:13.5px;color:#e2e8f0;word-break:break-all}
.kv-value.mono{font-size:12.5px}
.status-line{display:flex;flex-wrap:wrap;gap:8px;align-items:center;margin-top:4px}
.status-line .meta-note{font-size:13px;color:#94a3b8}
.warn-list{list-style:none}
.warn-list li{padding:8px 12px;border-left:3px solid #d97706;background:rgba(217,119,6,.08);border-radius:0 6px 6px 0;margin-bottom:6px;font-size:13px;color:#fde68a}
.note-box{margin-top:12px;background:#0f172a;border:1px solid #334155;border-radius:8px;padding:10px 14px;font-size:13px;color:#cbd5e1}
footer{text-align:center;color:#64748b;font-size:12.5px;padding:18px 0 6px}
footer .foot-sub{margin-top:4px;color:#475569;font-size:12px}
@media print{
  body{background:#fff;color:#111;padding:0}
  .card{background:#fff;border-color:#bbb;box-shadow:none;break-inside:avoid}
  .risk-card,.risk-score,.risk-bar-fill{-webkit-print-color-adjust:exact;print-color-adjust:exact}
  .toolbar,.copy-btn,details.evidence summary{display:none}
  details.evidence pre{max-height:none;color:#222;background:#f5f5f5}
  .findings-table th,.ep-table th{color:#444}
  footer{color:#555}
}
"""


# --- 内嵌脚本 / Embedded script（严重级别过滤 + 搜索 + 证据折叠 + 复制 SHA-256）---
_JS = """
(function () {
  'use strict';
  var rows = Array.prototype.slice.call(document.querySelectorAll('.frow'));
  var active = 'all', query = '';
  function applyFilter() {
    var q = query.toLowerCase();
    rows.forEach(function (r) {
      var okSev = (active === 'all') || (r.getAttribute('data-severity') === active);
      var okQ = !q || (r.textContent.toLowerCase().indexOf(q) !== -1);
      r.style.display = (okSev && okQ) ? '' : 'none';
    });
  }
  var btns = document.querySelectorAll('.sev-btn');
  for (var i = 0; i < btns.length; i++) {
    btns[i].addEventListener('click', function () {
      for (var j = 0; j < btns.length; j++) { btns[j].classList.remove('active'); }
      this.classList.add('active');
      active = this.getAttribute('data-sev');
      applyFilter();
    });
  }
  var input = document.getElementById('findings-search');
  if (input) { input.addEventListener('input', function () { query = this.value; applyFilter(); }); }
  var toggleBtn = document.getElementById('toggle-evidence');
  if (toggleBtn) {
    toggleBtn.addEventListener('click', function () {
      var open = toggleBtn.getAttribute('data-open') !== '1';
      toggleBtn.setAttribute('data-open', open ? '1' : '0');
      toggleBtn.textContent = open ? '收起全部 / Collapse all' : '展开全部 / Expand all';
      var ds = document.querySelectorAll('details.evidence');
      for (var k = 0; k < ds.length; k++) { ds[k].open = open; }
    });
  }
  function flashCopied(btn) {
    var old = btn.textContent;
    btn.textContent = '已复制 / Copied';
    setTimeout(function () { btn.textContent = old; }, 1500);
  }
  var copyBtn = document.getElementById('copy-sha');
  if (copyBtn) {
    copyBtn.addEventListener('click', function () {
      var sha = copyBtn.getAttribute('data-sha') || '';
      if (navigator.clipboard && navigator.clipboard.writeText) {
        navigator.clipboard.writeText(sha).then(function () { flashCopied(copyBtn); });
      } else {
        var ta = document.createElement('textarea');
        ta.value = sha; document.body.appendChild(ta); ta.select();
        try { document.execCommand('copy'); flashCopied(copyBtn); } catch (err) { /* clipboard unavailable */ }
        document.body.removeChild(ta);
      }
    });
  }
})();
"""


# --- 基础工具 / Small helpers ---
def _esc(value: Any) -> str:
    """HTML-escape any value for safe embedding in markup."""
    return "" if value is None else html.escape(str(value), quote=True)


def _text(value: Any, fallback: str = "-") -> str:
    """Return a usable display string, falling back to a placeholder."""
    if value is None:
        return fallback
    s = str(value).strip()
    return s if s else fallback


def _badge(text: str, cls: str) -> str:
    """Build a small pill badge."""
    return f'<span class="badge {cls}">{_esc(text)}</span>'


def _kv(label: str, value: Any, mono: bool = False) -> str:
    """Build one key/value grid item; empty values degrade to '-'."""
    cls = "kv-value mono" if mono else "kv-value"
    return (f'<div class="kv"><span class="kv-label">{_esc(label)}</span>'
            f'<span class="{cls}">{_esc(_text(value))}</span></div>')


def _fmt_size(size: Any) -> str:
    """Human-readable file size (bytes -> KB/MB/GB)."""
    try:
        n = float(size)
    except (TypeError, ValueError):
        return _text(size)
    units = ("B", "KB", "MB", "GB")
    i = 0
    while n >= 1024 and i < len(units) - 1:
        n /= 1024.0
        i += 1
    return f"{int(n)} {units[i]}" if i == 0 else f"{n:.1f} {units[i]}"


def _fmt_sha(sha: Any, head: int = 12, tail: int = 12) -> str:
    """Truncate a long hash for display, keeping head and tail."""
    s = _text(sha)
    if s == "-" or len(s) <= head + tail + 3:
        return s
    return f"{s[:head]}…{s[-tail:]}"


def _sev_badge(severity: Any) -> str:
    """Severity pill badge with bilingual label and stable color."""
    sev = str(severity or "info").lower()
    meta = {
        "critical": ("sev-critical", "严重 Critical"),
        "high": ("sev-high", "高危 High"),
        "medium": ("sev-medium", "中危 Medium"),
        "low": ("sev-low", "低危 Low"),
        "info": ("sev-info", "信息 Info"),
    }
    cls, label = meta.get(sev, meta["info"])
    return f'<span class="badge {cls}">{label}</span>'


def _risk_class(level: Any) -> str:
    """CSS class for the risk card, keyed by risk level."""
    return {
        "clean": "risk-clean",
        "suspicious": "risk-suspicious",
        "malicious": "risk-malicious",
    }.get(str(level).lower(), "risk-clean")


# --- 区块渲染 / Section renderers ---
def _render_header(rep: dict) -> str:
    """Header card: app identity, file metadata and SHA-256."""
    app = rep.get("app_info") or {}
    name = _text(app.get("app_name"), "未知应用 / Unknown App")
    pkg = _text(app.get("package"), "未知包名 / Unknown")
    version = _text(app.get("version"))
    fmt = _text(rep.get("file_format"))
    sha = _text(rep.get("sha256"))
    fname = _text(rep.get("file_name"))
    fsize = _fmt_size(rep.get("file_size"))
    rule_ver = _text(rep.get("rule_version"), "无 / None")
    sub = f"{_esc(pkg)}<span class=\"dot\">·</span>v{_esc(version)}"
    return f"""
<header class="card header-card">
  <div class="header-top">
    <svg class="logo" viewBox="0 0 24 24" fill="none" stroke="currentColor"
         stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
      <path d="M12 2l8 3.2v5.6c0 4.9-3.4 9.2-8 11.2-4.6-2-8-6.3-8-11.2V5.2z"></path>
      <path d="M8.5 12l2.3 2.3 4.7-4.7"></path>
    </svg>
    <div class="header-title">
      <h1>{_esc(name)}</h1>
      <div class="header-sub">{sub}</div>
    </div>
    <div class="header-badges">
      <span class="badge file-badge">{_esc(fmt)}</span>
    </div>
  </div>
  <div class="meta-grid">
    <div class="meta-item"><span class="meta-label">文件名称 / File Name</span>
      <span class="meta-value">{_esc(fname)}</span></div>
    <div class="meta-item"><span class="meta-label">文件格式 / Format</span>
      <span class="meta-value">{_esc(fmt)}</span></div>
    <div class="meta-item"><span class="meta-label">文件大小 / File Size</span>
      <span class="meta-value">{_esc(fsize)}</span></div>
    <div class="meta-item"><span class="meta-label">规则版本 / Rule Version</span>
      <span class="meta-value">{_esc(rule_ver)}</span></div>
    <div class="meta-item meta-sha"><span class="meta-label">SHA-256</span>
      <span class="meta-value mono">{_esc(sha)}</span>
      <button class="copy-btn" id="copy-sha" type="button" data-sha="{_esc(sha)}">复制 / Copy</button></div>
  </div>
</header>"""


def _render_risk_card(risk: dict) -> str:
    """Big risk overview card; colors follow clean/suspicious/malicious."""
    level = str(risk.get("risk_level") or "clean").lower()
    label = _text(risk.get("risk_label"), "未知 / Unknown")
    profile = _text(risk.get("severity_profile"), "-")
    try:
        score = int(risk.get("total_score"))
    except (TypeError, ValueError):
        score = 0
    thr = risk.get("threshold") or {}
    try:
        clean_below = int(thr["clean_below"]) if thr.get("clean_below") is not None else None
    except (TypeError, ValueError):
        clean_below = None
    try:
        mal_at = int(thr["malicious_at"]) if thr.get("malicious_at") is not None else None
    except (TypeError, ValueError):
        mal_at = None
    pct = max(0, min(100, score * 100 // mal_at)) if mal_at and mal_at > 0 else 0
    if clean_below is not None and mal_at is not None:
        thr_text = f"阈值 / Threshold: 低于 {clean_below} 分视为干净，达到 {mal_at} 分判定恶意 / clean &lt; {clean_below}, malicious ≥ {mal_at}"
    else:
        thr_text = "阈值 / Threshold: 未提供 / not provided"
    cls = _risk_class(level)
    return f"""
<section class="card risk-card {cls}">
  <div class="risk-main">
    <div class="risk-score-wrap">
      <div class="risk-score">{score}</div>
      <div class="risk-label">{_esc(label)}</div>
    </div>
    <div class="risk-meta">
      <div class="risk-title">风险总览 / Risk Overview</div>
      <div class="risk-bar"><div class="risk-bar-fill" style="width:{pct}%"></div></div>
      <div class="risk-threshold">{thr_text}</div>
      <div class="risk-profile">检测档位 / Severity Profile: {_esc(profile)}</div>
    </div>
  </div>
</section>"""


def _render_evidence(evidence: list, detail: dict) -> str:
    """Evidence + structured detail, rendered inside a collapsible <details>."""
    lines: list[str] = [str(e) for e in evidence or []]
    for k, v in (detail or {}).items():
        if isinstance(v, (list, tuple)):
            v = ", ".join(str(x) for x in v)
        lines.append(f"{k}: {v}")
    if not lines:
        return '<div class="fdesc-body">无详细信息 / No detailed evidence</div>'
    body = _esc("\n".join(lines))
    return ('<details class="evidence"><summary>证据 / Evidence</summary>'
            f"<pre>{body}</pre></details>")


def _render_findings(findings: list) -> str:
    """Findings table with severity badges, scores and expandable evidence."""
    if not findings:
        return """
<section class="card">
  <h2 class="card-title">检测发现 / Findings <span class="count">0</span></h2>
  <div class="empty">未发现可疑行为 / No suspicious findings detected</div>
</section>"""
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    ranked = sorted(findings,
                    key=lambda f: (-int(f.get("weight") or 0),
                                   order.get(str(f.get("severity")).lower(), 4)))
    rows = []
    for f in ranked:
        sev_key = str(f.get("severity") or "info").lower()
        rows.append(f"""
    <tr class="frow" data-severity="{sev_key}">
      <td>{_sev_badge(sev_key)}</td>
      <td><span class="score">{_text(f.get("weight"))}</span></td>
      <td>
        <div class="ftitle">{_esc(f.get("title") or "未知发现 / Unknown finding")}</div>
        <div class="ftitle-en">{_esc(f.get("title_en") or "")}</div>
        <div class="fdesc-body">{_esc(f.get("description") or "")}</div>
      </td>
      <td>{_render_evidence(f.get("evidence"), f.get("detail"))}</td>
    </tr>""")
    return f"""
<section class="card">
  <h2 class="card-title">检测发现 / Findings <span class="count">{len(findings)}</span></h2>
  <div class="toolbar">
    <div class="sev-filters">
      <button class="sev-btn active" data-sev="all" type="button">全部 / All</button>
      <button class="sev-btn" data-sev="critical" type="button">严重 Critical</button>
      <button class="sev-btn" data-sev="high" type="button">高危 High</button>
      <button class="sev-btn" data-sev="medium" type="button">中危 Medium</button>
      <button class="sev-btn" data-sev="low" type="button">低危 Low</button>
      <button class="sev-btn" data-sev="info" type="button">信息 Info</button>
    </div>
    <input id="findings-search" type="search"
           placeholder="搜索发现… / Search findings…" aria-label="搜索发现">
    <button class="toolbar-btn" id="toggle-evidence" type="button" data-open="0">展开全部 / Expand all</button>
  </div>
  <table class="findings-table">
    <thead><tr><th>严重级别 / Severity</th><th>分值 / Score</th><th>发现 / Finding</th><th>证据 / Evidence</th></tr></thead>
    <tbody>{''.join(rows)}
    </tbody>
  </table>
</section>"""


def _render_permissions(perms: dict) -> str:
    """Dangerous permissions as badges, with declared-total counter."""
    dangerous = perms.get("dangerous_declared") or []
    total = perms.get("all_declared_count")
    body = "".join(f'<span class="perm-badge">{_esc(p)}</span>' for p in dangerous)
    if not body:
        body = '<div class="empty">未声明危险权限 / No dangerous permissions declared</div>'
    total_txt = f"共声明 {_text(total)} 项权限 / {_text(total)} permissions declared in total"
    return f"""
<section class="card">
  <h2 class="card-title">危险权限 / Dangerous Permissions <span class="count">{len(dangerous)}</span></h2>
  <div class="perm-count">{_esc(total_txt)}</div>
  {body}
</section>"""


def _render_endpoints(endpoints: list) -> str:
    """Network endpoint table; suspicious rows (score > 0) are highlighted."""
    if not endpoints:
        return """
<section class="card">
  <h2 class="card-title">网络端点 / Network Endpoints <span class="count">0</span></h2>
  <div class="empty">未提取到网络端点 / No network endpoints extracted</div>
</section>"""
    kind_labels = {"domain": "域名 Domain", "ip": "IP 地址 IP", "url": "URL"}
    rows = []
    for ep in endpoints:
        endpoint = _text(ep.get("endpoint"))
        kind = kind_labels.get(str(ep.get("kind")), _text(ep.get("kind")))
        try:
            score = int(ep.get("score"))
        except (TypeError, ValueError):
            score = 0
        features = ep.get("features") or []
        if features:
            feats = "".join(
                f'<span class="feature-badge {"feature-ok" if score <= 0 else ""}">{_esc(x)}</span>'
                for x in features)
        else:
            feats = '<span class="meta-value">-</span>'
        sus_cls = "ep-sus" if score > 0 else ""
        score_cls = "ep-score sus" if score > 0 else "ep-score"
        rows.append(f"""
    <tr class="{sus_cls}">
      <td class="mono">{_esc(endpoint)}</td>
      <td><span class="badge kind-badge">{_esc(kind)}</span></td>
      <td>{feats}</td>
      <td><span class="{score_cls}">{score}</span></td>
    </tr>""")
    return f"""
<section class="card">
  <h2 class="card-title">网络端点 / Network Endpoints <span class="count">{len(endpoints)}</span></h2>
  <table class="ep-table">
    <thead><tr><th>端点 / Endpoint</th><th>类型 / Type</th><th>特征 / Features</th><th>分值 / Score</th></tr></thead>
    <tbody>{''.join(rows)}
    </tbody>
  </table>
</section>"""


def _render_signature(sig: dict) -> str:
    """Signing certificate info with validity / debug-key badges."""
    if not sig:
        return """
<section class="card">
  <h2 class="card-title">签名信息 / Signature Info</h2>
  <div class="empty">未提取到签名信息 / No signature information available</div>
</section>"""
    valid = bool(sig.get("valid"))
    valid_badge = _badge("签名有效 / Valid", "badge-ok") if valid else _badge("签名无效 / Invalid", "badge-bad")
    extra = ""
    if sig.get("self_signed"):
        extra += _badge("自签名 / Self-signed", "badge-warn")
    if sig.get("debug_key"):
        extra += _badge("调试签名 / Debug key", "badge-warn")
    warn_html = ""
    if sig.get("warnings"):
        warn_html = ('<ul class="warn-list">'
                     + "".join(f"<li>{_esc(w)}</li>" for w in sig["warnings"])
                     + "</ul>")
    dates = f"{_text(sig.get('not_before'))} → {_text(sig.get('not_after'))}"
    return f"""
<section class="card">
  <h2 class="card-title">签名信息 / Signature Info</h2>
  <div class="status-line">{valid_badge}{extra}</div>
  <div class="kv-grid">
    {_kv("签名方案 / Scheme", sig.get("signature_scheme"))}
    {_kv("颁发者 / Issuer", sig.get("issuer"))}
    {_kv("序列号 / Serial", sig.get("serial"), mono=True)}
    {_kv("证书指纹 / SHA-256", _fmt_sha(sig.get("sha256")), mono=True)}
    {_kv("有效期 / Validity", dates)}
  </div>
  {warn_html}
</section>"""


def _render_dynamic(dyn: dict) -> str:
    """Dynamic analysis status block, including the human-readable note."""
    status = str(dyn.get("status") or "not_executed").lower()
    status_badges = {
        "executed": ("badge-ok", "已执行 / Executed"),
        "degraded": ("badge-warn", "降级执行 / Degraded"),
        "skipped": ("badge-muted", "已跳过 / Skipped"),
        "not_executed": ("badge-muted", "未执行 / Not executed"),
    }
    cls, label = status_badges.get(status, status_badges["not_executed"])
    enabled = "是 / Yes" if dyn.get("enabled") else "否 / No"
    executed = "是 / Yes" if dyn.get("executed") else "否 / No"
    note = _text(dyn.get("note"), "无 / None")
    findings_html = ""
    if dyn.get("findings"):
        items = "".join(f"<li>{_esc(str(f))}</li>" for f in dyn["findings"])
        findings_html = f'<ul class="warn-list" style="margin-top:10px">{items}</ul>'
    return f"""
<section class="card">
  <h2 class="card-title">动态分析 / Dynamic Analysis</h2>
  <div class="status-line">{_badge(label, cls)}
    <span class="meta-note">启用 / Enabled: {enabled} · 已执行 / Executed: {executed}</span></div>
  <div class="kv-grid">
    {_kv("测试设备 / Device", dyn.get("device_used"))}
    {_kv("后端类型 / Backend", dyn.get("backend"))}
    {_kv("状态 / Status", label)}
  </div>
  <div class="note-box">{_esc(note)}</div>
  {findings_html}
</section>"""


def _render_warnings(warnings: list) -> str:
    """Parse warnings list; omitted entirely when empty."""
    if not warnings:
        return ""
    items = "".join(f"<li>{_esc(w)}</li>" for w in warnings)
    return f"""
<section class="card">
  <h2 class="card-title">解析警告 / Parse Warnings <span class="count">{len(warnings)}</span></h2>
  <ul class="warn-list">{items}</ul>
</section>"""


def _render_footer(rep: dict) -> str:
    """Footer with generator attribution and generation timestamp."""
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    rule_ver = _text(rep.get("rule_version"), "无 / None")
    return f"""
<footer>
  <p>apkguard 静态分析报告 / Generated by apkguard</p>
  <p class="foot-sub">生成时间 / Generated at: {ts} · 规则版本 / Rule Version: {_esc(rule_ver)}</p>
</footer>"""


# --- 公开 API / Public API ---
def render_html(report: dict) -> str:
    """Render a report dict into a complete self-contained HTML string.

    ``report`` 为 ``Report.to_dict()`` 的输出；对缺失/空字段安全，不会抛异常。
    """
    rep = report if isinstance(report, dict) else {}
    app = rep.get("app_info") or {}
    app_name = _text(app.get("app_name"), "未知应用 / Unknown App")
    sections = [
        _render_header(rep),
        _render_risk_card(rep.get("risk") or {}),
        _render_findings(rep.get("findings") or []),
        _render_permissions(rep.get("permissions") or {}),
        _render_endpoints(rep.get("network_endpoints") or []),
        _render_signature(rep.get("signature") or None),
        _render_dynamic(rep.get("dynamic") or {}),
        _render_warnings(rep.get("parse_warnings") or []),
        _render_footer(rep),
    ]
    page_title = f"{app_name} · apkguard 静态分析报告 / Static Analysis Report"
    return (
        '<!DOCTYPE html>\n<html lang="zh-CN">\n<head>\n'
        '<meta charset="utf-8">\n'
        '<meta name="viewport" content="width=device-width, initial-scale=1">\n'
        f"<title>{_esc(page_title)}</title>\n"
        f"<style>{_CSS}</style>\n"
        "</head>\n<body>\n"
        f'<div class="wrap">\n{"".join(sections)}\n</div>\n'
        f"<script>{_JS}</script>\n"
        "</body>\n</html>"
    )


def write_html_report(report_dict: dict, out_path: str | Path) -> None:
    """Render the report and write the HTML to ``out_path`` (UTF-8)."""
    html_text = render_html(report_dict)
    with open(out_path, "w", encoding="utf-8") as f:
        f.write(html_text)
