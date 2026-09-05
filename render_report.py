import json
from pathlib import Path

BASE = Path(__file__).parent


def severity_color(sev: str) -> str:
    return {
        "CRITICAL": "#dc2626",
        "HIGH": "#ea580c",
        "MEDIUM": "#ca8a04",
        "LOW": "#16a34a",
    }.get((sev or "").upper(), "#6b7280")


def render():
    data = json.loads((BASE / "latest_report.json").read_text(encoding="utf-8"))

    target = data.get("target", "")
    started = data.get("started_at", "")
    finished = data.get("finished_at", "")
    total_rounds = data.get("total_rounds", 0)
    rounds = data.get("rounds", [])

    # 取最后一轮的最高风险作为总体结论
    final_risk = "unknown"
    if rounds:
        final_risk = rounds[-1]["decision"].get("highest_risk", "unknown")

    # 收集所有轮次里查到的 CVE(去重,按分数排序)
    cve_map = {}
    for r in rounds:
        intel = r.get("intel", {})
        for comp, info in intel.items():
            for cve in info.get("cves", []):
                cid = cve.get("id")
                if cid and cid not in cve_map:
                    cve_map[cid] = cve
    all_cves = sorted(cve_map.values(), key=lambda c: c.get("cvss_score") or 0, reverse=True)

    # ---------- 拼 HTML ----------
    rounds_html = ""
    for r in rounds:
        d = r["decision"]
        findings = "".join(f"<li>{f}</li>" for f in d.get("risk_findings", []))
        rounds_html += f"""
        <div class="round-card">
          <div class="round-head">
            <span class="round-no">第 {r['round']} 轮</span>
            <span class="round-focus">探测重点: {r['focus']}(强度 {r.get('intensity','')})</span>
          </div>
          <div class="round-body">
            <div class="kv"><b>匹配组件:</b> {', '.join(d.get('matched_components', []))}</div>
            <div class="kv"><b>最高风险:</b>
              <span class="badge" style="background:{severity_color(d.get('highest_risk',''))}">
                {d.get('highest_risk','').upper()}</span>
            </div>
            <div class="kv"><b>风险发现:</b><ul>{findings}</ul></div>
            <div class="reasoning"><b>决策依据:</b> {d.get('reasoning','')}</div>
            <div class="kv"><b>是否继续探测:</b> {'是' if d.get('need_more_recon') else '否(信息已充分,闭环收敛)'}</div>
          </div>
        </div>"""

    cve_rows = ""
    for c in all_cves:
        sev = c.get("severity", "")
        cve_rows += f"""
        <tr>
          <td class="cve-id">{c.get('id','')}</td>
          <td><span class="badge" style="background:{severity_color(sev)}">{sev}</span></td>
          <td class="score">{c.get('cvss_score','')}</td>
          <td class="summary">{c.get('summary','')}</td>
        </tr>"""

    html = f"""<!DOCTYPE html>
<html lang="zh">
<head>
<meta charset="utf-8">
<title>网络安全态势感知报告</title>
<style>
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{ font-family: "Segoe UI", "Microsoft YaHei", sans-serif;
    background: #0f172a; color: #e2e8f0; padding: 32px; line-height: 1.6; }}
  .container {{ max-width: 1100px; margin: 0 auto; }}
  h1 {{ font-size: 26px; margin-bottom: 4px; }}
  .subtitle {{ color: #94a3b8; margin-bottom: 24px; font-size: 14px; }}
  .overview {{ display: grid; grid-template-columns: repeat(4, 1fr);
    gap: 16px; margin-bottom: 28px; }}
  .stat {{ background: #1e293b; border-radius: 12px; padding: 18px; text-align: center; }}
  .stat .num {{ font-size: 24px; font-weight: 700; }}
  .stat .label {{ font-size: 12px; color: #94a3b8; margin-top: 4px; }}
  .section-title {{ font-size: 18px; margin: 24px 0 12px;
    border-left: 4px solid #3b82f6; padding-left: 10px; }}
  .badge {{ display: inline-block; padding: 2px 10px; border-radius: 999px;
    font-size: 12px; font-weight: 600; color: #fff; }}
  .flow {{ display: flex; align-items: center; gap: 12px; flex-wrap: wrap;
    background: #1e293b; border-radius: 12px; padding: 18px; margin-bottom: 8px; }}
  .flow .node {{ background: #334155; border-radius: 8px; padding: 10px 16px; font-size: 14px; }}
  .flow .arrow {{ color: #3b82f6; font-size: 18px; }}
  .round-card {{ background: #1e293b; border-radius: 12px; margin-bottom: 16px; overflow: hidden; }}
  .round-head {{ background: #334155; padding: 12px 18px; display: flex;
    justify-content: space-between; align-items: center; }}
  .round-no {{ font-weight: 700; color: #60a5fa; }}
  .round-focus {{ font-size: 13px; color: #cbd5e1; }}
  .round-body {{ padding: 16px 18px; }}
  .kv {{ margin-bottom: 10px; font-size: 14px; }}
  .kv ul {{ margin: 6px 0 0 20px; }}
  .kv li {{ margin-bottom: 4px; }}
  .reasoning {{ background: #0f172a; border-radius: 8px; padding: 12px;
    font-size: 13px; color: #cbd5e1; margin-bottom: 10px; }}
  table {{ width: 100%; border-collapse: collapse; background: #1e293b;
    border-radius: 12px; overflow: hidden; }}
  th, td {{ padding: 10px 14px; text-align: left; font-size: 13px;
    border-bottom: 1px solid #334155; }}
  th {{ background: #334155; }}
  .cve-id {{ font-family: monospace; color: #60a5fa; white-space: nowrap; }}
  .score {{ font-weight: 700; }}
  .summary {{ color: #cbd5e1; }}
  .footer {{ margin-top: 24px; font-size: 12px; color: #64748b; text-align: center; }}
</style>
</head>
<body>
<div class="container">
  <h1>网络安全自主态势感知报告</h1>
  <div class="subtitle">目标: {target} &nbsp;|&nbsp; 开始: {started} &nbsp;|&nbsp; 结束: {finished}</div>

  <div class="overview">
    <div class="stat"><div class="num">{target}</div><div class="label">授权目标</div></div>
    <div class="stat"><div class="num">{total_rounds}</div><div class="label">闭环轮数</div></div>
    <div class="stat"><div class="num">{len(all_cves)}</div><div class="label">命中 CVE</div></div>
    <div class="stat"><div class="num" style="color:{severity_color(final_risk)}">{final_risk.upper()}</div><div class="label">最高风险等级</div></div>
  </div>

  <div class="section-title">闭环决策流程</div>
  <div class="flow">
    <div class="node">态势感知<br><small>nmap + HTTP</small></div>
    <div class="arrow">→</div>
    <div class="node">情报比对<br><small>NVD 实时查询</small></div>
    <div class="arrow">→</div>
    <div class="node">风险研判<br><small>CVSS 分级</small></div>
    <div class="arrow">→</div>
    <div class="node">自主决策<br><small>调整 / 收敛</small></div>
    <div class="arrow">↻</div>
    <div class="node">授权门禁<br><small>越界即停</small></div>
  </div>

  <div class="section-title">逐轮决策过程</div>
  {rounds_html}

  <div class="section-title">命中的真实漏洞情报(来源: NVD 官方库)</div>
  <table>
    <tr><th>CVE 编号</th><th>严重度</th><th>CVSS</th><th>描述摘要</th></tr>
    {cve_rows}
  </table>

  <div class="footer">
    本报告由自主安全态势感知系统生成 · 全程只读信息收集 · 未进行任何漏洞利用或攻击操作<br>
    所有决策依据均已存档于 audit_logs/ 目录,支持审计与复现
  </div>
</div>
</body>
</html>"""

    out = BASE / "report.html"
    out.write_text(html, encoding="utf-8")
    print(f"可视化报告已生成: {out}")
    print(f"直接双击打开 report.html 即可查看")


if __name__ == "__main__":
    render()