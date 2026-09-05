import os
import json
import asyncio
import subprocess
import urllib.request
import xml.etree.ElementTree as ET
from pathlib import Path
from datetime import datetime
from typing import List, Optional
from urllib.parse import urlparse

from dotenv import load_dotenv
from pydantic import BaseModel, Field
from autogen_ext.models.openai import OpenAIChatCompletionClient
from autogen_core.models import UserMessage, SystemMessage
from nvd_query import query_nvd
from tool_registry import get_tools_for, nmap_service_scan as reg_nmap

load_dotenv(Path(__file__).parent / ".env")

AUTHORIZED_SCOPE = {"127.0.0.1", "localhost"}
BASE = Path(__file__).parent


# ==================== 感知层(只读工具) ====================

def nmap_service_scan(target: str, intensity: int = 7) -> dict:
    """只读端口/服务识别。intensity 控制指纹探测强度(0-9),用于动态调整探测精度。"""
    if target not in AUTHORIZED_SCOPE:
        return {"error": "授权拒绝", "target": target}

    cmd = [
        "nmap", "-sV", "-Pn",
        "--version-intensity", str(intensity),
        "-p", "80,443,8080,8443,3306,6379,22,21,25,8000,8888,8009",
        "-oX", "-", target,
    ]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True,
                                encoding="utf-8", errors="ignore", timeout=180)
    except Exception as e:
        return {"error": f"扫描失败: {e}"}

    services = []
    try:
        root = ET.fromstring(result.stdout)
        for host in root.findall("host"):
            ports = host.find("ports")
            if ports is None:
                continue
            for port in ports.findall("port"):
                state = port.find("state")
                if state is None or state.get("state") != "open":
                    continue
                svc = port.find("service")
                services.append({
                    "port": int(port.get("portid")),
                    "service": svc.get("name", "") if svc is not None else "",
                    "product": svc.get("product", "") if svc is not None else "",
                    "version": svc.get("version", "") if svc is not None else "",
                })
    except ET.ParseError:
        pass
    return {"target": target, "services": services}


def fetch_http_headers(url: str) -> dict:
    """只读 HTTP 响应头。"""
    host = urlparse(url).hostname
    if host not in AUTHORIZED_SCOPE:
        return {"error": "授权拒绝", "url": url}
    try:
        req = urllib.request.Request(url, method="GET")
        with urllib.request.urlopen(req, timeout=15) as resp:
            return {"url": url, "status": resp.status, "headers": dict(resp.getheaders())}
    except Exception as e:
        return {"error": f"请求失败: {e}"}


def perceive(target: str, focus: str, intensity: int, focus_port: int = None) -> dict:
    """感知层(插件化):先用 nmap 发现服务,再对每个服务从注册表自动选择适用的只读工具执行。"""
    from tool_registry import get_tools_for, RISK_ACTIVE

    # 第一步:nmap 发现服务(nmap 本身也是注册表里的工具)
    nmap_result = reg_nmap(target, port=focus_port, intensity=intensity)
    services = nmap_result.get("services", [])

    result = {"nmap": {"target": target, "services": services}, "probes": []}

    # 第二步:对每个服务,从注册表自动选适用工具(nmap 已跑过,这里跑其余的)
    for svc in services:
        tools = get_tools_for(svc, max_risk=RISK_ACTIVE)
        for tool in tools:
            if tool.name == "nmap_service_scan":
                continue  # nmap 已经跑过了,跳过
            # 自动调用该工具
            probe_result = tool.func(target, port=svc["port"])
            result["probes"].append({
                "tool": tool.name,
                "risk": tool.risk,
                "port": svc["port"],
                "result": probe_result,
            })

    return result


# ==================== 研判层(决策 agent) ====================

class Decision(BaseModel):
    risk_findings: List[str] = Field(description="本轮识别出的风险点,每条含依据")
    matched_components: List[str] = Field(description="比对知识库后匹配到的组件名")
    highest_risk: str = Field(description="当前最高风险等级: low/medium/high/critical")
    need_more_recon: bool = Field(description="是否还需要进一步探测")
    next_focus: str = Field(description="若需继续,下一轮的探测重点是什么(仅限只读信息收集)")
    next_intensity: int = Field(description="下一轮建议的扫描强度 0-9", ge=0, le=9)
    next_focus_port: int = Field(default=0, description="下一轮要深入探测的端口号;0表示无需聚焦或已完成")
    reasoning: str = Field(description="做出以上决策的推理依据(可解释性)")


def gather_intel(perception: dict) -> dict:
    """根据感知结果,对识别出的每个组件查询 NVD 真实漏洞情报。"""
    intel = {}
    for svc in perception.get("nmap", {}).get("services", []):
        product = svc.get("product", "").strip()
        version = svc.get("version", "").strip()
        if not product:
            continue
        # 调 NVD 查这个组件+版本的真实 CVE
        result = query_nvd(product, version)
        intel[f"{product} {version}".strip()] = result
    return intel

async def judge(model_client, target: str, perception: dict, round_no: int) -> Decision:
    intel = gather_intel(perception)   # 查 NVD 真实漏洞情报
    kb = json.dumps(intel, ensure_ascii=False, indent=2)
    schema = json.dumps(Decision.model_json_schema(), ensure_ascii=False)

    sys_prompt = f"""你是网络安全态势研判 agent,运行在隔离授权环境中,只做只读的信息研判与决策。

你的职责:
1. 分析本轮感知层收集到的资产信息。
2. 与漏洞情报比对,识别风险点。
3. 多资产深入策略(重要,必须遵守):
   本轮首次全局扫描可能一次发现多个资产,但"发现存在"不等于"已完成深入研判"。
   你必须对每个资产逐一进行独立的深入研判,一轮只深入一个资产,以保证每个资产的
   风险评估都经过充分、独立的分析,并保留清晰的分轮决策审计轨迹。
   - 判断规则:检查本轮 perception 中是否只包含单一资产(说明是聚焦深入轮)。
     · 如果本轮 perception 里有多个服务(首轮全局扫描),说明各资产尚未逐一深入,
       必须设 need_more_recon=true,选择风险最高的一个资产作为下一轮聚焦目标
       (通常未授权访问的数据库如 Redis 优先级最高),
       在 next_focus 说明聚焦哪个资产及理由,next_focus_port 填该端口号。
     · 如果本轮 perception 里只有单一资产(聚焦深入轮),完成该资产研判后,
       检查是否还有其他已知但未深入的资产。若有,继续 need_more_recon=true 指向下一个;
       若所有资产都已逐一深入完毕,才设 need_more_recon=false 收敛。
   - 你可以在 reasoning 中记录"已完成深入的资产清单"和"待深入的资产清单",帮助判断。
4. 绝不决定进行任何漏洞利用或攻击动作。若发现高危点,只在 risk_findings 中提示"需人工确认后评估",不自动推进。

NVD官方漏洞情报(针对本轮识别出的组件实时查询,按CVSS从高到低):
{kb}

严格按以下 JSON Schema 输出,不要有多余文字:
{schema}"""

    user_msg = f"""这是第 {round_no} 轮态势研判。
目标: {target}
本轮感知结果:
{json.dumps(perception, ensure_ascii=False, indent=2)}

请研判并决策。注意:如果版本或组件已经足够明确、风险已判定清楚,应将 need_more_recon 设为 false 以结束循环;不要无休止探测。"""

    result = await model_client.create([
        SystemMessage(content=sys_prompt),
        UserMessage(content=user_msg, source="user"),
    ])
    raw = result.content.replace("```json", "").replace("```", "").strip()
    return Decision.model_validate_json(raw)


# ==================== 审计 ====================

def save_round(round_no: int, perception: dict, decision: Decision):
    log_dir = BASE / "audit_logs"
    log_dir.mkdir(exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    f = log_dir / f"loop_r{round_no}_{ts}.json"
    f.write_text(json.dumps({
        "round": round_no,
        "timestamp": ts,
        "perception": perception,
        "decision": decision.model_dump(),
    }, ensure_ascii=False, indent=2), encoding="utf-8")
    return f


# ==================== 编排循环 ====================

async def main():
    model_client = OpenAIChatCompletionClient(
        model="deepseek-chat",
        base_url="https://api.deepseek.com/v1",
        api_key=os.getenv("DEEPSEEK_API_KEY"),
        model_info={
            "vision": False, "function_calling": True, "json_output": True,
            "family": "unknown", "structured_output": True,
        },
    )

    target = "127.0.0.1"
    focus = "初始资产识别:识别所有开放端口和服务"
    intensity = 7
    MAX_ROUNDS = 4
    report = {"target": target, "started_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"), "rounds": []}

    print(f"\n{'='*60}\n开始对授权目标 {target} 进行闭环态势感知\n{'='*60}")

    for round_no in range(1, MAX_ROUNDS + 1):
        print(f"\n{'─'*60}")
        print(f"【第 {round_no} 轮】探测重点: {focus} (强度 {intensity})")
        print(f"{'─'*60}")

        # 1. 感知
        perception = perceive(target, focus, intensity)
        print(f"  [感知] {json.dumps(perception.get('nmap', {}), ensure_ascii=False)}")

        # 2. 研判决策
        decision = await judge(model_client, target, perception, round_no)

        # 3. 展示决策
        print(f"  [研判] 匹配组件: {decision.matched_components}")
        print(f"  [研判] 最高风险: {decision.highest_risk}")
        for rf in decision.risk_findings:
            print(f"         · {rf}")
        print(f"  [推理] {decision.reasoning}")

        # 4. 审计
        log = save_round(round_no, perception, decision)
        print(f"  [审计] 已存档: {log.name}")
        # 收集本轮数据用于可视化
        report["rounds"].append({
            "round": round_no,
            "focus": focus,
            "intensity": intensity,
            "perception": perception,
            "intel": gather_intel(perception),
            "decision": decision.model_dump(),
        })

        # 5. 动态调整:决定是否继续、下一轮重点
        if not decision.need_more_recon:
            print(f"\n{'='*60}")
            print(f"研判认为信息已充分,闭环结束(共 {round_no} 轮)")
            print(f"{'='*60}")
            break

        focus = decision.next_focus
        intensity = decision.next_intensity
        print(f"  [调整] → 下一轮重点: {focus}")
    else:
        print(f"\n达到最大轮次 {MAX_ROUNDS},结束。")

    report["finished_at"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    report["total_rounds"] = len(report["rounds"])
    (BASE / "latest_report.json").write_text(
        json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    print(f"\n可视化数据已生成: latest_report.json")

    await model_client.close()


if __name__ == "__main__":
    asyncio.run(main())