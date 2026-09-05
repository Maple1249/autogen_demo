import os
import json
import asyncio
import subprocess
import urllib.request
import xml.etree.ElementTree as ET
from pathlib import Path
from datetime import datetime
from typing import List
from urllib.parse import urlparse

from dotenv import load_dotenv
from pydantic import BaseModel, Field
from autogen_agentchat.agents import AssistantAgent
from autogen_agentchat.ui import Console
from autogen_ext.models.openai import OpenAIChatCompletionClient
import warnings
warnings.filterwarnings("ignore", category=UserWarning)

load_dotenv(Path(__file__).parent / ".env")


# ---------- 授权范围 ----------
AUTHORIZED_SCOPE = {"127.0.0.1", "localhost"}


# ---------- 工具1:nmap 服务扫描(只读) ----------

def nmap_service_scan(target: str) -> str:
    """对授权范围内的目标进行只读的端口与服务版本识别扫描。
    信息收集级操作,不发送攻击载荷、不利用漏洞。仅允许扫描授权白名单内的地址。

    参数:
        target: 目标 IP 或主机名,必须在授权范围内。
    返回:
        JSON字符串,包含开放端口、服务类型、软件名和版本。
    """
    if target not in AUTHORIZED_SCOPE:
        return json.dumps({
            "error": "授权拒绝",
            "detail": f"目标 {target} 不在授权范围 {list(AUTHORIZED_SCOPE)} 内,拒绝扫描。",
        }, ensure_ascii=False)

    cmd = [
        "nmap", "-sV", "-Pn",
        "-p", "80,443,8080,8443,3306,6379,22,21,25,8000,8888",
        "-oX", "-", target,
    ]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
    except FileNotFoundError:
        return json.dumps({"error": "nmap 未安装或不在 PATH 中"}, ensure_ascii=False)
    except subprocess.TimeoutExpired:
        return json.dumps({"error": "扫描超时"}, ensure_ascii=False)

    services: List[dict] = []
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
                    "protocol": port.get("protocol"),
                    "state": state.get("state"),
                    "service": svc.get("name", "") if svc is not None else "",
                    "product": svc.get("product", "") if svc is not None else "",
                    "version": svc.get("version", "") if svc is not None else "",
                })
    except ET.ParseError:
        return json.dumps({"error": "无法解析扫描结果"}, ensure_ascii=False)

    return json.dumps({"target": target, "services": services}, ensure_ascii=False)


# ---------- 工具2:HTTP 响应头探测(只读) ----------

def fetch_http_headers(url: str) -> str:
    """向授权范围内的 HTTP 服务发起一次请求,只读取响应头(不读取响应体)。
    用于识别应用层技术栈,如 Server、X-Powered-By 等字段。
    信息收集级操作,不提交任何数据、不利用漏洞。仅允许请求授权白名单内的地址。

    参数:
        url: 完整的 HTTP URL,例如 http://127.0.0.1:8080/,主机部分必须在授权范围内。
    返回:
        JSON字符串,包含状态码和响应头字段。
    """
    host = urlparse(url).hostname
    if host not in AUTHORIZED_SCOPE:
        return json.dumps({
            "error": "授权拒绝",
            "detail": f"主机 {host} 不在授权范围 {list(AUTHORIZED_SCOPE)} 内,拒绝请求。",
        }, ensure_ascii=False)

    try:
        req = urllib.request.Request(url, method="HEAD")
        with urllib.request.urlopen(req, timeout=15) as resp:
            headers = dict(resp.getheaders())
            return json.dumps({
                "url": url,
                "status": resp.status,
                "headers": headers,
            }, ensure_ascii=False)
    except Exception as e:
        # HEAD 不被支持时退回 GET 只读头
        try:
            req = urllib.request.Request(url, method="GET")
            with urllib.request.urlopen(req, timeout=15) as resp:
                headers = dict(resp.getheaders())
                return json.dumps({
                    "url": url, "status": resp.status, "headers": headers,
                }, ensure_ascii=False)
        except Exception as e2:
            return json.dumps({"error": f"请求失败: {e2}"}, ensure_ascii=False)


# ---------- 审计留痕 ----------

def save_audit(target: str, agent_output: str):
    log_dir = Path(__file__).parent / "audit_logs"
    log_dir.mkdir(exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    log_file = log_dir / f"recon_{ts}.json"
    log_file.write_text(json.dumps({
        "timestamp": ts, "target": target, "result": agent_output,
    }, ensure_ascii=False, indent=2), encoding="utf-8")
    return log_file


# ---------- 感知 agent ----------

RECON_SYSTEM_PROMPT = """你是一个网络安全态势感知 agent,运行在隔离的授权测试环境中。
你的职责是对授权目标进行只读的资产识别,产出结构化的资产画像。

可用工具(你只能使用下面这两个,严禁臆造或调用任何其他工具):
1. nmap_service_scan(target): 端口与服务版本识别
2. fetch_http_headers(url): 读取 HTTP 响应头,识别应用层技术栈

工作流程:
1. 先用 nmap_service_scan 识别开放端口和服务。
2. 如果发现 HTTP 类服务,再用 fetch_http_headers 抓取响应头做交叉验证。
3. 综合两种手段的结果,生成最终资产画像。

工作原则:
- 只做信息收集与态势感知,绝不进行漏洞利用、攻击或破坏性操作。
- 若工具返回"授权拒绝",不得尝试绕过。
- 绝对不要调用未提供的工具。如果你觉得需要某个不存在的能力,就用现有信息作答,不要虚构工具调用。

最终输出用中文,包含:
- 资产画像:每个开放端口的服务、软件、版本,以及 HTTP 头透露的技术栈信息
- 交叉验证:说明 nmap 和 HTTP 头两种手段是否互相印证
- 初步风险提示:对每个服务指出需要关注的点(仅提示,不提供利用方法),并说明依据
"""


async def main():
    model_client = OpenAIChatCompletionClient(
        model="deepseek-chat",
        base_url="https://api.deepseek.com/v1",
        api_key=os.getenv("DEEPSEEK_API_KEY"),
        model_info={
            "vision": False,
            "function_calling": True,
            "json_output": True,
            "family": "unknown",
            "structured_output": True,
        },
    )

    agent = AssistantAgent(
        name="recon_agent",
        model_client=model_client,
        tools=[nmap_service_scan, fetch_http_headers],
        system_message=RECON_SYSTEM_PROMPT,
        reflect_on_tool_use=True,
        max_tool_iterations=5,   # 允许多轮工具调用,让它先nmap再抓头
    )

    target = "127.0.0.1"
    task = f"请对授权目标 {target} 进行资产识别扫描,先做端口服务识别,若有HTTP服务再抓取响应头交叉验证,最后生成完整资产画像和风险提示。"

    result = await Console(agent.run_stream(task=task))

    final_text = result.messages[-1].content if result.messages else ""
    log_file = save_audit(target, str(final_text))
    print(f"\n审计日志已保存: {log_file}")

    await model_client.close()


if __name__ == "__main__":
    asyncio.run(main())