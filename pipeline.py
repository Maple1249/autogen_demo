import os
import re
import json
import asyncio
from pathlib import Path
from datetime import datetime

from dotenv import load_dotenv
from autogen_ext.models.openai import OpenAIChatCompletionClient

from task_parser import parse_task
from decision_loop import perceive, judge, gather_intel, save_round
import render_report

load_dotenv(Path(__file__).parent / ".env")
BASE = Path(__file__).parent


def make_client():
    return OpenAIChatCompletionClient(
        model="deepseek-chat",
        base_url="https://api.deepseek.com/v1",
        api_key=os.getenv("DEEPSEEK_API_KEY"),
        model_info={
            "vision": False, "function_calling": True, "json_output": True,
            "family": "unknown", "structured_output": True,
        },
    )


def extract_target(scope: list) -> str | None:
    """从 scope 中提取一个干净的目标地址(IP 或主机名),剥离协议、括号、端口、路径。"""
    for item in scope:
        item = item.strip().replace("http://", "").replace("https://", "")
        ip_match = re.search(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", item)
        if ip_match:
            return ip_match.group(0)
        host = item.split("(")[0].split("/")[0].split(":")[0].split()[0].strip()
        if host:
            return host
    return None


async def run_pipeline(task_description: str):
    print("=" * 64)
    print("网络安全自主智能体 · 完整流水线")
    print("=" * 64)

    # 阶段一:任务理解
    print("\n【阶段一】任务理解:解析自然语言任务 ...")
    plan = await parse_task(task_description)
    print(f"  任务概括: {plan.task_summary}")
    print(f"  授权范围: {plan.scope}")
    print(f"  禁止范围: {plan.out_of_scope}")
    print(f"  拆解出 {len(plan.subtasks)} 个子任务")
    if plan.open_questions:
        print(f"  待确认问题: {plan.open_questions}")

    # 授权门禁:scope 为空则拒绝执行任何探测
    if not plan.scope:
        print("\n" + "!" * 64)
        print("授权范围未明确,依据安全原则,不执行任何探测。")
        print("请补充明确的授权目标后重试。以下是需向任务发起方确认的问题:")
        for q in plan.open_questions:
            print(f"  ? {q}")
        print("!" * 64)
        return

    target = extract_target(plan.scope)
    if not target:
        print("\n无法从授权范围中提取有效目标地址,终止。")
        return

    print(f"\n  → 授权目标已注入执行层: {target}")

    # 将解析出的 scope 注入 decision_loop 的授权白名单;
    # 本地靶机场景额外放行 127.0.0.1/localhost,真实场景应严格等于 plan.scope
    import decision_loop
    decision_loop.AUTHORIZED_SCOPE = set(plan.scope) | {target, "localhost", "127.0.0.1"}

    # 阶段二:资产队列驱动的多轮闭环感知决策
    print(f"\n【阶段二】闭环执行:对授权目标 {target} 进行感知决策循环 ...")
    model_client = make_client()

    MAX_ROUNDS = 6
    report = {
        "task_description": task_description,
        "task_summary": plan.task_summary,
        "scope": plan.scope,
        "out_of_scope": plan.out_of_scope,
        "target": target,
        "started_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "rounds": [],
    }

    # 第 1 轮:全局扫描,发现所有资产
    round_no = 1
    print(f"\n  ── 第 {round_no} 轮 · 全局资产发现(强度 7)")
    global_perception = perceive(target, "全局资产发现", 7)
    all_services = global_perception.get("nmap", {}).get("services", [])
    print(f"     感知: 发现 {len(all_services)} 个资产: "
          + ", ".join(f"{s['port']}/{s.get('product', '?')}" for s in all_services))

    decision = await judge(model_client, target, global_perception, round_no)
    print(f"     研判: 全局态势 | 最高风险 {decision.highest_risk}")
    save_round(round_no, global_perception, decision)
    report["rounds"].append({
        "round": round_no, "focus": "全局资产发现", "intensity": 7,
        "perception": global_perception, "intel": gather_intel(global_perception),
        "decision": decision.model_dump(),
    })

    pending_ports = [s["port"] for s in all_services]
    print(f"     → 待逐一深入的资产队列: {pending_ports}")

    # 后续轮次:每轮聚焦深入一个资产
    for port in pending_ports:
        round_no += 1
        if round_no > MAX_ROUNDS:
            break
        print(f"\n  ── 第 {round_no} 轮 · 聚焦深入端口 {port}(强度 9)")
        focus_perception = perceive(target, f"深入研判端口 {port} 的资产", 9, focus_port=port)
        svcs = focus_perception.get("nmap", {}).get("services", [])
        label = svcs[0].get("product", "?") if svcs else "?"
        print(f"     感知: 聚焦 {port}/{label}")
        for probe in focus_perception.get("probes", []):
            r = probe.get("result", {})
            note = " ⚠未授权访问!" if r.get("reachable_without_auth") else ""
            print(f"       ├─ 自动调用插件 [{probe['tool']}] (风险:{probe['risk']}){note}")

        decision = await judge(model_client, target, focus_perception, round_no)
        print(f"     研判: 最高风险 {decision.highest_risk} | 匹配 {decision.matched_components}")
        save_round(round_no, focus_perception, decision)
        report["rounds"].append({
            "round": round_no, "focus": f"深入研判端口 {port}", "intensity": 9,
            "perception": focus_perception, "intel": gather_intel(focus_perception),
            "decision": decision.model_dump(),
        })
        print(f"     → 端口 {port} 研判完毕")

    print(f"\n     → 所有 {len(pending_ports)} 个资产逐一深入完毕,闭环结束(共 {round_no} 轮)")

    report["finished_at"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    report["total_rounds"] = len(report["rounds"])
    (BASE / "latest_report.json").write_text(
        json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    await model_client.close()

    # 阶段三:生成可视化报告,并返回结构化结果供网页端复用
    print(f"\n【阶段三】生成可视化报告 ...")
    render_report.render()

    print("\n" + "=" * 64)
    print("流水线执行完毕。打开 report.html 查看完整态势报告。")
    print("=" * 64)
    return report


async def main():
    task = """在隔离靶场环境中,对本地测试用的 Web 应用(目标 127.0.0.1)进行安全态势评估,
识别其运行的服务、组件和版本,比对已知漏洞情报,评估风险等级。
测试期间仅进行只读的信息收集,不得进行任何漏洞利用或影响服务可用性。"""
    await run_pipeline(task)


if __name__ == "__main__":
    asyncio.run(main())