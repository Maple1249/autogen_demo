"""
态势感知核心：把 run_pipeline 包装成可复用函数，供命令行和网页后端调用。
"""
from pathlib import Path
from pipeline import run_pipeline   # ← 如果你的文件名不是 pipeline，改成实际的

BASE = Path(__file__).parent


async def assess_once(task: str) -> dict:
    """跑一次态势感知，返回结构化摘要（report.html 会同时生成）。"""
    report = await run_pipeline(task)

    if not report:   # 授权不明确等情况，run_pipeline 可能提前返回 None
        return {
            "ok": False,
            "message": "任务未通过授权解析，未执行探测。请提供明确的授权目标。",
        }

    rounds = report.get("rounds", [])
    last = rounds[-1]["decision"] if rounds else {}

    return {
        "ok": True,
        "target": report.get("target"),
        "total_rounds": report.get("total_rounds", len(rounds)),
        "highest_risk": last.get("highest_risk", "unknown"),
        "matched_components": last.get("matched_components", []),
        "report_url": "/report",   # 前端点这个链接看完整可视化报告
    }