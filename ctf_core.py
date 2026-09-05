"""
CTF 分析核心:把 Agent 分析逻辑包装成可复用函数,供命令行和网页后端调用。
"""
import os
import json
from pathlib import Path
from datetime import datetime

from dotenv import load_dotenv
from autogen_agentchat.agents import AssistantAgent
from autogen_ext.models.openai import OpenAIChatCompletionClient

# 复用 ctf_agent 里已经定义好的工具包装函数和系统提示
from ctf_agent import (
    tool_identify_file, tool_extract_strings, tool_try_decode,
    tool_auto_analyze, tool_decode_morse, tool_decode_binary, tool_decode_ascii,
    tool_identify_crypto, tool_caesar_brute,
    tool_analyze_web_code, tool_analyze_disassembly, tool_analyze_pwn,
    tool_analyze_image,
    CTF_SYSTEM_PROMPT,
)

load_dotenv(Path(__file__).parent / ".env")
BASE = Path(__file__).parent


def _make_agent():
    model_client = OpenAIChatCompletionClient(
        model="deepseek-chat",
        base_url="https://api.deepseek.com/v1",
        api_key=os.getenv("DEEPSEEK_API_KEY"),
        model_info={
            "vision": False, "function_calling": True, "json_output": True,
            "family": "unknown", "structured_output": True,
        },
    )
    agent = AssistantAgent(
        name="ctf_agent",
        model_client=model_client,
        tools=[tool_identify_file, tool_extract_strings, tool_try_decode,
               tool_auto_analyze, tool_decode_morse, tool_decode_binary, tool_decode_ascii,
               tool_identify_crypto, tool_caesar_brute,
               tool_analyze_web_code, tool_analyze_disassembly, tool_analyze_pwn,
               tool_analyze_image],
        system_message=CTF_SYSTEM_PROMPT,
        reflect_on_tool_use=True,
        max_tool_iterations=10,
    )
    return agent, model_client


async def analyze_once(task: str) -> dict:
    """跑一次 CTF 分析,返回结构化结果:决策步骤 + 最终答案。
    命令行和网页后端都调这个函数。"""
    agent, model_client = _make_agent()

    steps = []          # 决策过程(每步调了什么工具、返回什么)
    final_answer = ""

    async for msg in agent.run_stream(task=task):
        msg_type = type(msg).__name__
        if msg_type == "ToolCallRequestEvent":
            for call in msg.content:
                steps.append({"type": "tool_call", "tool": call.name,
                              "arguments": call.arguments})
        elif msg_type == "ToolCallExecutionEvent":
            for r in msg.content:
                steps.append({"type": "tool_result", "tool": r.name,
                              "result": str(r.content)[:800]})
        elif msg_type == "TextMessage" and getattr(msg, "source", "") == "ctf_agent":
            final_answer = str(msg.content)

    await model_client.close()

    # 存审计日志
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    log_dir = BASE / "audit_logs"
    log_dir.mkdir(exist_ok=True)
    (log_dir / f"ctf_{ts}.json").write_text(
        json.dumps({"timestamp": ts, "task": task, "steps": steps,
                    "final_answer": final_answer}, ensure_ascii=False, indent=2),
        encoding="utf-8")

    return {
        "task": task,
        "steps": steps,            # 决策过程
        "final_answer": final_answer,  # 最终结论
        "total_steps": len(steps),
    }


# 单独测试
if __name__ == "__main__":
    import asyncio

    async def test():
        result = await analyze_once("解码这段:ZmxhZ3t0ZXN0fQ==")
        print("=== 决策步骤 ===")
        for s in result["steps"]:
            if s["type"] == "tool_call":
                print(f"  调用 {s['tool']}({s['arguments']})")
        print(f"\n=== 最终答案 ===\n{result['final_answer']}")

    asyncio.run(test())