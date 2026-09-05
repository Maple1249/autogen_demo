import os
import json
import asyncio
from pathlib import Path
from datetime import datetime
from enum import Enum

from dotenv import load_dotenv
from pydantic import BaseModel, Field
from autogen_ext.models.openai import OpenAIChatCompletionClient
from autogen_core.models import UserMessage, SystemMessage

load_dotenv(Path(__file__).parent / ".env")
BASE = Path(__file__).parent


class TaskType(str, Enum):
    security_assessment = "security_assessment"   # 安全评估/态势感知
    ctf_analysis = "ctf_analysis"                 # CTF 分析解题
    unclear = "unclear"                           # 无法判断,需澄清


class TaskClassification(BaseModel):
    task_type: TaskType = Field(description="任务类型")
    confidence: str = Field(description="判断置信度: high/medium/low")
    reasoning: str = Field(description="做出此分类的依据(可解释)")
    key_signals: list = Field(description="任务描述中支持此分类的关键信号")


CLASSIFIER_PROMPT = """你是一个网络安全任务分类器,是通用安全智能体的调度中枢。
你的职责:阅读用户的安全任务描述,自主判断它属于哪一类,以便分派给对应的处理模块。

任务类型:
1. security_assessment(安全评估/态势感知): 涉及对目标系统/IP/网络进行资产识别、
   端口服务扫描、漏洞比对、风险态势评估等。典型信号:目标IP、端口、资产、扫描、
   态势评估、渗透测试的信息收集阶段、漏洞排查。
2. ctf_analysis(CTF分析): 涉及分析CTF题目、附件文件、编码解码、寻找flag等。
   典型信号:flag、解码、base64、附件、题目文件、隐写、CTF、找出隐藏信息。
3. unclear: 描述太模糊,无法判断属于哪类,需要向用户澄清。

请给出分类、置信度、判断依据和关键信号。严格按JSON Schema输出,不要多余文字。"""


async def classify_task(model_client, task: str) -> TaskClassification:
    schema = json.dumps(TaskClassification.model_json_schema(), ensure_ascii=False)
    result = await model_client.create([
        SystemMessage(content=CLASSIFIER_PROMPT),
        UserMessage(content=f"请分类以下任务,按此Schema输出:\n{schema}\n\n任务:\n{task}",
                    source="user"),
    ])
    raw = result.content.replace("```json", "").replace("```", "").strip()
    return TaskClassification.model_validate_json(raw)


async def dispatch(task: str):
    print("=" * 64)
    print("通用网络安全智能体 · 统一入口")
    print("=" * 64)
    print(f"\n收到任务: {task}\n")

    model_client = OpenAIChatCompletionClient(
        model="deepseek-chat",
        base_url="https://api.deepseek.com/v1",
        api_key=os.getenv("DEEPSEEK_API_KEY"),
        model_info={
            "vision": False, "function_calling": True, "json_output": True,
            "family": "unknown", "structured_output": True,
        },
    )

    print("【任务分类】自主判断任务类型 ...")
    classification = await classify_task(model_client, task)
    print(f"  → 判定类型: {classification.task_type.value}")
    print(f"  → 置信度: {classification.confidence}")
    print(f"  → 判断依据: {classification.reasoning}")
    print(f"  → 关键信号: {classification.key_signals}")

    save_dispatch_log(task, classification)
    await model_client.close()

    print(f"\n【任务分派】")
    if classification.task_type == TaskType.security_assessment:
        print("  → 分派给【态势感知模块】处理\n")
        from pipeline import run_pipeline
        await run_pipeline(task)

    elif classification.task_type == TaskType.ctf_analysis:
        print("  → 分派给【CTF分析模块】处理\n")
        from ctf_agent import analyze
        await analyze(task)

    else:
        print("  → 任务描述不够明确,无法自动分派。")
        print("  → 需要用户澄清:这是对目标系统的安全评估,还是CTF题目分析?")


def save_dispatch_log(task: str, classification: TaskClassification):
    log_dir = BASE / "audit_logs"
    log_dir.mkdir(exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    log_file = log_dir / f"dispatch_{ts}.json"
    log_file.write_text(json.dumps({
        "timestamp": ts,
        "task": task,
        "classification": classification.model_dump(),
    }, ensure_ascii=False, indent=2), encoding="utf-8")
    return log_file


async def main():
    task = "对本地测试Web应用(127.0.0.1)进行只读安全态势评估"
    # 也可换成 CTF 任务,例如: task = "分析密文 ZmxhZ3t0ZXN0fQ=="
    await dispatch(task)


if __name__ == "__main__":
    asyncio.run(main())