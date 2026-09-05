import os
import json
import asyncio
from pathlib import Path
from enum import Enum
from typing import List
from datetime import datetime

from dotenv import load_dotenv
from pydantic import BaseModel, Field
from autogen_ext.models.openai import OpenAIChatCompletionClient
from autogen_core.models import UserMessage, SystemMessage

load_dotenv(Path(__file__).parent / ".env")


# ---------- 1. 定义结构化输出的 schema ----------

class RiskLevel(str, Enum):
    """每个动作的风险等级,决定是否需要人工确认。"""
    passive = "passive"        # 纯被动/信息收集,无副作用
    active = "active"          # 主动探测,有痕迹但无破坏
    intrusive = "intrusive"    # 可能造成影响,必须人工授权


class SubTask(BaseModel):
    id: str = Field(description="子任务编号,如 T1、T2")
    name: str = Field(description="子任务简短名称")
    objective: str = Field(description="这一步要达成的具体目标")
    rationale: str = Field(description="为什么需要做这一步(可解释性依据)")
    depends_on: List[str] = Field(default_factory=list, description="依赖的前置子任务id")
    risk_level: RiskLevel = Field(description="该子任务的风险等级")
    requires_approval: bool = Field(description="执行前是否需要人工确认")


class ExecutionPlan(BaseModel):
    task_summary: str = Field(description="对整体任务的一句话概括")
    scope: List[str] = Field(description="授权范围内的目标(明确允许操作的对象)")
    out_of_scope: List[str] = Field(description="明确不得触碰的范围")
    subtasks: List[SubTask] = Field(description="有序的子任务列表")
    open_questions: List[str] = Field(
        default_factory=list,
        description="任务描述中不清晰、需要向发起方确认的点"
    )


# ---------- 2. 解析函数 ----------

PARSER_SYSTEM_PROMPT = """你是一个网络安全任务规划分析器,运行在一个隔离的授权测试环境中。
你的职责是把用户给出的安全任务描述,解析成一份结构化的执行计划。

重要原则:
1. 你只做"理解和规划",绝不生成任何具体的攻击载荷、exploit代码或命令。
   每个子任务的 objective 只描述"要达成什么",不描述"用什么payload"。
2. 严格区分风险等级。凡是可能对目标产生影响的动作(写入、利用、拒绝服务等),
   一律标记为 intrusive 且 requires_approval=true。
3. 如果任务描述里没有明确授权范围,必须在 open_questions 中提出,
   并把 scope 留空——没有明确授权就不假设授权。
4. 每个子任务都必须有 rationale,说明这一步的必要性和依据。

只输出符合 schema 的 JSON,不要有任何额外文字。"""


async def parse_task(task_description: str) -> ExecutionPlan:
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

    # 把 schema 塞进提示,让模型知道要输出什么结构
    schema_hint = json.dumps(ExecutionPlan.model_json_schema(), ensure_ascii=False, indent=2)

    messages = [
        SystemMessage(content=PARSER_SYSTEM_PROMPT),
        UserMessage(
            content=(
                f"请解析以下安全任务,并严格按这个 JSON Schema 输出:\n\n"
                f"{schema_hint}\n\n"
                f"任务描述:\n{task_description}"
            ),
            source="user",
        ),
    ]

    result = await model_client.create(messages)
    await model_client.close()

    # 清洗可能的 markdown 代码块包裹
    raw = result.content
    raw = raw.replace("```json", "").replace("```", "").strip()

    # 解析并用 Pydantic 校验——这一步保证输出结构合法
    plan = ExecutionPlan.model_validate_json(raw)
    return plan


# ---------- 3. 审计留痕 ----------

def save_audit_log(task_description: str, plan: ExecutionPlan):
    """把每次解析结果存档,满足可审计要求。"""
    log_dir = Path(__file__).parent / "audit_logs"
    log_dir.mkdir(exist_ok=True)

    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    log_file = log_dir / f"plan_{ts}.json"

    record = {
        "timestamp": ts,
        "input": task_description,
        "output": plan.model_dump(),
    }
    log_file.write_text(json.dumps(record, ensure_ascii=False, indent=2), encoding="utf-8")
    return log_file


# ---------- 4. 试运行 ----------

async def main():
    task = """在隔离靶场环境中,对内部测试用的 Web 应用(靶机地址 192.168.56.101)
进行一次安全评估,重点排查是否存在 SQL 注入和越权访问问题,
生成一份包含风险点和证据的评估报告。测试期间不得影响服务可用性。"""

    plan = await parse_task(task)

    # 打印结构化结果
    print("=" * 50)
    print(f"任务概括: {plan.task_summary}")
    print(f"授权范围: {plan.scope}")
    print(f"禁止范围: {plan.out_of_scope}")
    print("-" * 50)
    for st in plan.subtasks:
        flag = " ⚠需人工确认" if st.requires_approval else ""
        print(f"[{st.id}] {st.name} ({st.risk_level.value}){flag}")
        print(f"     目标: {st.objective}")
        print(f"     依据: {st.rationale}")
        if st.depends_on:
            print(f"     依赖: {st.depends_on}")
    if plan.open_questions:
        print("-" * 50)
        print("需向发起方确认的问题:")
        for q in plan.open_questions:
            print(f"  ? {q}")

    log_file = save_audit_log(task, plan)
    print("=" * 50)
    print(f"审计日志已保存: {log_file}")


if __name__ == "__main__":
    asyncio.run(main())