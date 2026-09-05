import os
import asyncio
from pathlib import Path
from dotenv import load_dotenv
from autogen_agentchat.agents import AssistantAgent
from autogen_agentchat.ui import Console
from autogen_agentchat.teams import RoundRobinGroupChat
from autogen_agentchat.conditions import TextMentionTermination, MaxMessageTermination
from autogen_ext.models.openai import OpenAIChatCompletionClient
import warnings
warnings.filterwarnings("ignore", category=UserWarning)

load_dotenv(Path(__file__).parent / ".env")


def get_weather(city: str) -> str:
    """查询指定城市的当前天气。"""
    return f"{city}今天晴朗,气温25度。"


def add(a: float, b: float) -> float:
    """计算两个数字的和。"""
    return a + b


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

    writer = AssistantAgent(
        name="writer",
        model_client=model_client,
        system_message="你是一位文案写手。根据要求写作,并根据评审意见修改。只输出正文。",
    )

    reviewer = AssistantAgent(
        name="reviewer",
        model_client=model_client,
        system_message=(
            "你是一位极其挑剔的编辑。审阅文案时必须指出具体问题,"
            "比如用词陈词滥调、缺少差异化卖点、没有行动号召等,并给出可执行的修改方向。"
            "前两轮无论文案如何都必须提出至少两条改进意见,不允许通过。"
            "第三轮起如果确实达到专业水准,才只回复'通过'两个字。"
        ),
    )

    termination = TextMentionTermination("通过") | MaxMessageTermination(10)
    team = RoundRobinGroupChat([writer, reviewer], termination_condition=termination)

    await Console(team.run_stream(task="写一段50字的咖啡店开业宣传文案"))
    await model_client.close()


asyncio.run(main())