import os
import asyncio
import json
from pathlib import Path
from datetime import datetime
from tool_registry import get_tools_by_category

from dotenv import load_dotenv
from autogen_agentchat.agents import AssistantAgent
from autogen_agentchat.ui import Console
from autogen_ext.models.openai import OpenAIChatCompletionClient
from autogen_core import CancellationToken

from ctf_tools import identify_file, extract_strings, try_decode

load_dotenv(Path(__file__).parent / ".env")
BASE = Path(__file__).parent


# 工具包装:每个函数的 docstring 供模型判断何时调用该工具,不可删除。

def tool_identify_file(filepath: str) -> str:
    """识别文件的真实类型(通过文件头魔数,而非扩展名)。
    当你拿到一个文件、需要知道它真实是什么格式时使用。
    参数 filepath: 文件路径。"""
    return json.dumps(identify_file(filepath), ensure_ascii=False)


def tool_extract_strings(filepath: str) -> str:
    """抽取文件中的可见字符串,并自动查找疑似 flag 的内容。
    当你怀疑 flag 以明文藏在文件里时使用。
    参数 filepath: 文件路径。"""
    return json.dumps(extract_strings(filepath), ensure_ascii=False)


def tool_try_decode(text: str) -> str:
    """尝试多种编码解码(base64/hex/URL/rot13)。
    当你遇到一段看起来是编码过的字符串时使用。解出的结果如果仍是编码,可以再次调用本工具解下一层。
    参数 text: 要解码的字符串。"""
    return json.dumps(try_decode(text), ensure_ascii=False)


def tool_auto_analyze(text: str) -> str:
    """分析一段未知编码文本,判断它可能是什么编码类型,给出该用哪个解码工具的建议。
    当你遇到一段不确定是什么编码的文本时,先用这个识别类型。
    参数 text: 待分析的文本。"""
    from ctf_tools import auto_analyze_text
    return json.dumps(auto_analyze_text(text), ensure_ascii=False)


def tool_decode_morse(text: str) -> str:
    """莫尔斯电码解码。参数 text: 形如 '.... . .-.. .-.. ---' 的莫尔斯码。"""
    from ctf_tools import decode_morse
    return json.dumps(decode_morse(text), ensure_ascii=False)


def tool_decode_binary(text: str) -> str:
    """二进制转文本。参数 text: 形如 '01100110 01101100' 的二进制串。"""
    from ctf_tools import decode_binary
    return json.dumps(decode_binary(text), ensure_ascii=False)


def tool_decode_ascii(text: str) -> str:
    """ASCII码数字转文本。参数 text: 形如 '102 108 97 103' 的数字序列。"""
    from ctf_tools import decode_ascii
    return json.dumps(decode_ascii(text), ensure_ascii=False)


def tool_caesar_brute(text: str) -> str:
    """凯撒密码爆破,尝试全部25种字母移位,挑出疑似flag的结果。
    当你判断这是凯撒/移位类古典密码时使用。参数 text: 密文。"""
    from crypto_tools import caesar_brute
    return json.dumps(caesar_brute(text), ensure_ascii=False)


def tool_identify_crypto(text: str) -> str:
    """识别密文可能是什么密码类型(RSA/古典密码/编码等),给出分析方向和解题思路。
    当你拿到一段密文、不确定是什么加密时,先用这个识别。参数 text: 密文或密码参数。"""
    from crypto_tools import identify_crypto
    return json.dumps(identify_crypto(text), ensure_ascii=False)


def tool_analyze_web_code(code: str) -> str:
    """审计一段Web源代码,找出可疑漏洞点(SQL注入/命令注入/文件包含等),指出类型和排查方向。
    当任务给的是一段Web代码、需要做安全审计时使用。参数 code: 源代码。"""
    from web_tools import analyze_web_code
    return json.dumps(analyze_web_code(code), ensure_ascii=False)


def tool_analyze_disassembly(code: str) -> str:
    """分析反汇编或C伪代码,识别异或/比较/循环等逆向模式,辅助理解程序逻辑。
    当任务给的是反汇编代码或伪代码时使用。参数 code: 反汇编/伪代码文本。"""
    from reverse_tools import analyze_disassembly
    return json.dumps(analyze_disassembly(code), ensure_ascii=False)


def tool_analyze_pwn(code: str) -> str:
    """分析C源码或反汇编,识别二进制漏洞迹象(栈溢出/格式化字符串等),给出风险点和排查方向。
    当任务涉及二进制Pwn题、给了源码或反汇编时使用。参数 code: 源码或反汇编文本。"""
    from pwn_tools import analyze_pwn_binary
    return json.dumps(analyze_pwn_binary(code), ensure_ascii=False)


def tool_analyze_image(filepath: str) -> str:
    """分析图片文件的隐写:检测尾部附加数据、内嵌文件、可疑字符串、元数据。
    当任务涉及图片文件、可能有隐写时使用。参数 filepath: 图片路径。"""
    from ctf_tools import analyze_image
    return json.dumps(analyze_image(filepath), ensure_ascii=False)


CTF_SYSTEM_PROMPT = """你是一个 CTF(夺旗赛)分析助手,在人机协同比赛中帮助队伍分析题目、寻找 flag。

你具备自主决策能力:根据当前掌握的信息,自主判断该使用哪个工具、下一步该做什么。

可用工具:
- tool_identify_file(filepath): 识别文件真实类型(通过文件头,戳穿伪装的扩展名)
- tool_extract_strings(filepath): 抽取文件中的可见字符串,并自动查找疑似flag
- tool_try_decode(text): 尝试多种编码解码(base64/hex等),会自动解多层直到明文
- tool_auto_analyze(text): 识别一段文本可能是什么编码(遇到不确定的编码先用这个)
- tool_decode_morse(text): 莫尔斯电码解码
- tool_decode_binary(text): 二进制转文本
- tool_decode_ascii(text): ASCII码数字转文本
- tool_identify_crypto(text): 识别密文类型(RSA/古典密码等),给分析方向
- tool_caesar_brute(text): 凯撒密码爆破(古典密码解密)
- tool_analyze_web_code(code): 审计Web代码,找漏洞点和排查方向
- tool_analyze_disassembly(code): 分析反汇编/伪代码,识别逆向模式,辅助理解逻辑
- tool_analyze_pwn(code): 分析二进制Pwn题的源码/反汇编,识别栈溢出、格式化字符串等漏洞迹象

分析策略:
- 如果任务给的是【文件路径】:
  1. 先用 tool_identify_file 确认文件真实类型
  2. 再用 tool_extract_strings 抽取字符串,查看是否有明文 flag 或可疑编码串
  3. 如果抽出的字符串里有疑似编码的内容,用 tool_try_decode 解码
- 如果任务给的是【一段文本/编码】:
  直接用 tool_try_decode 解码
- 如果任务像是【密码学题目】(有密文、RSA参数、或疑似古典密码):
  先用 tool_identify_crypto 识别类型,再根据识别结果选工具
  (如识别为凯撒就用 tool_caesar_brute;识别为RSA则给出分析方向供人工推导)
- 如果任务给的是【一段Web源代码】,用 tool_analyze_web_code 做安全审计,
  指出可疑漏洞点、类型和排查方向(只做分析,不生成攻击payload,利用由人工完成)
- 如果任务给的是【反汇编代码或C伪代码】,用 tool_analyze_disassembly 分析逻辑,
  识别异或/比较/循环等模式,指出还原方向(辅助理解,具体破解由人工完成)
- 如果任务涉及【二进制Pwn题】(给了C源码或反汇编,涉及缓冲区、内存操作):
  用 tool_analyze_pwn 识别漏洞迹象(栈溢出/格式化字符串等),指出风险点和排查方向
  (只做漏洞识别,不生成shellcode/ROP/利用代码,实际利用由人工完成)
 - 遇到密码/密文题:优先用 tool_identify_crypto 识别类型。
  识别出类型后:
  · 如果是本工具能直接解的(凯撒/编码/维吉尼亚),调对应工具解
  · 如果是需要专业工具的(替换密码/RSA复杂攻击/未知类型),
    明确告诉用户是什么类型、推荐什么工具、解题思路是什么,不要硬解
- 如果任务给的是【图片文件路径】(.png/.jpg等):
  用 tool_analyze_image 检测隐写(尾部数据/内嵌文件/元数据),再用 extract_strings 抽字符串

工作原则:
1. 自主决策:你自己判断分析步骤,不要每一步都问用户。
2. 找到形如 flag{...} 或 xxx{...} 的内容就是找到了 flag,明确指出。
3. 你只做分析,不进行任何攻击或漏洞利用。
4. 每一步说明你的判断依据(为什么选这个工具、结果说明什么),保持决策可解释。

完成后清晰告诉用户:flag 是什么、你是怎么一步步分析出来的。

重要铁律:

- 如果一道题需要某种破解/计算,但你没有对应工具:不要硬着头皮手算!
  直接明确告诉用户:"这道题需要XX类型的破解,当前工具未覆盖,建议使用专业工具(如dCode/CyberChef),
  解题思路是XXX",然后停止。手算只会失败并浪费时间。
- 始终用中文回答,无论分析多复杂,最终结论必须是清晰的中文。
"""


async def analyze(task: str):
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
               tool_analyze_web_code,
               tool_analyze_disassembly,
               tool_analyze_pwn],
        system_message=CTF_SYSTEM_PROMPT,
        reflect_on_tool_use=True,
        max_tool_iterations=10,
    )

    audit_trail = []
    final_answer = ""

    async for msg in agent.run_stream(task=task):
        msg_type = type(msg).__name__

        if msg_type == "ToolCallRequestEvent":
            for call in msg.content:
                audit_trail.append({
                    "step": len(audit_trail) + 1,
                    "action": "调用工具",
                    "tool": call.name,
                    "arguments": call.arguments,
                })
                print(f"  [决策] 调用工具 {call.name}({call.arguments})")

        elif msg_type == "ToolCallExecutionEvent":
            for result in msg.content:
                audit_trail.append({
                    "step": len(audit_trail) + 1,
                    "action": "工具返回",
                    "tool": result.name,
                    "result": str(result.content)[:500],
                })

        elif msg_type == "ThoughtEvent":
            audit_trail.append({
                "step": len(audit_trail) + 1,
                "action": "思考",
                "content": str(msg.content)[:300],
            })

        elif msg_type == "TextMessage" and getattr(msg, "source", "") == "ctf_agent":
            final_answer = str(msg.content)
            print(f"\n  [结论]\n{final_answer}")

    save_ctf_audit(task, audit_trail, final_answer)
    await model_client.close()


def save_ctf_audit(task: str, audit_trail: list, final_answer: str):
    """保存 CTF 分析的完整审计日志:输入、每步决策与依据、最终结论,支持追溯与复现。"""
    log_dir = BASE / "audit_logs"
    log_dir.mkdir(exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    log_file = log_dir / f"ctf_{ts}.json"

    record = {
        "timestamp": ts,
        "task": task,
        "decision_trail": audit_trail,
        "final_answer": final_answer,
        "total_steps": len(audit_trail),
    }
    log_file.write_text(json.dumps(record, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"\n  [审计] 分析过程已存档: {log_file.name}(共 {len(audit_trail)} 步)")
    return log_file


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

    # agent 建在循环外只创建一次,以在多轮对话之间保留上下文
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

    print("=" * 60)
    print("CTF 分析助手 (连续对话模式)")
    print("直接输入密文/问题/文件路径,它会结合前面的对话分析")
    print("输入 `新题` 清空上下文开始新题;输入 `exit` 退出")
    print("=" * 60)

    while True:
        try:
            user_input = input("\n你 > ").strip()
        except (EOFError, KeyboardInterrupt):
            break

        if user_input.lower() in ("exit", "quit", "退出"):
            print("再见!")
            break
        # 换新题时清空上下文,避免历史无限累积
        if user_input in ("新题", "reset", "清空"):
            await agent.on_reset(CancellationToken())
            print("  已清空上下文,可以开始新的一道题了。")
            continue
        if not user_input:
            continue

        audit_trail = []
        final_answer = ""
        async for msg in agent.run_stream(task=user_input):
            msg_type = type(msg).__name__
            if msg_type == "ToolCallRequestEvent":
                for call in msg.content:
                    print(f"  [调用] {call.name}")
                    audit_trail.append({"action": "调用工具", "tool": call.name,
                                        "arguments": call.arguments})
            elif msg_type == "ToolCallExecutionEvent":
                for r in msg.content:
                    audit_trail.append({"action": "工具返回", "tool": r.name,
                                        "result": str(r.content)[:500]})
            elif msg_type == "TextMessage" and getattr(msg, "source", "") == "ctf_agent":
                final_answer = str(msg.content)
                print(f"\n助手 > {final_answer}")

        if audit_trail:
            save_ctf_audit(user_input, audit_trail, final_answer)

    await model_client.close()


if __name__ == "__main__":
    asyncio.run(main())