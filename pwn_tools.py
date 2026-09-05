"""
Pwn 辅助工具(识别二进制漏洞迹象,只做漏洞识别与风险提示,不生成任何利用代码/shellcode/ROP链)。
"""
import re


# 危险函数库:每条 = (漏洞类型, 危险函数正则, 风险说明, 排查方向)
PWN_DANGER = [
    ("栈溢出",
     r"\b(gets|strcpy|strcat|sprintf|scanf|read)\s*\(",
     "使用了不检查长度的输入函数,若缓冲区大小固定则可能栈溢出",
     "检查目标缓冲区大小与可写入长度;确认是否有边界检查"),

    ("格式化字符串",
     r"\b(printf|fprintf|sprintf|snprintf)\s*\(\s*\w+\s*\)",
     "printf类函数直接用变量作格式串,可能存在格式化字符串漏洞",
     "检查格式串是否可被用户控制;应使用固定格式串如 printf(\"%s\", buf)"),

    ("危险内存操作",
     r"\b(memcpy|memmove|alloca)\s*\(",
     "内存拷贝操作,若长度参数可控可能导致溢出",
     "检查拷贝长度是否来自不可信输入、是否超过目标大小"),

    ("命令执行(后门迹象)",
     r"\b(system|execve|execl)\s*\(",
     "存在系统命令执行调用,可能是后门函数或利用目标",
     "检查是否有直接调用system(\"/bin/sh\")的函数,常是Pwn题的目标"),

    ("整数问题",
     r"\b(malloc|calloc)\s*\(\s*\w+\s*[\*\+]",
     "内存分配大小涉及运算,可能存在整数溢出导致分配过小",
     "检查分配大小的计算是否可能溢出"),
]


def analyze_pwn_binary(code: str) -> dict:
    """分析C源码或反汇编,识别二进制漏洞迹象(栈溢出、格式化字符串等),给出风险点和排查方向。
    只做漏洞识别,不生成任何利用代码。输入为源码或反汇编文本。
    参数 code: 源代码或反汇编文本。"""
    findings = []
    lines = code.split("\n")

    for vuln_type, pattern, desc, direction in PWN_DANGER:
        for i, line in enumerate(lines, 1):
            if re.search(pattern, line, re.IGNORECASE):
                findings.append({
                    "line": i,
                    "vuln_type": vuln_type,
                    "code_snippet": line.strip()[:100],
                    "risk": desc,
                    "check_direction": direction,
                })

    # 检测是否有 /bin/sh 字符串(Pwn题常见目标)
    has_binsh = bool(re.search(r"/bin/sh|/bin/bash", code))

    return {
        "tool": "analyze_pwn_binary",
        "total_findings": len(findings),
        "vulnerabilities": findings,
        "has_binsh_string": has_binsh,   # 存在/bin/sh常是利用目标
        "note": "本工具仅识别漏洞迹象与风险点,不提供任何利用方法、shellcode或ROP构造。实际利用需由人工完成。",
    }


# ---------- 单独测试 ----------
if __name__ == "__main__":
    import json

    test_code = '''
    void vulnerable() {
        char buf[64];
        gets(buf);              // 栈溢出:gets不检查长度
        printf(buf);            // 格式化字符串漏洞
    }
    void backdoor() {
        system("/bin/sh");     // 后门函数
    }
    '''

    r = analyze_pwn_binary(test_code)
    print(json.dumps(r, ensure_ascii=False, indent=2))