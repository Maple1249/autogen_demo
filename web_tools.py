"""
Web 代码审计工具(纯分析:找可疑点、指漏洞类型、给排查方向,不生成利用payload)。
"""
import re


# 危险模式库:每条 = (漏洞类型, 危险模式正则, 说明, 排查方向)
DANGER_PATTERNS = [
    ("SQL注入",
     r"(SELECT|INSERT|UPDATE|DELETE|FROM|WHERE).*(\.\s*\$|\$_GET|\$_POST|\$_REQUEST|\{.*\}|%s|f['\"])",
     "SQL语句中可能拼接了用户输入/变量",
     "检查用户输入是否经过参数化查询/预编译;是否有过滤或转义"),

    ("命令注入",
     r"(system|exec|shell_exec|popen|passthru|os\.system|subprocess|eval)\s*\(",
     "调用了系统命令执行函数,若参数含用户输入则有命令注入风险",
     "检查传入的参数是否来自用户输入、是否有白名单校验"),

    ("文件包含",
     r"(include|require|include_once|require_once)\s*\(?\s*\$",
     "文件包含语句使用了变量,可能存在本地/远程文件包含",
     "检查被包含的路径是否可被用户控制;是否限定了目录"),

    ("反序列化",
     r"(unserialize|pickle\.loads|yaml\.load|marshal\.loads)\s*\(",
     "对数据进行了反序列化,若数据来自用户则可能触发反序列化漏洞",
     "检查反序列化的数据来源;是否使用了安全的反序列化方式"),

    ("XSS",
     r"(echo|print|innerHTML|document\.write).*(\$_GET|\$_POST|\$_REQUEST|request\.)",
     "输出中可能直接包含未转义的用户输入,存在跨站脚本风险",
     "检查输出前是否对用户输入做了HTML转义"),

    ("文件上传",
     r"(move_uploaded_file|\$_FILES|request\.files)",
     "存在文件上传处理,可能缺少类型/后缀校验",
     "检查是否校验了文件类型、后缀、内容;上传目录是否可执行"),

    ("弱口令/硬编码密钥",
     r"(password|passwd|secret|api_key|token)\s*=\s*['\"][^'\"]{1,20}['\"]",
     "代码中疑似硬编码了密码或密钥",
     "检查是否将敏感凭据硬编码在源码中"),
]


def analyze_web_code(code: str) -> dict:
    """审计一段 Web 代码,找出可疑的漏洞点,指出类型和排查方向(只做分析,不生成攻击payload)。
    参数 code: 待审计的源代码字符串。"""
    findings = []
    lines = code.split("\n")

    for vuln_type, pattern, desc, direction in DANGER_PATTERNS:
        for i, line in enumerate(lines, 1):
            if re.search(pattern, line, re.IGNORECASE):
                findings.append({
                    "line": i,
                    "vuln_type": vuln_type,
                    "code_snippet": line.strip()[:100],
                    "reason": desc,
                    "check_direction": direction,
                })

    return {
        "tool": "analyze_web_code",
        "total_findings": len(findings),
        "findings": findings,
        "note": "以上为静态分析发现的可疑点,需人工确认是否真实可利用。本工具仅做分析,不提供利用方法。",
    }


if __name__ == "__main__":
    import json

    test_code = '''<?php
$id = $_GET['id'];
$sql = "SELECT * FROM users WHERE id = " . $id;
$result = mysql_query($sql);

$file = $_GET['page'];
include($file);

$cmd = $_POST['cmd'];
system($cmd);

$data = $_POST['data'];
$obj = unserialize($data);

$api_key = "sk-12345secret";
?>'''

    r = analyze_web_code(test_code)
    print(json.dumps(r, ensure_ascii=False, indent=2))