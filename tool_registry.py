"""
工具注册表 —— 插件化的安全工具管理核心。
每个探测工具通过 @register_tool 装饰器注册,自带元数据(名称、风险等级、适用条件)。
新增工具只需定义函数 + 加装饰器,无需改动任何调度或授权逻辑。
"""
import subprocess
import urllib.request
import xml.etree.ElementTree as ET
from urllib.parse import urlparse
from dataclasses import dataclass, field
from typing import Callable, List


# ---------- 风险等级(与授权门禁绑定) ----------
RISK_PASSIVE = "passive"      # 纯被动,无痕迹
RISK_ACTIVE = "active"        # 主动探测,有痕迹但只读
RISK_INTRUSIVE = "intrusive"  # 有副作用,禁止自动执行


@dataclass
class Tool:
    name: str
    description: str
    risk: str
    func: Callable
    applies_to: Callable
    category: str = "security"   # 工具领域: security(安全评估) / ctf(CTF分析)


# ---------- 全局注册表 ----------
_REGISTRY: List[Tool] = []


def register_tool(name, description, risk, applies_to, category="security"):
    def decorator(func):
        _REGISTRY.append(Tool(name=name, description=description,
                              risk=risk, func=func, applies_to=applies_to,
                              category=category))
        return func
    return decorator


def get_tools_for(service: dict, max_risk: str = RISK_ACTIVE) -> List[Tool]:
    """返回适用于该服务、且风险不超过 max_risk 的所有工具。
    这就是授权门禁:intrusive 工具默认不会被自动选中。"""
    risk_order = {RISK_PASSIVE: 0, RISK_ACTIVE: 1, RISK_INTRUSIVE: 2}
    limit = risk_order[max_risk]
    return [t for t in _REGISTRY
            if t.applies_to(service) and risk_order[t.risk] <= limit]

def get_tools_by_category(category: str) -> List[Tool]:
    """返回指定领域的所有工具(如所有 CTF 工具)。"""
    return [t for t in _REGISTRY if t.category == category]


def list_all_tools() -> List[Tool]:
    return list(_REGISTRY)


# ==================== 具体工具定义 ====================
# 加新工具 = 在这里加一个带 @register_tool 的函数,其它什么都不用改。

@register_tool(
    name="nmap_service_scan",
    description="端口与服务版本识别扫描",
    risk=RISK_ACTIVE,
    applies_to=lambda svc: True,   # 对所有资产适用
)
def nmap_service_scan(target: str, port: int = None, intensity: int = 7) -> dict:
    port_arg = str(port) if port else "80,443,8080,8443,3306,6379,22,21,25,8000,8888,8009"
    cmd = ["nmap", "-sV", "-Pn", "--version-intensity", str(intensity),
           "-p", port_arg, "-oX", "-", target]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True,
                                encoding="utf-8", errors="ignore", timeout=180)
    except Exception as e:
        return {"error": f"扫描失败: {e}"}

    services = []
    try:
        root = ET.fromstring(result.stdout)
        for host in root.findall("host"):
            ports = host.find("ports")
            if ports is None:
                continue
            for p in ports.findall("port"):
                state = p.find("state")
                if state is None or state.get("state") != "open":
                    continue
                svc = p.find("service")
                services.append({
                    "port": int(p.get("portid")),
                    "service": svc.get("name", "") if svc is not None else "",
                    "product": svc.get("product", "") if svc is not None else "",
                    "version": svc.get("version", "") if svc is not None else "",
                })
    except ET.ParseError:
        pass
    return {"tool": "nmap", "target": target, "services": services}


@register_tool(
    name="fetch_http_headers",
    description="读取 HTTP 响应头,识别应用层技术栈",
    risk=RISK_PASSIVE,
    applies_to=lambda svc: "http" in svc.get("service", "").lower()
                           or svc.get("port") in (80, 8080, 8000, 8888),
)
def fetch_http_headers(target: str, port: int = None, **kw) -> dict:
    port = port or 80
    url = f"http://{target}:{port}/"
    try:
        req = urllib.request.Request(url, method="GET")
        with urllib.request.urlopen(req, timeout=15) as resp:
            return {"tool": "http_headers", "url": url,
                    "status": resp.status, "headers": dict(resp.getheaders())}
    except Exception as e:
        return {"tool": "http_headers", "error": f"请求失败: {e}"}


@register_tool(
    name="redis_info_probe",
    description="对 Redis 服务发送只读的 INFO 探测,识别版本与配置态势(不读取任何数据键)",
    risk=RISK_ACTIVE,
    applies_to=lambda svc: "redis" in svc.get("service", "").lower()
                           or svc.get("port") == 6379,
)

def redis_info_probe(target: str, port: int = None, **kw) -> dict:
    """只读探测:发送 Redis INFO 命令,只取服务器元信息,不触碰业务数据。"""
    import socket
    port = port or 6379
    try:
        s = socket.create_connection((target, port), timeout=10)
        s.sendall(b"INFO server\r\n")
        data = s.recv(4096).decode("utf-8", errors="ignore")
        s.close()
        info = {}
        for line in data.splitlines():
            if ":" in line and not line.startswith("#"):
                k, v = line.split(":", 1)
                if k in ("redis_version", "os", "tcp_port", "redis_mode"):
                    info[k] = v.strip()
        unauth = "redis_version" in info
        return {"tool": "redis_info", "target": f"{target}:{port}",
                "reachable_without_auth": unauth, "server_info": info}
    except Exception as e:
        return {"tool": "redis_info", "error": f"探测失败: {e}"}

# ==================== CTF 分析工具 ====================
# 从 ctf_tools 导入实现,用装饰器注册进统一框架。
# 注意 applies_to 对 CTF 工具用输入类型判断(file/text),category 标为 "ctf"。

from ctf_tools import identify_file as _identify_file
from ctf_tools import extract_strings as _extract_strings
from ctf_tools import try_decode as _try_decode


@register_tool(
    name="identify_file",
    description="识别文件真实类型(通过文件头魔数,戳穿伪装的扩展名)",
    risk=RISK_PASSIVE,
    applies_to=lambda inp: inp.get("type") == "file",
    category="ctf",
)
def ctf_identify_file(target, port=None, **kw):
    filepath = kw.get("filepath") or target
    return _identify_file(filepath)


@register_tool(
    name="extract_strings",
    description="抽取文件中的可见字符串,自动查找疑似flag",
    risk=RISK_PASSIVE,
    applies_to=lambda inp: inp.get("type") == "file",
    category="ctf",
)
def ctf_extract_strings(target, port=None, **kw):
    filepath = kw.get("filepath") or target
    return _extract_strings(filepath)


@register_tool(
    name="try_decode",
    description="尝试多种编码解码(base64/hex等),自动解多层直到明文",
    risk=RISK_PASSIVE,
    applies_to=lambda inp: inp.get("type") == "text",
    category="ctf",
)
def ctf_try_decode(target, port=None, **kw):
    text = kw.get("text") or target
    return _try_decode(text)

def redis_info_probe(target: str, port: int = None, **kw) -> dict:
    """只读探测:发送 Redis INFO 命令,只取服务器元信息,不触碰业务数据。"""
    import socket
    port = port or 6379
    try:
        s = socket.create_connection((target, port), timeout=10)
        s.sendall(b"INFO server\r\n")
        data = s.recv(4096).decode("utf-8", errors="ignore")
        s.close()
        # 简单解析几个关键字段
        info = {}
        for line in data.splitlines():
            if ":" in line and not line.startswith("#"):
                k, v = line.split(":", 1)
                if k in ("redis_version", "os", "tcp_port", "redis_mode"):
                    info[k] = v.strip()
        # 判断未授权访问:能直接 INFO 成功说明无需认证
        unauth = "redis_version" in info
        return {"tool": "redis_info", "target": f"{target}:{port}",
                "reachable_without_auth": unauth, "server_info": info}
    except Exception as e:
        return {"tool": "redis_info", "error": f"探测失败: {e}"}


if __name__ == "__main__":
    print("=== 全部已注册工具(跨领域统一管理)===")
    for t in list_all_tools():
        print(f"  [{t.category}] {t.name} (风险:{t.risk}) — {t.description}")

    print("\n=== 安全评估领域的工具 ===")
    for t in get_tools_by_category("security"):
        print(f"  - {t.name}")

    print("\n=== CTF 分析领域的工具 ===")
    for t in get_tools_by_category("ctf"):
        print(f"  - {t.name}")

    print("\n=== 测试:CTF 解码工具是否正常 ===")
    import json
    r = ctf_try_decode("ZmxhZ3tyZWdpc3RyeV9va30=")  # flag{registry_ok} 的base64
    print(json.dumps(r, ensure_ascii=False))