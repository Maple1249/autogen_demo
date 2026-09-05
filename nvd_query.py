import os
import json
import time
import urllib.request
import urllib.parse
from pathlib import Path
from dotenv import load_dotenv

load_dotenv(Path(__file__).parent / ".env")

NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"

# 常见组件 → CPE(厂商:产品) 的映射表
CPE_MAP = {
    "apache tomcat": ("apache", "tomcat"),
    "tomcat": ("apache", "tomcat"),
    "nginx": ("nginx", "nginx"),
    "apache httpd": ("apache", "http_server"),
    "httpd": ("apache", "http_server"),
    "redis": ("redis", "redis"),
    "weblogic": ("oracle", "weblogic_server"),
    "openssh": ("openbsd", "openssh"),
    "mysql": ("oracle", "mysql"),
}


def query_nvd(product: str, version: str = "", max_results: int = 10) -> dict:
    """用 CPE 精确查询 NVD,返回指定产品+版本真正相关的 CVE(按 CVSS 从高到低)。
    只读情报查询,不涉及对目标系统的任何操作。
    """
    key = product.strip().lower()
    cpe_entry = CPE_MAP.get(key)

    params = {"resultsPerPage": str(max_results)}
    if cpe_entry and version:
        vendor, prod = cpe_entry
        cpe = f"cpe:2.3:a:{vendor}:{prod}:{version}"
        params["virtualMatchString"] = cpe
        query_desc = cpe
    else:
        params["keywordSearch"] = product.strip()
        query_desc = f"keyword:{product}"

    url = f"{NVD_API}?{urllib.parse.urlencode(params)}"
    headers = {}
    api_key = os.getenv("NVD_API_KEY")
    if api_key:
        headers["apiKey"] = api_key

    try:
        req = urllib.request.Request(url, headers=headers)
        with urllib.request.urlopen(req, timeout=30) as resp:
            data = json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        if e.code in (403, 429):
            return {"error": "NVD 限流,请稍后重试或配置 NVD_API_KEY", "query": query_desc}
        return {"error": f"NVD 查询失败: HTTP {e.code}", "query": query_desc}
    except Exception as e:
        return {"error": f"NVD 查询失败: {e}", "query": query_desc}

    cves = []
    for item in data.get("vulnerabilities", []):
        cve = item.get("cve", {})
        cve_id = cve.get("id", "")

        desc = ""
        for d in cve.get("descriptions", []):
            if d.get("lang") == "en":
                desc = d.get("value", "")
                break

        score, severity = None, ""
        metrics = cve.get("metrics", {})
        for mkey in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            if mkey in metrics and metrics[mkey]:
                m = metrics[mkey][0]
                cvss = m.get("cvssData", {})
                score = cvss.get("baseScore")
                severity = m.get("baseSeverity") or cvss.get("baseSeverity", "")
                break

        cves.append({
            "id": cve_id,
            "cvss_score": score,
            "severity": severity,
            "summary": desc[:200],
        })

    cves.sort(key=lambda c: c["cvss_score"] or 0, reverse=True)
    return {"query": query_desc, "count": len(cves), "cves": cves}


if __name__ == "__main__":
    print("测试查询 Apache Tomcat 8.5.19 ...")
    result = query_nvd("Apache Tomcat", "8.5.19")
    print(json.dumps(result, ensure_ascii=False, indent=2))