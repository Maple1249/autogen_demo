"""
CTF 分析工具集(纯 Python 实现,无外部依赖)。
每个工具都是只读分析,不产出攻击载荷。
"""
import base64
import binascii
import re
import codecs
from urllib.parse import unquote

import magic  # python-magic-bin 提供


def identify_file(filepath: str) -> dict:
    """识别文件真实类型(通过文件头魔数,而非扩展名)。
    CTF 常把文件伪装成别的扩展名,这一步戳穿伪装。"""
    try:
        file_type = magic.from_file(filepath)
        mime = magic.from_file(filepath, mime=True)

        with open(filepath, "rb") as f:
            header = f.read(16)
        header_hex = header.hex()

        return {
            "tool": "identify_file",
            "filepath": filepath,
            "detected_type": file_type,
            "mime": mime,
            "header_hex": header_hex,
        }
    except Exception as e:
        return {"tool": "identify_file", "error": f"识别失败: {e}"}


def extract_strings(filepath: str, min_len: int = 4) -> dict:
    """抽取文件里的可见字符串(相当于 Linux 的 strings 命令)。
    flag 经常直接以明文藏在文件里,这一步能直接抓出来。"""
    try:
        with open(filepath, "rb") as f:
            data = f.read()

        pattern = rb"[\x20-\x7e]{%d,}" % min_len
        found = re.findall(pattern, data)
        strings_list = [s.decode("ascii", errors="ignore") for s in found]

        flag_like = [s for s in strings_list
                     if re.search(r"(flag|ctf|key)\{.*\}", s, re.IGNORECASE)]

        return {
            "tool": "extract_strings",
            "total_strings": len(strings_list),
            "flag_like": flag_like,
            "sample": strings_list[:30],
        }
    except Exception as e:
        return {"tool": "extract_strings", "error": f"抽取失败: {e}"}


def try_decode(text: str, max_depth: int = 20) -> dict:
    """尝试多种编码解码。对 base64/hex 会自动递归解码多层,直到得到可读明文或无法继续。
    CTF 里 flag 常被套多层编码,本工具一次性解到底。"""

    def looks_like_flag(s):
        return bool(re.search(r"[a-zA-Z0-9_]{2,}\{.*\}", s))

    def is_readable(s):
        # 可打印、且不像纯 base64/hex 长串,才算最终明文
        if not s or not s.isprintable():
            return False
        if re.fullmatch(r"[A-Za-z0-9+/=]{16,}", s):
            return False
        if re.fullmatch(r"[0-9a-fA-F]{16,}", s):
            return False
        return True

    layers = []
    current = text.strip()

    for depth in range(max_depth):
        decoded = None
        method = None

        try:
            d = base64.b64decode(current, validate=True).decode("utf-8", errors="strict")
            if d and d != current:
                decoded, method = d, "base64"
        except Exception:
            pass

        if decoded is None:
            try:
                d = binascii.unhexlify(current.strip()).decode("utf-8", errors="strict")
                if d and d != current:
                    decoded, method = d, "hex"
            except Exception:
                pass

        if decoded is None:
            break

        layers.append({"depth": depth + 1, "method": method, "result": decoded[:100]})
        current = decoded

        if looks_like_flag(decoded):
            return {"tool": "try_decode", "found_flag": True,
                    "flag": decoded, "layers_decoded": len(layers),
                    "decode_path": layers}

        if is_readable(decoded):
            break

    # 补充尝试不需要递归的 URL 解码与 rot13
    single = {}
    try:
        u = unquote(text)
        if u != text:
            single["url"] = u
    except Exception:
        pass
    try:
        single["rot13"] = codecs.decode(text, "rot_13")
    except Exception:
        pass

    return {
        "tool": "try_decode",
        "found_flag": looks_like_flag(current),
        "final_result": current[:200],
        "layers_decoded": len(layers),
        "decode_path": layers,
        "other_attempts": single,
    }


def decode_morse(text: str) -> dict:
    """莫尔斯电码解码。输入形如 '.... . .-.. .-.. ---',用空格分隔字母,'/' 或多个空格分隔单词。"""
    MORSE = {
        '.-': 'A', '-...': 'B', '-.-.': 'C', '-..': 'D', '.': 'E', '..-.': 'F',
        '--.': 'G', '....': 'H', '..': 'I', '.---': 'J', '-.-': 'K', '.-..': 'L',
        '--': 'M', '-.': 'N', '---': 'O', '.--.': 'P', '--.-': 'Q', '.-.': 'R',
        '...': 'S', '-': 'T', '..-': 'U', '...-': 'V', '.--': 'W', '-..-': 'X',
        '-.--': 'Y', '--..': 'Z', '-----': '0', '.----': '1', '..---': '2',
        '...--': '3', '....-': '4', '.....': '5', '-....': '6', '--...': '7',
        '---..': '8', '----.': '9', '.-.-.-': '.', '--..--': ',', '..--..': '?',
    }
    try:
        words = re.split(r"\s*/\s*|\s{2,}", text.strip())
        result = []
        for word in words:
            letters = word.split()
            decoded = "".join(MORSE.get(c, "?") for c in letters if c)
            result.append(decoded)
        decoded_text = " ".join(result)
        return {"tool": "decode_morse", "input": text[:60],
                "decoded": decoded_text,
                "found_flag": bool(re.search(r"\w+\{.*\}", decoded_text))}
    except Exception as e:
        return {"tool": "decode_morse", "error": f"解码失败: {e}"}


def decode_binary(text: str) -> dict:
    """二进制转文本。输入形如 '01100110 01101100 01100001 01100111'(8位一组)。"""
    try:
        bits = re.sub(r"[^01]", "", text)
        if len(bits) % 8 != 0:
            return {"tool": "decode_binary", "error": "位数不是8的倍数,可能不是标准二进制文本"}
        chars = [chr(int(bits[i:i+8], 2)) for i in range(0, len(bits), 8)]
        decoded = "".join(chars)
        return {"tool": "decode_binary", "input": text[:60],
                "decoded": decoded,
                "found_flag": bool(re.search(r"\w+\{.*\}", decoded))}
    except Exception as e:
        return {"tool": "decode_binary", "error": f"解码失败: {e}"}


def decode_ascii(text: str) -> dict:
    """ASCII 码数字转文本。输入形如 '102 108 97 103'(空格分隔的十进制数)。"""
    try:
        nums = re.findall(r"\d+", text)
        chars = [chr(int(n)) for n in nums if 0 <= int(n) <= 0x10ffff]
        decoded = "".join(chars)
        return {"tool": "decode_ascii", "input": text[:60],
                "decoded": decoded,
                "found_flag": bool(re.search(r"\w+\{.*\}", decoded))}
    except Exception as e:
        return {"tool": "decode_ascii", "error": f"解码失败: {e}"}


def analyze_image(filepath: str) -> dict:
    """分析图片文件,检测常见隐写:文件尾部附加数据、藏匿的其他文件(如zip/rar)、
    可疑字符串、文件结构异常。纯文件分析,不修改文件。
    参数 filepath: 图片文件路径。"""
    result = {"tool": "analyze_image", "filepath": filepath, "findings": []}

    try:
        with open(filepath, "rb") as f:
            data = f.read()
    except Exception as e:
        return {"tool": "analyze_image", "error": f"读取失败: {e}"}

    signatures = {
        b"\xff\xd9": "JPEG结束标志(FFD9后若还有数据,是附加隐写)",
        b"\x49\x45\x4e\x44\xae\x42\x60\x82": "PNG结束标志(IEND后若还有数据,是附加隐写)",
    }
    embedded_sigs = {
        b"PK\x03\x04": "ZIP压缩包",
        b"Rar!\x1a\x07": "RAR压缩包",
        b"\x1f\x8b\x08": "GZIP压缩",
        b"\x89PNG": "内嵌PNG图片",
        b"\xff\xd8\xff": "内嵌JPEG图片",
        b"%PDF": "内嵌PDF",
    }

    # 尾部附加数据(最常见的图片隐写)
    for end_sig, desc in signatures.items():
        pos = data.rfind(end_sig)
        if pos != -1 and pos + len(end_sig) < len(data) - 5:
            extra = len(data) - (pos + len(end_sig))
            result["findings"].append({
                "type": "文件尾部附加数据",
                "detail": f"{desc}后还有 {extra} 字节数据,可能是隐写内容",
                "direction": "用 binwalk 提取,或 foremost 分离;检查尾部数据是否是flag或另一个文件"})

    # 文件内藏有其他文件(文件头不在开头)
    for sig, desc in embedded_sigs.items():
        pos = data.find(sig)
        if pos > 10:
            result["findings"].append({
                "type": "内嵌文件",
                "detail": f"在偏移 {pos} 处发现{desc}的文件头,图片里可能藏了一个{desc}",
                "direction": f"用 binwalk -e 或 foremost 提取这个内嵌文件"})

    # 可见字符串里的明文 flag
    strings = re.findall(rb"[\x20-\x7e]{5,}", data)
    flag_like = [s.decode("ascii", errors="ignore") for s in strings
                 if re.search(rb"(flag|ctf|key)\{", s, re.IGNORECASE)]
    if flag_like:
        result["findings"].append({
            "type": "疑似flag明文",
            "detail": f"在文件中直接发现: {flag_like}",
            "direction": "这可能就是flag"})

    # EXIF/元数据里的可疑文本
    exif_markers = [b"Exif", b"Comment", b"Description"]
    for marker in exif_markers:
        if marker in data:
            idx = data.find(marker)
            snippet = data[idx:idx+100].decode("ascii", errors="ignore")
            if re.search(r"(flag|ctf|key)", snippet, re.IGNORECASE):
                result["findings"].append({
                    "type": "元数据可疑内容",
                    "detail": f"在{marker.decode()}附近发现可疑文本",
                    "direction": "用 exiftool 查看完整元数据"})

    if not result["findings"]:
        result["findings"].append({
            "type": "未发现明显隐写",
            "detail": "文件尾部、内嵌文件、字符串、元数据均无明显异常",
            "direction": "考虑LSB隐写(用zsteg/stegsolve)、盲水印,或图片本身就是线索"})

    result["note"] = "本工具做静态隐写检测,复杂隐写(LSB/盲水印)需要zsteg/stegsolve等专业工具"
    return result


def auto_analyze_text(text: str) -> dict:
    """自动分析一段未知编码的文本,判断它可能是什么编码,并给出识别依据。
    作为编码类型识别器,帮助自主决策该用哪个解码工具。"""
    hints = []
    t = text.strip()

    if re.fullmatch(r"[.\-/ ]+", t):
        hints.append("疑似莫尔斯电码(只含 . - / 空格)→ 建议用 decode_morse")
    if re.fullmatch(r"[01\s]+", t) and "0" in t and "1" in t:
        hints.append("疑似二进制(只含 0 1 空格)→ 建议用 decode_binary")
    if re.fullmatch(r"[\d\s]+", t) and len(re.findall(r"\d+", t)) > 1:
        hints.append("疑似 ASCII 码数字序列 → 建议用 decode_ascii")
    if re.fullmatch(r"[A-Za-z0-9+/=]{8,}", t):
        hints.append("疑似 base64 → 建议用 try_decode")
    if re.fullmatch(r"[0-9a-fA-F\s]{8,}", t):
        hints.append("疑似十六进制 → 建议用 try_decode")

    return {"tool": "auto_analyze_text", "input": text[:60],
            "possible_encodings": hints if hints else ["无法自动识别,建议人工判断"]}


if __name__ == "__main__":
    import json

    print("测试1:解码 base64")
    r = try_decode("ZmxhZ3toZWxsb193b3JsZH0=")
    print(json.dumps(r, ensure_ascii=False, indent=2))

    print("\n测试2:解码 hex")
    r = try_decode("666c61677b6865785f666c61677d")
    print(json.dumps(r, ensure_ascii=False, indent=2))