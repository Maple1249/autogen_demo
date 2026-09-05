"""
Crypto 分析工具集(纯 Python,只做分析与古典密码解密,不生成攻击代码)。
"""
import re
import string






def identify_crypto(text: str, params: str = "") -> dict:
    """识别密文/编码的类型,给出识别依据、推荐的破解工具和解题思路。
    这是一个密码类型识别专家:不负责破解,只负责快速准确地判断'这是什么',指明方向。
    参数 text: 密文或编码; params: 附带参数(如 n=..., e=...)。"""
    import re
    t = text.strip()
    combined = (text + " " + params).lower()
    candidates = []

    # ===== 编码类(通常有标准解码) =====
    if re.fullmatch(r"[A-Za-z0-9+/]+={0,2}", t) and len(t) >= 8:
        candidates.append({
            "type": "Base64 编码", "confidence": "高",
            "evidence": "字符集为 A-Za-z0-9+/,可能以 = 结尾(填充符)",
            "tool": "本工具的 try_decode / CyberChef",
            "approach": "直接 base64 解码;若解出仍是编码则多层解码"})

    if re.fullmatch(r"[0-9a-fA-F\s]+", t) and len(re.sub(r"\s","",t)) % 2 == 0 and len(t) >= 8:
        candidates.append({
            "type": "十六进制(Hex)编码", "confidence": "高",
            "evidence": "仅含 0-9a-f,长度为偶数",
            "tool": "try_decode / CyberChef (From Hex)",
            "approach": "每两位转一个字节"})

    if re.fullmatch(r"[01\s]+", t) and "0" in t and "1" in t:
        candidates.append({
            "type": "二进制编码", "confidence": "高",
            "evidence": "仅含 0 和 1",
            "tool": "decode_binary / CyberChef",
            "approach": "每8位转一个ASCII字符"})

    if re.fullmatch(r"[.\-/\s]+", t):
        candidates.append({
            "type": "摩斯电码", "confidence": "高",
            "evidence": "仅含 . - / 和空格",
            "tool": "decode_morse / CyberChef (From Morse Code)",
            "approach": "查摩斯码表,空格分字母 / 分单词"})

    if re.fullmatch(r"[A-Za-z\s]+", t) and re.search(r"\b[a-z]{5}\b", t.lower()):
        # 培根密码:通常只有两种字母(如全是a和b),或5字母一组
        letters = set(re.sub(r"[^a-z]","",t.lower()))
        if len(letters) <= 2:
            candidates.append({
                "type": "培根密码(Bacon)", "confidence": "高",
                "evidence": f"文本只由 {len(letters)} 种字母组成,符合培根的二元编码特征",
                "tool": "CyberChef (Bacon Cipher Decode) / dCode",
                "approach": "5个字母一组,按A/B(或两种字母)映射查培根表"})

    # ===== 古典密码类 =====
    if re.fullmatch(r"[A-Za-z\s.,'?!\-]+", t) and len(re.sub(r"[^a-z]","",t.lower())) > 30:
        # 用重合指数区分单表替换 vs 维吉尼亚
        seq = re.sub(r"[^a-z]", "", t.lower())
        counts = [0]*26
        for c in seq:
            counts[ord(c)-97] += 1
        n = len(seq)
        ic = sum(k*(k-1) for k in counts)/(n*(n-1)) if n > 1 else 0

        if ic > 0.06:  # IC接近英文0.067 → 单表替换/凯撒
            candidates.append({
                "type": "单表替换密码(Substitution) 或 凯撒",
                "confidence": "高",
                "evidence": f"重合指数 IC={ic:.4f},接近英文的0.067,说明字母频率分布未被打散(单表映射)",
                "tool": "凯撒先用 caesar_brute;若非凯撒用 quipqiup / dCode Substitution Solver",
                "approach": "先试凯撒25种移位;不行则是任意替换,用quipqiup频率分析自动破解"})
        else:  # IC偏低 → 维吉尼亚等多表
            candidates.append({
                "type": "维吉尼亚密码(Vigenère) 或其他多表替换",
                "confidence": "高",
                "evidence": f"重合指数 IC={ic:.4f},明显低于英文0.067,说明字母频率被打散(多表/周期密钥)",
                "tool": "本工具的 vigenere_solve / dCode Vigenère / CyberChef",
                "approach": "用Kasiski或重合指数找密钥长度,再频率分析求密钥"})

    # ===== RSA / 现代密码 =====
    if any(k in combined for k in ["n =", "n=", "e =", "e=", "c =", "c=", "rsa", "modulus", "phi", "公钥", "私钥", "两个素数", "p*q", "pq"]):
        candidates.append({
            "type": "RSA 公钥密码", "confidence": "高",
            "evidence": "出现 n/e/c/p/q 等 RSA 参数",
            "tool": "RsaCtfTool / yafu(分解n) / dCode",
            "approach": "看e是否小(低指数)、n是否可分解(小因子/费马)、是否共模/共享因子,选对应攻击"})

    if re.search(r"aes|des|rc4|cbc|ecb|iv\s*=|对称加密", combined):
        candidates.append({
            "type": "对称加密(AES/DES/RC4等)", "confidence": "中",
            "evidence": "提到AES/DES/RC4或分组模式",
            "tool": "CyberChef / Python cryptography库",
            "approach": "需要密钥;找题目给的key/iv,注意ECB/CBC模式"})

    # ===== 栅栏 =====
    if re.fullmatch(r"[A-Za-z]+", t) and 10 < len(t) < 200:
        candidates.append({
            "type": "可能是栅栏密码(Rail Fence)或换位密码", "confidence": "低",
            "evidence": "纯字母、无空格、长度中等——若上面的替换/维吉尼亚不符,考虑字母顺序被重排",
            "tool": "CyberChef (Rail Fence) / dCode",
            "approach": "换位密码不改变字母,只改顺序;试不同栏数/周期重排"})

    return {
        "tool": "identify_crypto",
        "input_preview": text[:80],
        "identified_types": candidates if candidates else [{
            "type": "未能自动识别", "confidence": "-",
            "evidence": "不符合已知的常见特征",
            "tool": "CyberChef Magic / dCode Cipher Identifier",
            "approach": "用CyberChef的Magic功能或dCode的密码识别器自动分析"}],
        "note": "本工具专注于'识别类型+指明方向',具体破解请用推荐的专业工具完成。",
    }



def caesar_brute(text: str) -> dict:
    """凯撒密码爆破:对输入文本尝试全部25种字母移位,列出所有结果。
    古典密码的标准解法,纯字母移位,自动标出疑似flag的结果。
    参数 text: 疑似凯撒加密的文本。"""
    results = []
    for shift in range(1, 26):
        decoded = []
        for ch in text:
            if ch.isupper():
                decoded.append(chr((ord(ch) - 65 - shift) % 26 + 65))
            elif ch.islower():
                decoded.append(chr((ord(ch) - 97 - shift) % 26 + 97))
            else:
                decoded.append(ch)
        d = "".join(decoded)
        # 更精确:不只看格式,还要以常见 flag 前缀开头(flag/ctf/key等),避免每种移位都误判
        is_flag = bool(re.search(r"(flag|ctf|key|pwn|crypto)\{", d, re.IGNORECASE))
        results.append({"shift": shift, "text": d, "looks_like_flag": is_flag})

    # 把疑似 flag 的结果挑出来放前面
    flag_hits = [r for r in results if r["looks_like_flag"]]
    return {
        "tool": "caesar_brute",
        "input": text[:60],
        "flag_candidates": flag_hits,        # 疑似 flag 的移位结果,最重要
        "all_shifts": results,               # 全部25种,供人工判断
    }



# ---------- 单独测试 ----------
if __name__ == "__main__":
    import json

    print("测试1:凯撒爆破")
    # flag{caesar} 用移位3加密后的密文
    r = caesar_brute("iodj{fdhvdu}")
    print(json.dumps(r["flag_candidates"], ensure_ascii=False, indent=2))

    print("\n测试2:识别 RSA")
    r = identify_crypto("c=12345", "n=3233, e=17")
    print(json.dumps(r, ensure_ascii=False, indent=2))