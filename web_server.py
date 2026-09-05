"""
御界·安全智能体 - Web 后端(FastAPI)。
托管前端页面,并提供 CTF 分析(文本/文件)与态势感知评估两类接口。
"""
import shutil
from pathlib import Path

from fastapi import FastAPI, UploadFile, File, Form
from fastapi.responses import HTMLResponse, JSONResponse

from ctf_core import analyze_once
from assess_core import assess_once

BASE = Path(__file__).parent
UPLOAD_DIR = BASE / "web_uploads"
UPLOAD_DIR.mkdir(exist_ok=True)

app = FastAPI(title="御界·安全智能体")


@app.get("/", response_class=HTMLResponse)
async def index():
    html_file = BASE / "index.html"
    return html_file.read_text(encoding="utf-8")


@app.post("/analyze")
async def analyze(text: str = Form(...)):
    """CTF 文本分析接口:接收一段文本/密文,返回分析结果。"""
    result = await analyze_once(text)
    return JSONResponse(result)


@app.post("/upload")
async def upload(file: UploadFile = File(...)):
    """CTF 文件分析接口:保存上传的文件,交给 Agent 分析。"""
    save_path = UPLOAD_DIR / file.filename
    with open(save_path, "wb") as f:
        shutil.copyfileobj(file.file, f)

    task = f"请分析这个CTF文件,找出隐藏的flag或线索。文件路径:{save_path}"
    result = await analyze_once(task)
    result["uploaded_file"] = file.filename
    return JSONResponse(result)


@app.post("/assess")
async def assess(text: str = Form(...)):
    """态势感知接口:接收授权任务描述,跑完整评估,返回摘要。"""
    result = await assess_once(text)
    return JSONResponse(result)


@app.get("/report", response_class=HTMLResponse)
async def report():
    """托管态势感知生成的可视化报告。"""
    f = BASE / "report.html"
    if not f.exists():
        return "<h3>还没有生成报告,请先运行一次态势感知。</h3>"
    return f.read_text(encoding="utf-8")


if __name__ == "__main__":
    import uvicorn
    print("=" * 50)
    print("御界·安全智能体 Web 版启动中...")
    print("浏览器打开: http://127.0.0.1:8000")
    print("=" * 50)
    uvicorn.run(app, host="127.0.0.1", port=8000)