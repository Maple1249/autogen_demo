@echo off
title 御界·安全超级智能体 - 一键部署
echo ============================================
echo    御界 · 安全超级智能体   一键部署脚本
echo ============================================
echo.

cd /d %~dp0

echo [1/5] 检查 Python 环境 ...
python --version >nul 2>&1
if errorlevel 1 (
    echo    [错误] 未检测到 Python，请先安装 Python 3.10+ 并勾选 Add to PATH
    echo    下载地址: https://www.python.org/downloads/
    pause & exit /b 1
)
python --version

echo.
echo [2/5] 准备虚拟环境 .venv ...
if not exist .venv (
    python -m venv .venv
    echo    已创建虚拟环境 .venv
) else (
    echo    虚拟环境已存在，跳过
)

echo.
echo [3/5] 安装 Python 依赖 ...
call .venv\Scripts\activate.bat
python -m pip install --upgrade pip
pip install -r requirements.txt
if errorlevel 1 (
    echo    [错误] 依赖安装失败，请检查网络或 requirements.txt
    pause & exit /b 1
)

echo.
echo [4/5] 检查 DeepSeek 密钥配置 ...
if not exist .env (
    echo DEEPSEEK_API_KEY=在此填入你的DeepSeek密钥>.env
    echo    [提示] 已生成 .env 模板，请打开 .env 填入你的 DEEPSEEK_API_KEY 再启动
) else (
    echo    .env 已存在
)

echo.
echo [5/5] 检查 nmap（态势感知功能依赖）...
nmap --version >nul 2>&1
if errorlevel 1 (
    echo    [警告] 未检测到 nmap，CTF 功能不受影响，但态势感知需要它
    echo    下载地址: https://nmap.org/download.html
) else (
    echo    nmap 已就绪
)

echo.
echo ============================================
echo    部署完成！接下来:
echo    1) 确认 .env 里已填好 DEEPSEEK_API_KEY
echo    2) 双击 start.bat 启动网页版
echo ============================================
pause
