@echo off
title 御界·安全超级智能体 - 网页版
cd /d %~dp0

if not exist .venv (
    echo [错误] 未找到虚拟环境，请先双击运行 deploy.bat 完成部署
    pause & exit /b 1
)

call .venv\Scripts\activate.bat
echo ============================================
echo    御界 · 安全超级智能体   网页版启动中
echo    浏览器访问:  http://127.0.0.1:8000
echo    关闭本窗口即可停止服务
echo ============================================
echo.
python web_server.py
pause
