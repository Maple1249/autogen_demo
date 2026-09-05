@echo off
title 御界 - 启动测试靶机(Vulhub)
echo ============================================
echo    启动 Vulhub 测试靶机（态势感知演示用）
echo ============================================
echo.

REM ==== 请把下面两行改成你本机 Vulhub 靶机的实际路径 ====
set TOMCAT_DIR=D:\python_learn\vulhub\tomcat\CVE-2017-12615
set REDIS_DIR=D:\python_learn\vulhub\redis\CVE-2022-0543

docker version >nul 2>&1
if errorlevel 1 (
    echo [错误] 未检测到 Docker，请先启动 Docker Desktop
    pause & exit /b 1
)

echo [1/2] 启动 Tomcat 靶机 (8080) ...
cd /d %TOMCAT_DIR% 2>nul && docker compose up -d || echo    [跳过] 路径不存在，请检查 TOMCAT_DIR

echo [2/2] 启动 Redis 靶机 (6379) ...
cd /d %REDIS_DIR% 2>nul && docker compose up -d || echo    [跳过] 路径不存在，请检查 REDIS_DIR

echo.
echo 当前运行中的容器:
docker ps
echo.
echo 靶机就绪后，在网页版态势感知模式输入: 对127.0.0.1进行只读安全态势评估
pause
