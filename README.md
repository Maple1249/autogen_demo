御界·安全超级智能体 — 一键部署方案

把本目录下的 3 个 .bat 脚本放到项目根目录（与 web_server.py、requirements.txt 同一层，即 D:\python_learn\autogen_demo）即可使用。

三个脚本的用途

deploy.bat	一键部署：检查 Python → 建虚拟环境 → 装依赖 → 生成 .env 模板 → 检查 nmap	首次部署时双击一次

start.bat	一键启动网页版：激活环境 → 启动 web_server.py	每次使用双击启动

start_targets.bat	一键启动 Vulhub 测试靶机（Tomcat/Redis）	演示态势感知前双击

首次部署

1.双击 deploy.bat，等它自动装好环境和依赖。

2.打开生成的 .env 文件，把 DEEPSEEK_API_KEY= 后面填上你的 DeepSeek 密钥，保存。

3.双击 start.bat，浏览器打开 http://127.0.0.1:8000 即可使用。

演示态势感知

先双击 start_targets.bat 起靶机（第一次用需按脚本顶部提示，把 TOMCAT_DIR/REDIS_DIR 改成你本机 Vulhub 的实际路径）。

再在网页"态势感知"模式输入：对127.0.0.1进行只读安全态势评估。

环境前置要求

Python 3.10+

nmap

Docker Desktop（仅启动测试靶机时需要）
