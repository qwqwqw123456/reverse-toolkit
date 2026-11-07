FROM python:3.10-slim

LABEL maintainer="reverse-toolkit"
LABEL description="Reverse-Toolkit: AI-powered reverse engineering toolkit with MCP"

# 安装系统依赖
RUN apt-get update && apt-get install -y --no-install-recommends \
    binutils \
    file \
    strings \
    readelf \
    upx \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# 先装 Python 依赖
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# 拷贝代码
COPY . .

# 安装
RUN pip install --no-cache-dir mcp unicorn

# 默认运行 MCP Server
CMD ["python", "mcp_server.py"]
