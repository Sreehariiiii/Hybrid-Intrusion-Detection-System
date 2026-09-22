# Multi-stage / Unified Container for Suricata IDS & Python Analytics Engine
FROM ubuntu:22.04

# Prevent interactive prompts during apt install
ENV DEBIAN_FRONTEND=noninteractive
ENV PYTHONUNBUFFERED=1

# Install Suricata, Python 3.10+, SQLite3, libpcap, and build essentials
RUN apt-get update && apt-get install -y --no-install-recommends \
    software-properties-common \
    ca-certificates \
    curl \
    gnupg \
    build-essential \
    libpcap-dev \
    sqlite3 \
    && add-apt-repository -y ppa:oisf/suricata-stable \
    && apt-get update && apt-get install -y --no-install-recommends \
    suricata \
    python3 \
    python3-pip \
    python3-dev \
    tcpdump \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /app

# Copy requirement files first for optimal caching
COPY requirements.txt /app/
RUN pip3 install --no-cache-dir -r requirements.txt

# Copy system code and configurations
COPY . /app

# Expose Streamlit default port
EXPOSE 8501

# Entrypoint default runs the orchestration pipeline and launches dashboard
CMD ["python3", "run_pipeline.py", "--dashboard"]
