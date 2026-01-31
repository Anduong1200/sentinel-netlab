FROM python:3.11-slim-bookworm

WORKDIR /app

# Install system dependencies (libpcap for scapy)
RUN apt-get update && apt-get upgrade -y && apt-get install -y --no-install-recommends \
    libpcap-dev \
    tcpdump \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Upgrade system-wide python security-sensitive packages
RUN pip install --no-cache-dir --upgrade pip setuptools wheel jaraco.context

# Install python dependencies
RUN pip install --no-cache-dir scapy flask flask-cors flask-limiter

# Copy app
COPY . .

# Environment
ENV PYTHONUNBUFFERED=1
ENV SENTINEL_LAB_MODE=true

# Port
EXPOSE 5001

# Command
CMD ["python", "app.py"]
