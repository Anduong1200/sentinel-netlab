FROM python:3.11-slim

WORKDIR /app

# Install system dependencies (libpcap for scapy)
RUN apt-get update && apt-get install -y \
    libpcap-dev \
    tcpdump \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements (simplified)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
RUN pip install scapy flask flask-cors flask-limiter

# Copy app
COPY . .

# Environment
ENV PYTHONUNBUFFERED=1
ENV SENTINEL_LAB_MODE=true

# Port
EXPOSE 5001

# Command
CMD ["python", "app.py"]
