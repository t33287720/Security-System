FROM python:3.10-slim

# MariaDB connector & ipset/iptables for firewall management
RUN apt-get update && apt-get install -y \
    gcc \
    libmariadb-dev \
    ipset \
    iptables \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

CMD ["python", "elk_api_v2.py"]
