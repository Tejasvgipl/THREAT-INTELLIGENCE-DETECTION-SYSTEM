FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY wazuh_watcher.py .

CMD ["python", "-u", "wazuh_watcher.py"]
