FROM python:3.12-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt && \
    playwright install --with-deps chromium && \
    rm -rf /var/lib/apt/lists/* /tmp/*

COPY main.py .

CMD uvicorn main:app --host 0.0.0.0 --port ${PORT:-10000}
