FROM python:3.11-slim

LABEL maintainer="Security Team"
LABEL description="TI Enricher Pro - Threat Intelligence enrichment tool"

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends gcc \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY ti_enricher_pro.py .
COPY api.py .

RUN useradd -m -u 1000 enricher && chown -R enricher:enricher /app
USER enricher

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8000/health')" || exit 1

CMD ["uvicorn", "api:app", "--host", "0.0.0.0", "--port", "8000"]
