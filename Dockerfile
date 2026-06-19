FROM python:3.11-slim

LABEL maintainer="Security Team <security@company.com>"
LABEL description="TI Enricher Pro - Threat Intelligence enrichment tool"

WORKDIR /app

# Установка системных зависимостей (для безопасности — минимум)
RUN apt-get update && apt-get install -y --no-install-recommends     gcc     && rm -rf /var/lib/apt/lists/*

# Копируем зависимости отдельно для кэширования слоёв
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Копируем код
COPY ti_enricher_pro.py .
COPY api.py .

# Создаём непривилегированного пользователя (безопасность!)
RUN useradd -m -u 1000 enricher && chown -R enricher:enricher /app
USER enricher

# Порт для FastAPI
EXPOSE 8000

# Healthcheck
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3     CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8000/health')" || exit 1

# По умолчанию запускаем FastAPI
CMD ["uvicorn", "api:app", "--host", "0.0.0.0", "--port", "8000"]
