#!/usr/bin/env python3
"""
FastAPI-обёртка для TI Enricher Pro.
Предоставляет REST API для интеграции с SOAR/SIEM.

Endpoints:
  POST /enrich      — обогатить один или несколько IoC
  GET  /health      — healthcheck
  GET  /docs        — Swagger UI (автодокументация)
"""

import os
import json
import asyncio
from typing import List, Optional, Dict, Any
from datetime import datetime, timedelta

from fastapi import FastAPI, HTTPException, BackgroundTasks, Query
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
import aioredis
import aiohttp

# Импортируем логику из основного скрипта
from ti_enricher_pro import (
    IoCInput, EnrichmentResult, EnrichmentEngine,
    VirusTotalSource, AbuseIPDBSource, OTXSource, OPSECFilter,
    FileOutput, ConsoleFormatter
)

app = FastAPI(
    title="TI Enricher API",
    description="REST API для обогащения инцидентов ИБ через Threat Intelligence",
    version="2.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
)

# ────────────────────────────────
# Redis кэш
# ────────────────────────────────
redis_pool: Optional[aioredis.Redis] = None

REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379/0")
CACHE_TTL = int(os.getenv("CACHE_TTL", "86400"))  # 24 часа по умолчанию

async def get_redis() -> Optional[aioredis.Redis]:
    global redis_pool
    if redis_pool is None:
        try:
            redis_pool = aioredis.from_url(REDIS_URL, decode_responses=True)
        except Exception as e:
            print(f"Redis недоступен: {e}. Кэширование отключено.")
    return redis_pool

async def get_cached(ioc: str) -> Optional[Dict[str, Any]]:
    redis = await get_redis()
    if not redis:
        return None
    data = await redis.get(f"ti:{ioc}")
    if data:
        return json.loads(data)
    return None

async def set_cached(ioc: str, result: Dict[str, Any]):
    redis = await get_redis()
    if not redis:
        return
    await redis.setex(f"ti:{ioc}", CACHE_TTL, json.dumps(result))

# ────────────────────────────────
# Pydantic-модели для API
# ────────────────────────────────
class EnrichRequest(BaseModel):
    iocs: List[str] = Field(..., description="Список IoC для обогащения", example=["8.8.8.8", "evil.com"])
    sources: Optional[List[str]] = Field(default=None, description="Источники (virustotal, abuseipdb, otx). Null = все доступные.")
    skip_cache: bool = Field(default=False, description="Пропустить кэш Redis и сделать свежие запросы")

class EnrichResponse(BaseModel):
    results: List[EnrichmentResult]
    cached_count: int
    fresh_count: int
    processing_time_ms: float

# ────────────────────────────────
# Инициализация источников
# ────────────────────────────────
def build_sources(requested: Optional[List[str]] = None) -> List[Any]:
    sources = []
    available = {
        "virustotal": (VirusTotalSource, os.getenv("VT_API_KEY")),
        "abuseipdb": (AbuseIPDBSource, os.getenv("ABUSEIPDB_API_KEY")),
        "otx": (OTXSource, os.getenv("OTX_API_KEY")),
    }

    for name, (cls, key) in available.items():
        if requested is None or name in requested:
            if key:
                sources.append(cls(key))
            else:
                print(f"Предупреждение: API-ключ для {name} не настроен")
    return sources

# ────────────────────────────────
# Endpoints
# ────────────────────────────────
@app.get("/health", tags=["System"])
async def health():
    """Healthcheck для Docker/Kubernetes."""
    redis = await get_redis()
    redis_status = "ok" if redis and await redis.ping() else "unavailable"
    return {
        "status": "ok",
        "redis": redis_status,
        "timestamp": datetime.utcnow().isoformat(),
    }

@app.post("/enrich", response_model=EnrichResponse, tags=["Enrichment"])
async def enrich(req: EnrichRequest, background_tasks: BackgroundTasks):
    """
    Обогатить список IoC данными из Threat Intelligence.

    - Проверяет кэш Redis (если не skip_cache)
    - Делает запросы к внешним API
    - Сохраняет результат в кэш
    - Возвращает агрегированный отчёт
    """
    import time
    start = time.time()

    sources = build_sources(req.sources)
    if not sources:
        raise HTTPException(status_code=503, detail="Нет доступных TI-источников. Проверьте API-ключи.")

    iocs = [IoCInput(value=v) for v in req.iocs]
    results: List[EnrichmentResult] = []
    cached_count = 0
    fresh_count = 0

    async with EnrichmentEngine(sources) as engine:
        for ioc in iocs:
            # Проверяем кэш
            if not req.skip_cache:
                cached = await get_cached(ioc.value)
                if cached:
                    results.append(EnrichmentResult(**cached))
                    cached_count += 1
                    continue

            # Делаем свежий запрос
            result = await engine.enrich(ioc)
            results.append(result)
            fresh_count += 1

            # Сохраняем в кэш (фоном, не блокируем ответ)
            background_tasks.add_task(set_cached, ioc.value, result.dict())

    elapsed = (time.time() - start) * 1000

    return EnrichResponse(
        results=results,
        cached_count=cached_count,
        fresh_count=fresh_count,
        processing_time_ms=round(elapsed, 2),
    )

@app.get("/enrich/single", tags=["Enrichment"])
async def enrich_single(
    ioc: str = Query(..., description="IoC для обогащения", example="8.8.8.8"),
    sources: Optional[List[str]] = Query(default=None, description="Источники"),
    skip_cache: bool = False,
):
    """Упрощённый endpoint для обогащения одного IoC (GET-запрос)."""
    req = EnrichRequest(iocs=[ioc], sources=sources, skip_cache=skip_cache)
    # Вызываем логику POST /enrich напрямую
    return await enrich(req, BackgroundTasks())

# ────────────────────────────────
# Точка входа (для локального запуска)
# ────────────────────────────────
if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
