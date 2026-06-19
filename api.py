#!/usr/bin/env python3
"""
FastAPI-обёртка для TI Enricher Pro.
REST API для интеграции с SOAR/SIEM.
"""

import os
import time
from typing import List, Optional

from fastapi import FastAPI, HTTPException, Query
from pydantic import BaseModel, Field

from ti_enricher_pro import (
    IoCInput, EnrichmentResult, EnrichmentEngine,
    VirusTotalSource, AbuseIPDBSource, OTXSource,
)

app = FastAPI(
    title="TI Enricher API",
    description="REST API для обогащения инцидентов ИБ через Threat Intelligence",
    version="2.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
)


def build_sources(requested: Optional[List[str]] = None):
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
    return sources


class EnrichRequest(BaseModel):
    iocs: List[str] = Field(..., example=["8.8.8.8", "evil.com"])
    sources: Optional[List[str]] = Field(default=None, description="Источники: virustotal, abuseipdb, otx. Null = все.")
    skip_cache: bool = Field(default=False, description="Пропустить кэш")


class EnrichResponse(BaseModel):
    results: List[EnrichmentResult]
    fresh_count: int
    processing_time_ms: float


@app.get("/health", tags=["System"])
async def health():
    return {
        "status": "ok",
        "timestamp": __import__("datetime").datetime.utcnow().isoformat(),
    }


@app.post("/enrich", response_model=EnrichResponse, tags=["Enrichment"])
async def enrich(req: EnrichRequest):
    start = time.time()
    sources = build_sources(req.sources)
    if not sources:
        raise HTTPException(status_code=503, detail="Нет доступных TI-источников. Проверьте API-ключи.")
    
    iocs = [IoCInput(value=v) for v in req.iocs]
    results: List[EnrichmentResult] = []
    
    async with EnrichmentEngine(sources) as engine:
        for ioc in iocs:
            result = await engine.enrich(ioc)
            results.append(result)
    
    elapsed = (time.time() - start) * 1000
    return EnrichResponse(
        results=results,
        fresh_count=len(results),
        processing_time_ms=round(elapsed, 2),
    )


@app.get("/enrich/single", tags=["Enrichment"])
async def enrich_single(
    ioc: str = Query(..., example="8.8.8.8"),
    sources: Optional[List[str]] = Query(default=None),
):
    req = EnrichRequest(iocs=[ioc], sources=sources)
    return await enrich(req)


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
