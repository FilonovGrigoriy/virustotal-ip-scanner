#!/usr/bin/env python3
"""
TI Enricher Pro
Enterprise-grade обогащение инцидентов из Threat Intelligence.
Поддерживает: VirusTotal, AbuseIPDB, AlienVault OTX.
"""

import argparse
import asyncio
import base64
import csv
import ipaddress
import json
import logging
import os
import re
import sys
from datetime import datetime
from typing import Dict, List, Optional, Any, Set

import aiohttp
import validators
from dotenv import load_dotenv
from pydantic import BaseModel, Field, validator

load_dotenv()

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)-8s | %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)],
)
logger = logging.getLogger("ti_enricher")


class IoCInput(BaseModel):
    value: str
    type: Optional[str] = None

    @validator("type", always=True, pre=True)
    def detect_type(cls, v, values):
        if v:
            return v
        val = values.get("value", "")
        if re.fullmatch(r"^[a-fA-F0-9]{32}$", val):
            return "md5"
        if re.fullmatch(r"^[a-fA-F0-9]{40}$", val):
            return "sha1"
        if re.fullmatch(r"^[a-fA-F0-9]{64}$", val):
            return "sha256"
        try:
            ipaddress.ip_address(val)
            return "ip"
        except ValueError:
            pass
        if val.startswith(("http://", "https://")):
            return "url"
        if validators.domain(val):
            return "domain"
        return "unknown"


class EnrichmentResult(BaseModel):
    ioc: str
    ioc_type: str
    timestamp: str = Field(default_factory=lambda: datetime.utcnow().isoformat())
    
    vt_malicious: Optional[int] = None
    vt_suspicious: Optional[int] = None
    vt_harmless: Optional[int] = None
    vt_undetected: Optional[int] = None
    vt_reputation: Optional[int] = None
    vt_tags: List[str] = Field(default_factory=list)
    vt_link: Optional[str] = None
    
    abuse_confidence: Optional[int] = None
    abuse_country: Optional[str] = None
    abuse_isp: Optional[str] = None
    abuse_total_reports: Optional[int] = None
    
    otx_pulses: Optional[int] = None
    otx_tags: List[str] = Field(default_factory=list)
    
    risk_level: str = "UNKNOWN"
    enrichment_sources: List[str] = Field(default_factory=list)
    opsec_skipped: bool = False


class OPSECFilter:
    RFC1918_NETWORKS = [
        ipaddress.ip_network("10.0.0.0/8"),
        ipaddress.ip_network("172.16.0.0/12"),
        ipaddress.ip_network("192.168.0.0/16"),
        ipaddress.ip_network("127.0.0.0/8"),
        ipaddress.ip_network("169.254.0.0/16"),
    ]
    
    INTERNAL_TLDS = {".local", ".internal", ".corp", ".lan"}
    
    @classmethod
    def is_internal_ip(cls, ip_str: str) -> bool:
        try:
            ip = ipaddress.ip_address(ip_str)
            return any(ip in net for net in cls.RFC1918_NETWORKS)
        except ValueError:
            return False
    
    @classmethod
    def is_internal_domain(cls, domain: str) -> bool:
        domain_lower = domain.lower()
        return any(domain_lower.endswith(tld) for tld in cls.INTERNAL_TLDS)
    
    @classmethod
    def should_skip(cls, ioc: IoCInput) -> bool:
        if ioc.type == "ip" and cls.is_internal_ip(ioc.value):
            return True
        if ioc.type == "domain" and cls.is_internal_domain(ioc.value):
            return True
        if ioc.type == "url":
            match = re.match(r"https?://([^/]+)", ioc.value)
            if match and cls.is_internal_domain(match.group(1)):
                return True
        return False


class BaseSource:
    name: str = "base"
    
    def __init__(self, api_key: Optional[str], delay: float = 1.0):
        self.api_key = api_key
        self.delay = delay
        self.sem = asyncio.Semaphore(1)
    
    async def enrich(self, ioc: IoCInput, session: aiohttp.ClientSession) -> Dict[str, Any]:
        raise NotImplementedError


class VirusTotalSource(BaseSource):
    name = "VirusTotal"
    
    def __init__(self, api_key: Optional[str]):
        super().__init__(api_key, delay=float(os.getenv("VT_DELAY", "15.0")))
        self.base_url = "https://www.virustotal.com/api/v3"
    
    async def enrich(self, ioc: IoCInput, session: aiohttp.ClientSession) -> Dict[str, Any]:
        if not self.api_key:
            return {}
        
        if ioc.type == "ip":
            endpoint = f"{self.base_url}/ip_addresses/{ioc.value}"
        elif ioc.type in ("md5", "sha1", "sha256"):
            endpoint = f"{self.base_url}/files/{ioc.value}"
        elif ioc.type == "domain":
            endpoint = f"{self.base_url}/domains/{ioc.value}"
        elif ioc.type == "url":
            url_id = base64.urlsafe_b64encode(ioc.value.encode()).decode().strip("=")
            endpoint = f"{self.base_url}/urls/{url_id}"
        else:
            return {}
        
        headers = {"x-apikey": self.api_key, "Accept": "application/json"}
        
        async with self.sem:
            try:
                async with session.get(endpoint, headers=headers, ssl=True) as resp:
                    if resp.status == 429:
                        logger.warning(f"VT Rate limit for {ioc.value}")
                        return {}
                    resp.raise_for_status()
                    data = await resp.json()
            except aiohttp.ClientError as e:
                logger.error(f"VT error for {ioc.value}: {e}")
                return {}
            finally:
                await asyncio.sleep(self.delay)
        
        attr = data.get("data", {}).get("attributes", {})
        stats = attr.get("last_analysis_stats", {})
        
        return {
            "vt_malicious": stats.get("malicious"),
            "vt_suspicious": stats.get("suspicious"),
            "vt_harmless": stats.get("harmless"),
            "vt_undetected": stats.get("undetected"),
            "vt_reputation": attr.get("reputation"),
            "vt_tags": attr.get("tags", []),
            "vt_link": f"https://www.virustotal.com/gui/{ioc.type}/{ioc.value}" if ioc.type != "url" else None,
        }


class AbuseIPDBSource(BaseSource):
    name = "AbuseIPDB"
    
    def __init__(self, api_key: Optional[str]):
        super().__init__(api_key, delay=float(os.getenv("ABUSEIPDB_DELAY", "1.0")))
        self.base_url = "https://api.abuseipdb.com/api/v2"
    
    async def enrich(self, ioc: IoCInput, session: aiohttp.ClientSession) -> Dict[str, Any]:
        if not self.api_key or ioc.type != "ip":
            return {}
        
        headers = {"Key": self.api_key, "Accept": "application/json"}
        params = {"ipAddress": ioc.value, "maxAgeInDays": "90"}
        
        async with self.sem:
            try:
                async with session.get(
                    f"{self.base_url}/check", headers=headers, params=params, ssl=True
                ) as resp:
                    if resp.status == 429:
                        logger.warning(f"AbuseIPDB Rate limit for {ioc.value}")
                        return {}
                    resp.raise_for_status()
                    data = await resp.json()
            except aiohttp.ClientError as e:
                logger.error(f"AbuseIPDB error for {ioc.value}: {e}")
                return {}
            finally:
                await asyncio.sleep(self.delay)
        
        d = data.get("data", {})
        return {
            "abuse_confidence": d.get("abuseConfidenceScore"),
            "abuse_country": d.get("countryCode"),
            "abuse_isp": d.get("isp"),
            "abuse_total_reports": d.get("totalReports"),
        }


class OTXSource(BaseSource):
    name = "AlienVault OTX"
    
    def __init__(self, api_key: Optional[str]):
        super().__init__(api_key, delay=float(os.getenv("OTX_DELAY", "0.5")))
        self.base_url = "https://otx.alienvault.com/api/v1"
    
    async def enrich(self, ioc: IoCInput, session: aiohttp.ClientSession) -> Dict[str, Any]:
        if not self.api_key:
            return {}
        
        otx_type_map = {"ip": "IPv4", "domain": "domain", "url": "url",
                        "md5": "file", "sha1": "file", "sha256": "file"}
        otx_type = otx_type_map.get(ioc.type)
        if not otx_type:
            return {}
        
        headers = {"X-OTX-API-KEY": self.api_key}
        endpoint = f"{self.base_url}/indicators/{otx_type}/{ioc.value}/general"
        
        async with self.sem:
            try:
                async with session.get(endpoint, headers=headers, ssl=True) as resp:
                    if resp.status == 429:
                        logger.warning(f"OTX Rate limit for {ioc.value}")
                        return {}
                    resp.raise_for_status()
                    data = await resp.json()
            except aiohttp.ClientError as e:
                logger.error(f"OTX error for {ioc.value}: {e}")
                return {}
            finally:
                await asyncio.sleep(self.delay)
        
        pulses = data.get("pulse_info", {}).get("pulses", [])
        tags: Set[str] = set()
        for p in pulses:
            tags.update(p.get("tags", []))
        
        return {
            "otx_pulses": len(pulses),
            "otx_tags": sorted(list(tags)),
        }


class EnrichmentEngine:
    def __init__(self, sources: List[BaseSource]):
        self.sources = sources
        self.session: Optional[aiohttp.ClientSession] = None
    
    async def __aenter__(self):
        timeout = aiohttp.ClientTimeout(total=30)
        self.session = aiohttp.ClientSession(timeout=timeout)
        return self
    
    async def __aexit__(self, exc_type, exc, tb):
        if self.session:
            await self.session.close()
    
    @staticmethod
    def calculate_risk(data: Dict[str, Any]) -> str:
        malicious = data.get("vt_malicious") or 0
        suspicious = data.get("vt_suspicious") or 0
        abuse = data.get("abuse_confidence") or 0
        otx = data.get("otx_pulses") or 0
        
        if malicious >= 10 or abuse >= 80 or otx >= 5:
            return "CRITICAL"
        elif malicious >= 3 or abuse >= 50 or otx >= 2:
            return "HIGH"
        elif malicious > 0 or abuse >= 20 or otx > 0:
            return "MEDIUM"
        elif malicious == 0 and abuse == 0 and otx == 0:
            return "LOW"
        return "UNKNOWN"
    
    async def enrich(self, ioc: IoCInput) -> EnrichmentResult:
        logger.info(f"Enriching {ioc.value} ({ioc.type})")
        
        if OPSECFilter.should_skip(ioc):
            logger.warning(f"OPSEC: Skipping internal/private IoC {ioc.value}")
            return EnrichmentResult(
                ioc=ioc.value,
                ioc_type=ioc.type,
                risk_level="SKIPPED",
                opsec_skipped=True,
                enrichment_sources=[],
            )
        
        tasks = [src.enrich(ioc, self.session) for src in self.sources]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        merged: Dict[str, Any] = {}
        sources_used: List[str] = []
        
        for src, res in zip(self.sources, results):
            if isinstance(res, Exception):
                logger.error(f"{src.name} failed for {ioc.value}: {res}")
            elif res:
                merged.update(res)
                sources_used.append(src.name)
        
        return EnrichmentResult(
            ioc=ioc.value,
            ioc_type=ioc.type,
            **merged,
            risk_level=self.calculate_risk(merged),
            enrichment_sources=sources_used,
        )


class ConsoleFormatter:
    RISK_EMOJI = {
        "CRITICAL": "🔴 CRITICAL",
        "HIGH": "🟠 HIGH",
        "MEDIUM": "🟡 MEDIUM",
        "LOW": "🟢 LOW",
        "UNKNOWN": "⚪ UNKNOWN",
        "SKIPPED": "🔒 SKIPPED (OPSEC)",
    }
    
    @classmethod
    def print(cls, result: EnrichmentResult):
        r = result
        print("\n" + "=" * 50)
        print(f"📡  ОТЧЁТ ОБОГАЩЕНИЯ: {r.ioc}")
        print("=" * 50)
        print(f"📋  Тип:        {r.ioc_type}")
        print(f"🛡️  Риск:       {cls.RISK_EMOJI.get(r.risk_level, r.risk_level)}")
        print(f"📅  Время:      {r.timestamp}")
        
        if r.opsec_skipped:
            print("🔒  Статус:     Пропущено по политике OPSEC")
            print("=" * 50)
            return
        
        print("-" * 50)
        print("📊  VIRUSTOTAL")
        print(f"    🔴 Malicious:   {r.vt_malicious or 0}")
        print(f"    🟡 Suspicious:  {r.vt_suspicious or 0}")
        print(f"    🟢 Harmless:    {r.vt_harmless or 0}")
        print(f"    ⚪ Undetected:  {r.vt_undetected or 0}")
        if r.vt_link:
            print(f"    🔗 Ссылка:      {r.vt_link}")
        if r.vt_tags:
            print(f"    🏷️  Теги:        {', '.join(r.vt_tags)}")
        
        if r.abuse_confidence is not None:
            print("-" * 50)
            print("📊  ABUSEIPDB")
            print(f"    🎯 Confidence:  {r.abuse_confidence}%")
            print(f"    🌍 Страна:      {r.abuse_country or 'N/A'}")
            print(f"    🏢 Провайдер:   {r.abuse_isp or 'N/A'}")
            print(f"    📨 Репортов:    {r.abuse_total_reports or 0}")
        
        if r.otx_pulses is not None:
            print("-" * 50)
            print("📊  ALIENVAULT OTX")
            print(f"    📡 Pulses:      {r.otx_pulses}")
            if r.otx_tags:
                print(f"    🏷️  Теги:        {', '.join(r.otx_tags)}")
        
        print("-" * 50)
        print(f"📡  Источники:  {', '.join(r.enrichment_sources) if r.enrichment_sources else 'Нет данных'}")
        print("=" * 50 + "\n")


class FileOutput:
    @staticmethod
    def save(results: List[EnrichmentResult], prefix: str = "reports"):
        ts = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        os.makedirs(prefix, exist_ok=True)
        
        json_path = os.path.join(prefix, f"{ts}_report.json")
        with open(json_path, "w", encoding="utf-8") as f:
            json.dump([r.dict() for r in results], f, indent=2, ensure_ascii=False)
        logger.info(f"JSON: {json_path}")
        
        csv_path = os.path.join(prefix, f"{ts}_report.csv")
        if results:
            fieldnames = list(results[0].dict().keys())
            with open(csv_path, "w", newline="", encoding="utf-8") as f:
                writer = csv.DictWriter(f, fieldnames=fieldnames)
                writer.writeheader()
                for r in results:
                    writer.writerow(r.dict())
        logger.info(f"CSV:  {csv_path}")
        return json_path, csv_path


def load_iocs(path: str) -> List[IoCInput]:
    iocs = []
    if path.endswith(".json"):
        with open(path, "r", encoding="utf-8") as f:
            raw = json.load(f)
            for item in raw:
                if isinstance(item, str):
                    iocs.append(IoCInput(value=item))
                elif isinstance(item, dict):
                    iocs.append(IoCInput(value=item.get("ioc", item.get("value")), type=item.get("type")))
    elif path.endswith(".csv"):
        with open(path, "r", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            for row in reader:
                iocs.append(IoCInput(value=row.get("ioc", row.get("value")), type=row.get("type")))
    else:
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#"):
                    iocs.append(IoCInput(value=line))
    return iocs


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="TI Enricher Pro — обогащение инцидентов через Threat Intelligence.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Примеры:
  python ti_enricher_pro.py 8.8.8.8 --vt-key YOUR_KEY
  python ti_enricher_pro.py iocs.json --output-dir ./reports
  python ti_enricher_pro.py hashes.csv --no-abuseipdb --no-otx
        """,
    )
    parser.add_argument("input", help="IP, домен, URL, хэш или путь к файлу (.json/.csv/.txt)")
    parser.add_argument("--vt-key", default=os.environ.get("VT_API_KEY"), help="VirusTotal API key")
    parser.add_argument("--abuse-key", default=os.environ.get("ABUSEIPDB_API_KEY"), help="AbuseIPDB API key")
    parser.add_argument("--otx-key", default=os.environ.get("OTX_API_KEY"), help="AlienVault OTX API key")
    parser.add_argument("--output-dir", default="./reports", help="Директория для отчётов")
    parser.add_argument("--no-abuseipdb", action="store_true", help="Отключить AbuseIPDB")
    parser.add_argument("--no-otx", action="store_true", help="Отключить AlienVault OTX")
    parser.add_argument("--concurrency", type=int, default=5, help="Параллельных запросов (default: 5)")
    parser.add_argument("--json-only", action="store_true", help="Только JSON/CSV, без вывода в консоль")
    return parser


async def main():
    parser = build_parser()
    args = parser.parse_args()
    
    if os.path.isfile(args.input):
        iocs = load_iocs(args.input)
        logger.info(f"Загружено {len(iocs)} IoC из файла {args.input}")
    else:
        iocs = [IoCInput(value=args.input)]
        logger.info(f"Обработка одиночного IoC: {args.input}")
    
    sources: List[BaseSource] = []
    if args.vt_key:
        sources.append(VirusTotalSource(args.vt_key))
    else:
        logger.warning("VirusTotal API key не указан — пропускаем")
    
    if not args.no_abuseipdb and args.abuse_key:
        sources.append(AbuseIPDBSource(args.abuse_key))
    elif not args.no_abuseipdb:
        logger.warning("AbuseIPDB API key не указан — пропускаем")
    
    if not args.no_otx and args.otx_key:
        sources.append(OTXSource(args.otx_key))
    elif not args.no_otx:
        logger.warning("OTX API key не указан — пропускаем")
    
    if not sources:
        logger.error("Не указан ни один API-ключ. Завершение.")
        sys.exit(1)
    
    results: List[EnrichmentResult] = []
    
    async with EnrichmentEngine(sources) as engine:
        sem = asyncio.Semaphore(args.concurrency)
        
        async def bounded(ioc: IoCInput):
            async with sem:
                return await engine.enrich(ioc)
        
        tasks = [bounded(ioc) for ioc in iocs]
        raw_results = await asyncio.gather(*tasks, return_exceptions=True)
        
        for r in raw_results:
            if isinstance(r, Exception):
                logger.error(f"Ошибка обогащения: {r}")
            else:
                results.append(r)
                if not args.json_only:
                    ConsoleFormatter.print(r)
    
    json_path, csv_path = FileOutput.save(results, args.output_dir)
    
    risk_counts = {}
    for r in results:
        risk_counts[r.risk_level] = risk_counts.get(r.risk_level, 0) + 1
    
    print("\n" + "=" * 50)
    print("📊  СВОДКА ПО РИСКАМ")
    print("=" * 50)
    for level in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN", "SKIPPED"]:
        if level in risk_counts:
            print(f"    {level:12}: {risk_counts[level]}")
    print("=" * 50)
    print(f"📁 Отчёты сохранены в: {args.output_dir}")


if __name__ == "__main__":
    asyncio.run(main())
