# TI Enricher Pro 🛡️

[![Python](https://img.shields.io/badge/python-3.10%2B-blue)](https://www.python.org/)
[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)
[![Docker](https://img.shields.io/badge/docker-ready-blue)](docker-compose.yml)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.100%2B-teal)](https://fastapi.tiangolo.com/)

> Enterprise-grade инструмент для автоматизированного обогащения инцидентов ИБ (IoC — IP, домены, URL, хэши) через Threat Intelligence: **VirusTotal**, **AbuseIPDB**, **AlienVault OTX**.

---

## 📋 Содержание

- [Описание](#описание)
- [Архитектура](#архитектура)
- [Возможности](#возможности)
- [Требования](#требования)
- [Установка](#установка)
- [Использование](#использование)
  - [CLI](#cli)
  - [Docker + FastAPI](#docker--fastapi)
- [Конфигурация](#конфигурация)
- [Структура проекта](#структура-проекта)
- [Безопасность (OPSEC)](#безопасность-opsec)
- [Лицензия](#лицензия)

---

## 🎯 Описание

**TI Enricher Pro** — Python-инструмент для SOC-аналитиков и инцидент-менеджеров, который автоматически:

1. **Определяет тип индикатора** (IP, домен, URL, MD5/SHA1/SHA256) без явного указания.
2. **Проверяет OPSEC-политику** — внутренние IP и домены не отправляются в публичные API.
3. **Параллельно запрашивает** данные из нескольких TI-источников с соблюдением rate limits.
4. **Формирует единый отчёт** с уровнем риска: `CRITICAL` / `HIGH` / `MEDIUM` / `LOW` / `SKIPPED`.
5. **Экспортирует результаты** в JSON и CSV для последующей интеграции с SIEM/SOAR.

---

## 🏗️ Архитектура

```
┌─────────────┐     ┌──────────────────┐     ┌─────────────────┐
│   Input     │────▶│  EnrichmentEngine│────▶│  OutputFormatter│
│ (IP/Domain/ │     │  (async + sem)   │     │ (json / csv /   │
│  URL/Hash)  │     │                  │     │     console)    │
└─────────────┘     └──────────────────┘     └─────────────────┘
         │                   │
         ▼                   ▼
   ┌──────────┐      ┌──────────────┐
   │ OPSEC    │      │ BaseSource   │
   │ Filter   │      │ (VT / OTX /  │
   │(RFC1918) │      │  AbuseIPDB)  │
   └──────────┘      └──────────────┘
```

---

## ✨ Возможности

| Функция | Описание |
|---------|----------|
| 🔍 **Автоопределение типа IoC** | Распознаёт IP, домен, URL, хэш без флагов |
| 🛡️ **OPSEC-фильтр** | Пропускает RFC1918 и внутренние домены (`.local`, `.corp`) |
| ⚡ **Асинхронность** | `aiohttp` + `asyncio` для высокой производительности |
| 🎚️ **Rate limiting** | Индивидуальные семафоры для каждого TI-источника |
| 📊 **Мультиформатный вывод** | JSON (машиночитаемый) + CSV (для аналитика) + Console |
| 🔧 **Модульная архитектура** | Новый источник TI = один класс |
| 🐳 **Docker-ready** | `Dockerfile` + `docker-compose.yml` |
| 🚀 **FastAPI REST API** | Готовый `/enrich` endpoint для SOAR/SIEM |

---

## 📦 Требования

- Python 3.10+
- Docker + Docker Compose (опционально, для контейнерного запуска)
- API-ключи: [VirusTotal](https://www.virustotal.com), [AbuseIPDB](https://www.abuseipdb.com), [AlienVault OTX](https://otx.alienvault.com) (опционально)

---

## 🚀 Установка

### Локальная установка

```bash
git clone https://github.com/FilonovGrigoriy/virustotal-ip-scanner.git
cd virustotal-ip-scanner

python -m venv venv
source venv/bin/activate  # Linux/macOS
# venv\Scripts\activate  # Windows

pip install -r requirements.txt
```

### Docker (рекомендуется)

```bash
cp .env.example .env
# Отредактируй .env: вставь реальные API-ключи

docker-compose up --build -d
```

---

## 💻 Использование

### CLI

```bash
# Одиночный IoC
python ti_enricher_pro.py 8.8.8.8 --vt-key YOUR_VT_KEY --abuse-key YOUR_ABUSE_KEY --otx-key YOUR_OTX_KEY

# Массовая обработка из файла
python ti_enricher_pro.py iocs.json --output-dir ./reports

# Только VirusTotal, без консольного вывода
python ti_enricher_pro.py 8.8.8.8 --vt-key YOUR_KEY --no-abuseipdb --no-otx --json-only
```

**Форматы входных файлов:**

- `iocs.json` — `["8.8.8.8", "evil.com", {"ioc": "hash", "type": "md5"}]`
- `iocs.csv` — колонки `ioc,type`
- `iocs.txt` — один IoC на строку

### Docker + FastAPI

После `docker-compose up -d`:

```bash
# Healthcheck
curl http://localhost:8000/health

# Обогатить один IP
curl -X POST "http://localhost:8000/enrich" \
  -H "Content-Type: application/json" \
  -d '{"iocs": ["8.8.8.8"]}'

# Обогатить с выбором источников
curl -X POST "http://localhost:8000/enrich" \
  -H "Content-Type: application/json" \
  -d '{"iocs": ["8.8.8.8"], "sources": ["virustotal", "abuseipdb"]}'

# Swagger UI
open http://localhost:8000/docs
```

---

## ⚙️ Конфигурация

Передайте ключи через **переменные окружения** (рекомендуется) или аргументы CLI:

```ini
# .env
VT_API_KEY=your_virustotal_key
ABUSEIPDB_API_KEY=your_abuseipdb_key
OTX_API_KEY=your_otx_key

# Rate limits (seconds between requests)
VT_DELAY=15.0          # 4 запроса/мин для Public API
ABUSEIPDB_DELAY=1.0
OTX_DELAY=0.5
```

---

## 🛡️ Безопасность (OPSEC)

Инструмент реализует **Zero-Trust** подход к внешним API:

- **RFC1918** (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`) — пропускаются.
- **Loopback** (`127.0.0.0/8`) — пропускаются.
- **Link-local** (`169.254.0.0/16`) — пропускаются.
- **Внутренние TLD** (`.local`, `.internal`, `.corp`, `.lan`) — пропускаются.

При срабатывании фильтра IoC помечается статусом `SKIPPED`, и в публичные API **запрос не отправляется**.

---

## 📁 Структура проекта

```
virustotal-ip-scanner/
├── .env.example           # Шаблон переменных окружения
├── .gitignore             # Исключение секретов и кэша
├── Dockerfile             # Docker-образ
├── docker-compose.yml     # Docker Compose (app + redis)
├── LICENSE                # MIT License
├── README.md              # Документация
├── requirements.txt       # Python-зависимости
├── ti_enricher_pro.py    # Основной скрипт (async, multi-source)
└── api.py                 # FastAPI REST API
```

---

## 📝 Лицензия

MIT License. Подробности см. в файле [LICENSE](LICENSE).

---

> **Disclaimer:** Инструмент предназначен для легального использования в рамках авторизованного тестирования на проникновение, аудита безопасности и работы SOC. Пользователь несёт ответственность за соблюдение Terms of Service внешних API.
