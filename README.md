# VirusTotal IP Enrichment Tool 🛡️

![Python Version](https://img.shields.io/badge/python-3.8%2B-blue.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)

Легковесный CLI-скрипт на Python для автоматизированного обогащения (enrichment) индикаторов компрометации (IP-адресов) с использованием API VirusTotal v3. 

Проект разработан в рамках практической работы по Threat Intelligence и автоматизации процессов ИБ.

## 🛠 Особенности
* **Работа через API v3:** Использование актуальной версии API VirusTotal.
* **Поддержка CLI:** Удобная работа из терминала благодаря `argparse`.
* **Безопасность ключей:** Поддержка чтения API-ключа из переменных окружения (защита от утечки ключей в коммитах).
* **Обработка ошибок:** Graceful-обработка сетевых сбоев и лимитов API (HTTP 429 / 401).

## 🚀 Установка

1. Склонируйте репозиторий:
   ```bash
   git clone [https://github.com/FilonovGrigoriy/virustotal-ip-scanner.git](https://github.com/ВАШ_ЮЗЕРНЕЙМ/vt-ip-enrichment.git)
   cd vt-ip-enrichment
   ```

2. Создайте и активируйте виртуальное окружение (рекомендуется):
   ```bash
   python -m venv venv
   source venv/bin/activate  # Для Linux/macOS
   venv\Scripts\activate     # Для Windows
   ```

3. Установите зависимости:
   ```bash
   pip install -r requirements.txt
   ```

## 💻 Использование

Для работы скрипта требуется бесплатный API-ключ, который можно получить после регистрации на [virustotal.com](https://www.virustotal.com/).

### Способ 1: Передача ключа через аргумент
```bash
python vt_enrich.py 185.220.101.14 --key ВАШ_API_КЛЮЧ
```

### Способ 2: Использование переменной окружения (Безопаснее)
Вы можете сохранить ключ в систему, чтобы не вводить его каждый раз:
```bash
# Для Linux / macOS:
export VT_API_KEY="ВАШ_API_КЛЮЧ"

# Для Windows (PowerShell):
$env:VT_API_KEY="ВАШ_API_КЛЮЧ"

# Запуск:
python vt_enrich.py 185.220.101.14
```

## 📊 Пример вывода
```text
[*] Выполняем запрос для 185.220.101.14...

===================================
📡 ОТЧЕТ VIRUSTOTAL ДЛЯ IP: 185.220.101.14
===================================
🏢 Провайдер: AS205100 (Censys, Inc.)
🌍 Страна:    US
-----------------------------------
🔴 Вредоносный (Malicious):   12
🟡 Подозрительный (Suspicious): 0
🟢 Безопасный (Harmless):     74
⚪ Не проверено (Undetected):  6
===================================
```

## 📝 Лицензия
Этот проект распространяется под лицензией MIT - подробности см. в файле [LICENSE](LICENSE).