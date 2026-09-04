[README.md](https://github.com/user-attachments/files/31821141/README.md)
# vuln_report.py

Инструмент для обработки XML-отчётов сканера уязвимостей **Greenbone OpenVAS**.  
Группирует уязвимости по уникальному идентификатору (OID), объединяет хосты,
на которых они обнаружены, и генерирует отчёт в одном или нескольких форматах.

---

## Возможности

- Принимает один XML-файл, каталог или рекурсивно обходит вложенные каталоги (`-r`)
- Поддерживает сжатые файлы `.xml.gz`
- Группирует уязвимости по OID — одна уязвимость на 20 хостах = одна запись в отчёте
- Берёт максимальную CVSS-оценку среди всех вхождений одного OID
- Извлекает поле **Impact** из тегов NVT (`<nvt><tags>`)
- Фильтрует уязвимости по минимальной CVSS-оценке (`--min-cvss`)
- Сортирует уязвимости по убыванию CVSS (отключается флагом `--no-sort`)
- Добавляет фоновый **водяной знак** на все страницы документа (`--watermark`)
- Выводит результат в любом сочетании форматов: **JSON**, **DOCX**, **PDF**
- При запросе только PDF — промежуточный `.docx` создаётся и удаляется автоматически
- Корректно пропускает битые XML-файлы, не прерывая обработку остальных

---

## Требования

| Компонент | Версия | Назначение |
|-----------|--------|------------|
| Python | 3.6+ | интерпретатор |
| [python-docx](https://python-docx.readthedocs.io/) | любая | генерация DOCX |
| [lxml](https://lxml.de/) | любая | XML-обработка (водяной знак) |
| LibreOffice (`soffice`) | любая | конвертация в PDF (только для `--pdf`) |

### Установка зависимостей

```bash
# Рекомендуется использовать виртуальное окружение
python3 -m venv venv
source venv/bin/activate          # Linux / macOS
# venv\Scripts\activate           # Windows

pip install python-docx lxml

# LibreOffice (только если нужен PDF, Linux):
sudo apt install libreoffice
```

---

## Использование

```
python vuln_report.py -i <путь> [--json] [--docx] [--pdf] [опции]
```

### Аргументы

| Флаг | Описание |
|------|----------|
| `-i`, `--input` | **Обязательный.** Путь к XML-файлу или каталогу с XML-файлами отчётов OpenVAS |
| `-o`, `--output` | Базовое имя выходных файлов без расширения (по умолчанию: `vulnerability_report`) |
| `-r`, `--recursive` | Искать XML-файлы рекурсивно во вложенных каталогах |
| `--json` | Сохранить структурированный JSON-отчёт (`<output>.json`) |
| `--docx` | Сохранить человекочитаемый Word-документ (`<output>.docx`) |
| `--pdf` | Сохранить PDF (`<output>.pdf`). Требует LibreOffice |
| `--min-cvss SCORE` | Включать только уязвимости с CVSS ≥ указанного (например, `4.0`) |
| `--no-sort` | Не сортировать уязвимости по CVSS |
| `-q`, `--quiet` | Не выводить прогресс в консоль (ошибки всё равно выводятся) |
| `--watermark IMAGE` | Путь к PNG/JPG-файлу для фонового водяного знака на каждой странице |
| `--watermark-width INCHES` | Ширина водяного знака в дюймах (по умолчанию: `5.5`). Для A4 используй `8.27` |
| `--watermark-opacity 0-100` | Непрозрачность водяного знака (по умолчанию: `35`). Работает в MS Word; LibreOffice игнорирует — готовь заранее бледное изображение |

> Если ни один из флагов `--json` / `--docx` / `--pdf` не указан — по умолчанию создаётся Word-документ.

---

## Примеры

```bash
# Word-документ из каталога с XML (поведение по умолчанию)
python vuln_report.py -i /home/administrator/repXML/

# Только PDF
python vuln_report.py -i /home/administrator/repXML/ --pdf

# Word + PDF со своим именем файла
python vuln_report.py -i /home/administrator/repXML/ -o audit_2026_06 --docx --pdf

# Все три формата сразу
python vuln_report.py -i report.xml --json --docx --pdf

# Фильтр: только Medium и выше (CVSS ≥ 4.0)
python vuln_report.py -i /home/administrator/repXML/ --docx --min-cvss 4.0

# PDF с фоновым водяным знаком на весь лист A4
python vuln_report.py -i /home/administrator/repXML/ --pdf \
  --watermark /path/to/logo.png --watermark-width 8.27

# Рекурсивный обход вложенных папок
python vuln_report.py -i /home/administrator/repXML/ --pdf -r

# Тихий режим (без вывода прогресса)
python vuln_report.py -i report.xml --docx -q
```

---

## Структура выходных файлов

### JSON (`--json`)

```json
{
  "report_metadata": {
    "scan_date": "2026-06-16T10:49:20+03:00",
    "generated_at": "2026-06-16T11:00:00",
    "total_vulnerabilities_grouped": 60,
    "total_original_results": 129,
    "source_files": ["report1.xml", "report2.xml"]
  },
  "vulnerabilities": [
    {
      "oid": "1.3.6.1.4.1.25623.1.0.108031",
      "name": "SSL/TLS: Report Vulnerable Cipher Suites for HTTPS",
      "description": "Vulnerable cipher suite TLS_RSA_WITH_RC4_128_MD5 detected.",
      "impact": "An attacker may decrypt TLS traffic.",
      "solution": "Disable vulnerable cipher suites in server config.",
      "cvss_score": 7.5,
      "threat_level": "High",
      "affected_assets": [
        {
          "ip": "172.22.6.5",
          "hostname": "vfs2.nlb.by",
          "ports": ["443/tcp"]
        }
      ]
    }
  ]
}
```

### DOCX / PDF (`--docx`, `--pdf`)

Документ содержит разделы в следующем порядке:

1. **Титульный блок** — дата сканирования, дата формирования отчёта, число уникальных уязвимостей, число исходных результатов, список источников
2. **Сводка по уровням угрозы** — цветная таблица с количеством уязвимостей по уровням
3. **Общий перечень хостов** — таблица всех уникальных хостов (IP, имя хоста, количество уязвимостей), итоговая строка с общим числом хостов
4. **Подробное описание уязвимостей** — для каждой уязвимости:
   - Название, уровень угрозы (цветная плашка), CVSS, OID
   - Описание
   - Влияние
   - Решение
   - Затронутые хосты (таблица IP / имя хоста / порты)

Цветовая шкала уровней угрозы:

| Уровень | Цвет |
|---------|------|
| Критический (Critical) | 🔴 Тёмно-красный |
| Высокий (High) | 🔴 Красный |
| Средний (Medium) | 🟠 Оранжевый |
| Низкий (Low) | 🟡 Жёлтый |
| Информационный (Log) | ⚪ Серый |

---

## Структура проекта

```
vuln_report/
├── vuln_report.py   # основной скрипт
├── README.md        # документация
└── venv/            # виртуальное окружение (не коммитить в git)
```

### .gitignore

```
venv/
__pycache__/
*.pyc
*.docx
*.pdf
*.json
```

---

## Лицензия

MIT
