Инструмент для обработки XML-отчётов сканера уязвимостей **Greenbone OpenVAS**.  
Группирует уязвимости по уникальному идентификатору (OID), объединяет хосты,  
на которых они обнаружены, и генерирует отчёт в одном или нескольких форматах.

---

## Возможности

- Принимает один XML-файл или каталог с несколькими XML-файлами
- Группирует уязвимости по OID — одна уязвимость на 20 хостах = одна запись в отчёте
- Берёт максимальную CVSS-оценку среди всех вхождений одного OID
- Сортирует уязвимости по убыванию CVSS (отключается флагом `--no-sort`)
- Выводит результат в любом сочетании форматов: **JSON**, **DOCX**, **PDF**
- При запросе только PDF — промежуточный `.docx` создаётся и удаляется автоматически
- Корректно пропускает битые XML-файлы, не прерывая обработку остальных
- Позволяет добавить **водяной знак** (логотип организации) на каждую страницу DOCX/PDF с настраиваемой шириной и прозрачностью

---

## Требования

| Компонент | Версия | Назначение |
|-----------|--------|------------|
| Python | 3.6+ | интерпретатор |
| [python-docx](https://python-docx.readthedocs.io/) | любая | генерация DOCX |
| LibreOffice (`soffice`) | любая | конвертация в PDF (только для `--pdf`) |

### Установка зависимостей

```bash
# Рекомендуется использовать виртуальное окружение
python3 -m venv venv
source venv/bin/activate         

pip install python-docx

sudo apt install libreoffice
```

---

## Использование

```
python vuln_report.py -i <путь> [--json] [--docx] [--pdf] [-o <имя>] [--no-sort]
                       [--watermark <файл>] [--watermark-opacity 0-100] [--watermark-width <дюймы>]
```

### Аргументы

| Флаг | Описание |
|------|----------|
| `-i`, `--input` | **Обязательный.** Путь к XML-файлу или каталогу с XML-файлами |
| `--json` | Сохранить структурированный JSON-отчёт |
| `--docx` | Сохранить человекочитаемый Word-документ |
| `--pdf` | Сохранить PDF (требует LibreOffice) |
| `-o`, `--output` | Базовое имя выходных файлов без расширения (по умолчанию: `vulnerability_report`) |
| `--no-sort` | Отключить сортировку по CVSS |
| `--watermark IMAGE` | Путь к файлу изображения (PNG/JPG/BMP), которое будет добавлено как фоновый водяной знак на каждой странице DOCX/PDF |
| `--watermark-opacity 0-100` | Непрозрачность водяного знака: 0 = невидимый, 100 = сплошной (по умолчанию: 35). Работает в MS Word; **LibreOffice при экспорте в PDF её игнорирует** |
| `--watermark-width INCHES` | Ширина водяного знака в дюймах (по умолчанию: 5.5). Высота масштабируется автоматически |

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

# Все три формата из одного XML-файла
python vuln_report.py -i report.xml --json --docx --pdf

# JSON без сортировки по CVSS
python vuln_report.py -i /home/administrator/repXML/ --json --no-sort

# С водяным знаком (логотип организации на каждой странице)
python vuln_report.py -i /home/administrator/repXML/ --pdf --watermark /path/to/logo.png

# Водяной знак с пользовательской шириной и непрозрачностью
python vuln_report.py -i /home/administrator/repXML/ --docx \
    --watermark logo.png --watermark-width 6 --watermark-opacity 20
```

---

## Структура выходных файлов

### JSON (`--json`)

```json
{
  "report_metadata": {
    "scan_date": "2026-06-16T10:49:20+03:00",
    "total_vulnerabilities_grouped": 60,
    "total_original_results": 129,
    "source_files": ["report1.xml", "report2.xml"]
  },
  "vulnerabilities": [
    {
      "oid": "1.3.6.1.4.1.25623.1.0.108031",
      "name": "SSL/TLS: Report Vulnerable Cipher Suites for HTTPS",
      "description": "...",
      "solution": "...",
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

Документ содержит:
- **Титульный блок** — дата сканирования, число уникальных уязвимостей, исходных результатов, список источников
- **Сводная таблица** — количество уязвимостей по уровню угрозы с цветовой маркировкой
- **Подробное описание** — для каждой уязвимости: название, уровень угрозы, CVSS, OID, описание, решение, таблица затронутых хостов (IP / hostname / порты)

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
```

---

## Лицензия

MIT
