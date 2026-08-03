#!/usr/bin/env python3
"""
vuln_report.py

Объединенный инструмент: обрабатывает XML-отчеты Greenbone OpenVAS,
группирует уязвимости по OID и выдает результат в любом сочетании
форматов: JSON (структурированные данные), DOCX (человекочитаемый
Word-документ) и PDF (через LibreOffice).

Использование:
    # Только Word-документ (формат по умолчанию, если ничего не указано)
    python vuln_report.py -i /path/to/reports/

    # Word + PDF
    python vuln_report.py -i /path/to/reports/ --docx --pdf

    # Все три формата сразу
    python vuln_report.py -i /path/to/reports/ --json --docx --pdf

    # Только PDF (промежуточный .docx создается и удаляется автоматически)
    python vuln_report.py -i /path/to/reports/ --pdf

    # Свое базовое имя выходных файлов (без расширения)
    python vuln_report.py -i report.xml -o audit_2026_06 --docx --pdf

Зависимости:
    pip install python-docx
    (для --pdf необходим установленный LibreOffice: soffice в PATH)
"""

import argparse
import json
import os
import shutil
import subprocess
import sys
import xml.etree.ElementTree as ET
from datetime import datetime

from docx import Document
from docx.shared import Pt, Inches, RGBColor
from docx.enum.text import WD_ALIGN_PARAGRAPH
from docx.enum.table import WD_TABLE_ALIGNMENT
from docx.oxml.ns import qn
from docx.oxml import OxmlElement


# ============================================================================
# Общие константы
# ============================================================================

THREAT_ORDER = ["Critical", "High", "Medium", "Low", "Log", "None"]

THREAT_COLORS = {
    "Critical": "C00000",
    "High": "E53935",
    "Medium": "F57C00",
    "Low": "FBC02D",
    "Log": "9E9E9E",
    "None": "9E9E9E",
}

THREAT_TEXT_LIGHT = {"Critical", "High", "Medium"}  # светлый текст на темном фоне

RU_THREAT = {
    "Critical": "Критический",
    "High": "Высокий",
    "Medium": "Средний",
    "Low": "Низкий",
    "Log": "Информационный",
    "None": "Не определен",
}


def log(msg):
    print(msg, flush=True)


# ============================================================================
# Часть 1: парсинг XML-отчетов OpenVAS и группировка по OID
# ============================================================================

def find_xml_files(input_path):
    """Возвращает список путей к XML-файлам для обработки."""
    if not os.path.exists(input_path):
        log(f"[ОШИБКА] Путь не существует: {input_path}")
        return []

    if os.path.isfile(input_path):
        if input_path.lower().endswith(".xml"):
            return [input_path]
        log(f"[ОШИБКА] Файл не является XML: {input_path}")
        return []

    if os.path.isdir(input_path):
        files = []
        for fname in sorted(os.listdir(input_path)):
            if fname.lower().endswith(".xml"):
                files.append(os.path.join(input_path, fname))
        if not files:
            log(f"[ПРЕДУПРЕЖДЕНИЕ] В каталоге не найдено XML-файлов: {input_path}")
        return files

    log(f"[ОШИБКА] Неподдерживаемый тип пути: {input_path}")
    return []


def text_or_none(elem):
    if elem is None:
        return None
    return (elem.text or "").strip() or None


def get_report_scan_date(root):
    """Пытается найти дату сканирования в нескольких возможных местах отчета."""
    for tag in ("creation_time", "timestamp"):
        el = root.find(f".//{tag}")
        if el is not None and el.text:
            return el.text.strip()

    report_el = root.find(".//report")
    if report_el is not None:
        for tag in ("creation_time", "timestamp"):
            el = report_el.find(tag)
            if el is not None and el.text:
                return el.text.strip()

    return None


def severity_to_threat(score):
    """Резервное определение уровня угрозы по CVSS, если тег <threat> отсутствует."""
    try:
        score = float(score)
    except (TypeError, ValueError):
        return "Log"
    if score >= 9.0:
        return "Critical"
    if score >= 7.0:
        return "High"
    if score >= 4.0:
        return "Medium"
    if score > 0.0:
        return "Low"
    return "Log"


def extract_solution(nvt_el, result_el):
    """Решение может быть в <nvt><solution> или в <solution> на уровне result."""
    sol_el = None
    if nvt_el is not None:
        sol_el = nvt_el.find("solution")
    if sol_el is None or not text_or_none(sol_el):
        sol_el = result_el.find("solution")
    return text_or_none(sol_el)


def extract_host(result_el):
    """Возвращает (ip, hostname) из тега <host>."""
    host_el = result_el.find("host")
    if host_el is None:
        return None, None

    ip = (host_el.text or "").strip() or None
    hostname = text_or_none(host_el.find("hostname"))
    return ip, hostname


def parse_result(result_el):
    """Извлекает данные одной уязвимости (<result>). None, если нет OID."""
    nvt_el = result_el.find("nvt")
    oid = nvt_el.get("oid") if nvt_el is not None else None
    if not oid:
        return None

    name = None
    if nvt_el is not None:
        name = text_or_none(nvt_el.find("name"))
    if not name:
        name = text_or_none(result_el.find("name"))
    if not name:
        name = "Без названия"

    description = text_or_none(result_el.find("description"))
    solution = extract_solution(nvt_el, result_el)

    cvss_score = None
    severity_el = result_el.find("severity")
    if severity_el is not None and severity_el.text:
        try:
            cvss_score = float(severity_el.text.strip())
        except ValueError:
            cvss_score = None

    if cvss_score is None and nvt_el is not None:
        severities_el = nvt_el.find("severities")
        if severities_el is not None and severities_el.get("score"):
            try:
                cvss_score = float(severities_el.get("score"))
            except ValueError:
                cvss_score = None
        if cvss_score is None:
            cvss_base_el = nvt_el.find("cvss_base")
            if cvss_base_el is not None and cvss_base_el.text:
                try:
                    cvss_score = float(cvss_base_el.text.strip())
                except ValueError:
                    cvss_score = None

    if cvss_score is None:
        cvss_score = 0.0

    threat = text_or_none(result_el.find("threat"))
    if not threat:
        threat = severity_to_threat(cvss_score)

    ip, hostname = extract_host(result_el)
    port = text_or_none(result_el.find("port"))

    return {
        "oid": oid,
        "name": name,
        "description": description,
        "solution": solution,
        "cvss_score": cvss_score,
        "threat_level": threat,
        "ip": ip,
        "hostname": hostname,
        "port": port,
    }


def process_file(filepath, grouped, stats):
    log(f"Обработка файла: {filepath} ...")
    try:
        tree = ET.parse(filepath)
    except ET.ParseError as e:
        log(f"  [ОШИБКА] Некорректный XML в файле {filepath}: {e}")
        return
    except OSError as e:
        log(f"  [ОШИБКА] Не удалось открыть файл {filepath}: {e}")
        return

    root = tree.getroot()

    scan_date = get_report_scan_date(root)
    if scan_date and not stats["scan_date"]:
        stats["scan_date"] = scan_date

    results = root.findall(".//result")
    log(f"  Найдено результатов сканирования: {len(results)}")

    file_count = 0
    for result_el in results:
        parsed = parse_result(result_el)
        if parsed is None:
            continue

        stats["total_original_results"] += 1
        file_count += 1

        oid = parsed["oid"]
        entry = grouped.get(oid)
        if entry is None:
            entry = {
                "oid": oid,
                "name": parsed["name"],
                "description": parsed["description"] or "",
                "solution": parsed["solution"] or "",
                "cvss_score": parsed["cvss_score"],
                "threat_level": parsed["threat_level"],
                "_assets": {},  # ip -> {"hostname": ..., "ports": set()}
            }
            grouped[oid] = entry
        else:
            # Берем максимальную CVSS-оценку среди всех вхождений этого OID
            if parsed["cvss_score"] > entry["cvss_score"]:
                entry["cvss_score"] = parsed["cvss_score"]
                entry["threat_level"] = parsed["threat_level"]
            if not entry["description"] and parsed["description"]:
                entry["description"] = parsed["description"]
            if not entry["solution"] and parsed["solution"]:
                entry["solution"] = parsed["solution"]

        if parsed["ip"]:
            asset = entry["_assets"].setdefault(
                parsed["ip"], {"hostname": parsed["hostname"], "ports": set()}
            )
            if not asset["hostname"] and parsed["hostname"]:
                asset["hostname"] = parsed["hostname"]
            if parsed["port"]:
                asset["ports"].add(parsed["port"])

    log(f"  Обработано записей из файла: {file_count}")


def build_grouped_data(grouped, stats, source_files, sort_desc=True):
    """Собирает финальную структуру данных (аналог JSON-отчета)."""
    vulnerabilities = []
    for entry in grouped.values():
        affected_assets = []
        for ip, asset in entry["_assets"].items():
            affected_assets.append(
                {
                    "ip": ip,
                    "hostname": asset["hostname"],
                    "ports": sorted(asset["ports"]),
                }
            )
        affected_assets.sort(key=lambda a: a["ip"])

        vulnerabilities.append(
            {
                "oid": entry["oid"],
                "name": entry["name"],
                "description": entry["description"],
                "solution": entry["solution"],
                "cvss_score": entry["cvss_score"],
                "threat_level": entry["threat_level"],
                "affected_assets": affected_assets,
            }
        )

    vulnerabilities.sort(key=lambda v: v["cvss_score"], reverse=sort_desc)

    return {
        "report_metadata": {
            "scan_date": stats["scan_date"] or datetime.now().isoformat(),
            "total_vulnerabilities_grouped": len(vulnerabilities),
            "total_original_results": stats["total_original_results"],
            "source_files": source_files,
        },
        "vulnerabilities": vulnerabilities,
    }


def parse_xml_to_data(input_path, sort_desc=True):
    """Полный пайплайн: находит XML, парсит, группирует, возвращает dict-структуру."""
    xml_files = find_xml_files(input_path)
    if not xml_files:
        return None

    grouped = {}
    stats = {"total_original_results": 0, "scan_date": None}

    for filepath in xml_files:
        process_file(filepath, grouped, stats)

    if not grouped:
        log("[ПРЕДУПРЕЖДЕНИЕ] Не найдено ни одной уязвимости в обработанных файлах.")

    source_files = [os.path.basename(f) for f in xml_files]
    data = build_grouped_data(grouped, stats, source_files, sort_desc=sort_desc)

    log(f"Обработано файлов: {len(xml_files)}")
    log(f"Исходных результатов: {stats['total_original_results']}")
    log(f"Найдено уникальных уязвимостей: {len(grouped)}")

    return data


# ============================================================================
# Часть 2: генерация Word-документа (.docx) из данных
# ============================================================================

def shade_cell(cell, hex_color):
    tcPr = cell._tc.get_or_add_tcPr()
    shd = OxmlElement("w:shd")
    shd.set(qn("w:val"), "clear")
    shd.set(qn("w:color"), "auto")
    shd.set(qn("w:fill"), hex_color)
    tcPr.append(shd)


def set_cell_borders(cell, color="CCCCCC", size=4):
    tcPr = cell._tc.get_or_add_tcPr()
    borders = OxmlElement("w:tcBorders")
    for edge in ("top", "left", "bottom", "right"):
        el = OxmlElement(f"w:{edge}")
        el.set(qn("w:val"), "single")
        el.set(qn("w:sz"), str(size))
        el.set(qn("w:space"), "0")
        el.set(qn("w:color"), color)
        borders.append(el)
    tcPr.append(borders)


def set_column_widths(table, widths_inches):
    table.autofit = False
    for row in table.rows:
        for cell, width in zip(row.cells, widths_inches):
            cell.width = Inches(width)


def add_horizontal_rule(paragraph, color="2E75B6", size=6):
    pPr = paragraph._p.get_or_add_pPr()
    pBdr = OxmlElement("w:pBdr")
    bottom = OxmlElement("w:bottom")
    bottom.set(qn("w:val"), "single")
    bottom.set(qn("w:sz"), str(size))
    bottom.set(qn("w:space"), "4")
    bottom.set(qn("w:color"), color)
    pBdr.append(bottom)
    pPr.append(pBdr)


def set_cell_text(cell, text, bold=False, color=None, size=10, align=None):
    cell.text = ""
    p = cell.paragraphs[0]
    if align is not None:
        p.alignment = align
    run = p.add_run(text if text else "-")
    run.bold = bold
    run.font.size = Pt(size)
    run.font.name = "Arial"
    if color:
        run.font.color.rgb = RGBColor.from_string(color)
    return p


def setup_styles(doc):
    styles = doc.styles
    normal = styles["Normal"]
    normal.font.name = "Arial"
    normal.font.size = Pt(10.5)

    h1 = styles["Heading 1"]
    h1.font.name = "Arial"
    h1.font.size = Pt(20)
    h1.font.bold = True
    h1.font.color.rgb = RGBColor.from_string("1F1F1F")

    h2 = styles["Heading 2"]
    h2.font.name = "Arial"
    h2.font.size = Pt(13)
    h2.font.bold = True
    h2.font.color.rgb = RGBColor.from_string("1F1F1F")


def add_title_page(doc, meta):
    title = doc.add_heading("Отчет о результатах сканирования уязвимостей", level=1)
    title.alignment = WD_ALIGN_PARAGRAPH.LEFT

    p = doc.add_paragraph()
    p.add_run("Дата сканирования: ").bold = True
    p.add_run(str(meta.get("scan_date", "не указана")))

    p = doc.add_paragraph()
    p.add_run("Уникальных уязвимостей: ").bold = True
    p.add_run(str(meta.get("total_vulnerabilities_grouped", 0)))

    p = doc.add_paragraph()
    p.add_run("Всего исходных результатов: ").bold = True
    p.add_run(str(meta.get("total_original_results", 0)))

    p = doc.add_paragraph()
    p.add_run("Источники: ").bold = True
    p.add_run(", ".join(meta.get("source_files", [])) or "не указаны")

    sep = doc.add_paragraph()
    add_horizontal_rule(sep)


def add_summary_table(doc, vulnerabilities):
    counts = {key: 0 for key in THREAT_ORDER}
    for v in vulnerabilities:
        level = v.get("threat_level") or "None"
        counts[level] = counts.get(level, 0) + 1

    doc.add_heading("Сводка по уровням угрозы", level=2)

    table = doc.add_table(rows=2, cols=len(THREAT_ORDER))
    table.alignment = WD_TABLE_ALIGNMENT.LEFT
    widths = [1.15] * len(THREAT_ORDER)
    set_column_widths(table, widths)

    header_cells = table.rows[0].cells
    value_cells = table.rows[1].cells
    for i, level in enumerate(THREAT_ORDER):
        color = THREAT_COLORS[level]
        text_color = "FFFFFF" if level in THREAT_TEXT_LIGHT else "1F1F1F"
        set_cell_text(header_cells[i], RU_THREAT[level], bold=True,
                      color=text_color, size=9, align=WD_ALIGN_PARAGRAPH.CENTER)
        shade_cell(header_cells[i], color)
        set_cell_borders(header_cells[i])

        set_cell_text(value_cells[i], str(counts[level]), bold=True,
                      size=14, align=WD_ALIGN_PARAGRAPH.CENTER)
        set_cell_borders(value_cells[i])

    doc.add_paragraph()


def add_vulnerability_section(doc, vuln, index, total):
    level = vuln.get("threat_level") or "None"
    color = THREAT_COLORS.get(level, "9E9E9E")

    heading = doc.add_heading(level=2)
    run = heading.add_run(f"{index}. {vuln.get('name', 'Без названия')}")
    run.font.color.rgb = RGBColor.from_string("1F1F1F")

    # "Плашка" со статусом, CVSS и OID реализована через 1-строчную таблицу с заливкой
    badge_table = doc.add_table(rows=1, cols=3)
    badge_table.autofit = False
    cells = badge_table.rows[0].cells
    cells[0].width = Inches(1.3)
    cells[1].width = Inches(1.6)
    cells[2].width = Inches(2.0)
    set_cell_text(cells[0], RU_THREAT.get(level, level), bold=True,
                  color="FFFFFF" if level in THREAT_TEXT_LIGHT else "1F1F1F",
                  size=9, align=WD_ALIGN_PARAGRAPH.CENTER)
    shade_cell(cells[0], color)
    set_cell_borders(cells[0])
    set_cell_text(cells[1], f"CVSS: {vuln.get('cvss_score', 0)}", bold=True, size=9)
    set_cell_text(cells[2], f"OID: {vuln.get('oid', '')}", size=8)

    doc.add_paragraph()

    if vuln.get("description"):
        p = doc.add_paragraph()
        p.add_run("Описание: ").bold = True
        p.add_run(vuln["description"])

    if vuln.get("solution"):
        p = doc.add_paragraph()
        p.add_run("Решение: ").bold = True
        p.add_run(vuln["solution"])

    assets = vuln.get("affected_assets", [])
    if assets:
        doc.add_paragraph().add_run(f"Затронутые хосты ({len(assets)}):").bold = True

        table = doc.add_table(rows=1, cols=3)
        table.alignment = WD_TABLE_ALIGNMENT.LEFT
        widths = [1.6, 2.4, 2.8]
        set_column_widths(table, widths)

        header = table.rows[0].cells
        for i, label in enumerate(["IP-адрес", "Имя хоста", "Порты"]):
            set_cell_text(header[i], label, bold=True, color="FFFFFF", size=9)
            shade_cell(header[i], "404040")
            set_cell_borders(header[i])

        for asset in assets:
            row = table.add_row().cells
            set_cell_text(row[0], asset.get("ip", "-"), size=9)
            set_cell_text(row[1], asset.get("hostname") or "-", size=9)
            set_cell_text(row[2], ", ".join(asset.get("ports", [])) or "-", size=9)
            for cell in row:
                set_cell_borders(cell)

    if index < total:
        sep = doc.add_paragraph()
        sep.paragraph_format.space_before = Pt(12)
        add_horizontal_rule(sep, color="D9D9D9", size=4)


def build_document(data):
    doc = Document()
    section = doc.sections[0]
    section.page_width = Inches(8.5)
    section.page_height = Inches(11)
    section.left_margin = Inches(0.8)
    section.right_margin = Inches(0.8)
    section.top_margin = Inches(0.8)
    section.bottom_margin = Inches(0.8)

    setup_styles(doc)

    meta = data.get("report_metadata", {})
    vulnerabilities = data.get("vulnerabilities", [])

    add_title_page(doc, meta)
    add_summary_table(doc, vulnerabilities)

    doc.add_heading("Подробное описание уязвимостей", level=1)

    total = len(vulnerabilities)
    for i, vuln in enumerate(vulnerabilities, start=1):
        add_vulnerability_section(doc, vuln, i, total)

    return doc


# ============================================================================
# Часть 3: конвертация DOCX -> PDF через LibreOffice
# ============================================================================

def convert_to_pdf(docx_path):
    soffice = shutil.which("soffice") or shutil.which("libreoffice")
    if not soffice:
        log("[ПРЕДУПРЕЖДЕНИЕ] LibreOffice (soffice) не найден в PATH. "
            "PDF не создан. Установите LibreOffice (sudo apt install libreoffice) "
            "или откройте .docx и сохраните как PDF вручную.")
        return None

    outdir = os.path.dirname(os.path.abspath(docx_path)) or "."
    try:
        subprocess.run(
            [soffice, "--headless", "--convert-to", "pdf", "--outdir", outdir, docx_path],
            check=True, capture_output=True, timeout=120,
        )
    except subprocess.CalledProcessError as e:
        log(f"[ОШИБКА] Конвертация в PDF не удалась: {e.stderr.decode(errors='ignore')}")
        return None
    except subprocess.TimeoutExpired:
        log("[ОШИБКА] Конвертация в PDF превысила тайм-аут.")
        return None

    pdf_path = os.path.splitext(docx_path)[0] + ".pdf"
    return pdf_path if os.path.exists(pdf_path) else None


# ============================================================================
# main
# ============================================================================

def main():
    parser = argparse.ArgumentParser(
        description=(
            "Группировка уязвимостей из XML-отчетов Greenbone OpenVAS по OID "
            "с выводом в JSON, Word (.docx) и/или PDF."
        )
    )
    parser.add_argument(
        "-i", "--input", required=True,
        help="Путь к XML-файлу или каталогу с XML-файлами отчетов OpenVAS.",
    )
    parser.add_argument(
        "-o", "--output", default="vulnerability_report",
        help="Базовое имя выходных файлов без расширения "
             "(по умолчанию: vulnerability_report).",
    )
    parser.add_argument(
        "--json", action="store_true",
        help="Сохранить структурированный JSON-отчет (<output>.json).",
    )
    parser.add_argument(
        "--docx", action="store_true",
        help="Сохранить человекочитаемый Word-документ (<output>.docx).",
    )
    parser.add_argument(
        "--pdf", action="store_true",
        help="Сохранить PDF (<output>.pdf). Требует LibreOffice (soffice в PATH).",
    )
    parser.add_argument(
        "--no-sort", action="store_true",
        help="Не сортировать уязвимости по CVSS (по умолчанию сортировка по убыванию включена).",
    )
    args = parser.parse_args()

    # Если ни один формат не указан явно — по умолчанию делаем Word-документ,
    # как наиболее человекочитаемый вариант.
    if not (args.json or args.docx or args.pdf):
        log("Формат вывода не указан (--json/--docx/--pdf), "
            "по умолчанию будет создан Word-документ (--docx).")
        args.docx = True

    data = parse_xml_to_data(args.input, sort_desc=not args.no_sort)
    if data is None:
        log("Не найдено файлов для обработки. Завершение.")
        sys.exit(1)

    produced = []

    if args.json:
        json_path = f"{args.output}.json"
        try:
            with open(json_path, "w", encoding="utf-8") as f:
                json.dump(data, f, ensure_ascii=False, indent=2)
            produced.append(json_path)
        except OSError as e:
            log(f"[ОШИБКА] Не удалось записать {json_path}: {e}")

    docx_path = f"{args.output}.docx"
    docx_was_requested = args.docx
    docx_created_for_pdf_only = False

    if args.docx or args.pdf:
        log("Формирование Word-документа ...")
        doc = build_document(data)
        try:
            doc.save(docx_path)
        except OSError as e:
            log(f"[ОШИБКА] Не удалось сохранить {docx_path}: {e}")
            docx_path = None

        if docx_path:
            if docx_was_requested:
                produced.append(docx_path)
            else:
                docx_created_for_pdf_only = True

    if args.pdf and docx_path:
        log("Конвертация в PDF ...")
        pdf_path = convert_to_pdf(docx_path)
        if pdf_path:
            produced.append(pdf_path)

        # Если .docx нужен был только как промежуточный шаг для PDF — убираем его
        if docx_created_for_pdf_only and os.path.exists(docx_path):
            os.remove(docx_path)

    log("")
    log("=== Готово ===")
    if produced:
        for path in produced:
            log(f"  -> {path}")
    else:
        log("  Ничего не было сохранено (проверьте сообщения об ошибках выше).")


if __name__ == "__main__":
    main()
