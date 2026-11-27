"""
Generate Team 04's Final Project Report (.docx) for Cyber Security Attack Analysis.
Uses the exact cover theme of DV_Proposal/ReportCover.png and the visual layout
of DSG2-T4-DV-Project_Proposal.pdf, embedding the verified high-DPI charts.

Run:  .venv\Scripts\python.exe build_report.py
Writes: DSG2-T4-DV-Final_Report.docx
"""
from __future__ import annotations

from pathlib import Path
from PIL import Image, ImageDraw, ImageFont
from docx import Document
from docx.enum.table import WD_TABLE_ALIGNMENT
from docx.enum.text import WD_ALIGN_PARAGRAPH
from docx.oxml import OxmlElement, parse_xml
from docx.oxml.ns import nsdecls, qn
from docx.shared import Inches, Pt, RGBColor

# ----------------------------------------------------------------- PATHS
BASE = Path(__file__).resolve().parent
PROPOSAL_DIR = BASE.parent / "DV_Proposal"
COVER_SRC = PROPOSAL_DIR / "ReportCover.png"
EXPORT_DIR = BASE / "exports"
FINAL_COVER_IMG = EXPORT_DIR / "_final_report_cover.png"
OUT_DOCX = BASE / "DSG2-T4-DV-Final_Report.docx"

# ----------------------------------------------------------------- COLORS
NAVY = RGBColor(0x13, 0x29, 0x4B)
ORANGE_HEX = "E8872B"
NAVY_HEX = "13294B"
LIGHT_BG_HEX = "F1F5F9"
BORDER_HEX = "CBD5E1"
TEXT_DARK = RGBColor(0x11, 0x18, 0x27)
TEXT_BODY = RGBColor(0x1F, 0x29, 0x37)
TEXT_MUTED = RGBColor(0x4B, 0x55, 0x63)


def build_final_cover_image() -> Path:
    """
    Create a Final Report cover directly from ReportCover.png (1414x2000),
    replacing 'Project Proposal' with 'Cyber Security Attack Analysis' / 'Final Project Report'
    while preserving the exact CADT IDT logo, typography, side bars, and team credits.
    """
    im = Image.open(COVER_SRC).convert("RGB")
    draw = ImageDraw.Draw(im)
    # Sample exact background color from cover
    bg_color = im.getpixel((700, 100))

    # Cleanly patch over "Project Proposal" (approx x: 100..900, y: 990..1120)
    draw.rectangle([100, 995, 1150, 1180], fill=bg_color)

    # Load clean system fonts (fallback safely)
    def load_font(candidates: list[str], size: int):
        for path in candidates:
            if Path(path).exists():
                return ImageFont.truetype(path, size)
        return ImageFont.load_default()

    font_sub = load_font(
        [r"C:\Windows\Fonts\segoeuil.ttf", r"C:\Windows\Fonts\segoeui.ttf", r"C:\Windows\Fonts\arial.ttf"],
        54,
    )
    font_accent = load_font(
        [r"C:\Windows\Fonts\seguisb.ttf", r"C:\Windows\Fonts\segoeuib.ttf", r"C:\Windows\Fonts\arialbd.ttf"],
        44,
    )

    draw.text((117, 1005), "Final Project Report", fill=(17, 24, 39), font=font_sub)
    draw.text((117, 1085), "Cyber Security Attack Analysis", fill=(19, 41, 75), font=font_accent)

    EXPORT_DIR.mkdir(exist_ok=True)
    im.save(FINAL_COVER_IMG)
    return FINAL_COVER_IMG


# ----------------------------------------------------------------- DOCX HELPERS
def set_cell_shading(cell, hex_color: str) -> None:
    shading = parse_xml(f'<w:shd {nsdecls("w")} w:fill="{hex_color}"/>')
    cell._tc.get_or_add_tcPr().append(shading)


def set_cell_margins(cell, top=80, bottom=80, left=120, right=120) -> None:
    tcPr = cell._tc.get_or_add_tcPr()
    tcMar = OxmlElement("w:tcMar")
    for side, val in [("top", top), ("bottom", bottom), ("left", left), ("right", right)]:
        node = OxmlElement(f"w:{side}")
        node.set(qn("w:w"), str(val))
        node.set(qn("w:type"), "dxa")
        tcMar.append(node)
    tcPr.append(tcMar)


def set_table_borders(table, border_hex: str = BORDER_HEX) -> None:
    tblPr = table._tbl.tblPr
    borders = parse_xml(
        f'<w:tblBorders {nsdecls("w")}>'
        f'<w:top w:val="single" w:sz="6" w:space="0" w:color="{border_hex}"/>'
        f'<w:bottom w:val="single" w:sz="6" w:space="0" w:color="{border_hex}"/>'
        f'<w:left w:val="single" w:sz="4" w:space="0" w:color="{border_hex}"/>'
        f'<w:right w:val="single" w:sz="4" w:space="0" w:color="{border_hex}"/>'
        f'<w:insideH w:val="single" w:sz="4" w:space="0" w:color="{border_hex}"/>'
        f'<w:insideV w:val="single" w:sz="4" w:space="0" w:color="{border_hex}"/>'
        f"</w:tblBorders>"
    )
    tblPr.append(borders)


def add_section_heading(doc: Document, text: str) -> None:
    """Navy section heading with signature orange bottom border (matches proposal PDF)."""
    p = doc.add_paragraph()
    p.paragraph_format.space_before = Pt(14)
    p.paragraph_format.space_after = Pt(6)
    p.paragraph_format.keep_with_next = True
    run = p.add_run(text)
    run.font.name = "Segoe UI"
    run.font.size = Pt(15)
    run.font.bold = True
    run.font.color.rgb = NAVY

    pPr = p._p.get_or_add_pPr()
    pBdr = parse_xml(
        f'<w:pBdr {nsdecls("w")}>'
        f'<w:bottom w:val="single" w:sz="12" w:space="4" w:color="{ORANGE_HEX}"/>'
        f"</w:pBdr>"
    )
    pPr.append(pBdr)


def add_sub_heading(doc: Document, text: str) -> None:
    p = doc.add_paragraph()
    p.paragraph_format.space_before = Pt(10)
    p.paragraph_format.space_after = Pt(4)
    p.paragraph_format.keep_with_next = True
    run = p.add_run(text)
    run.font.name = "Segoe UI"
    run.font.size = Pt(11.5)
    run.font.bold = True
    run.font.color.rgb = NAVY


def add_body(doc: Document, text: str, space_after: int = 6) -> None:
    p = doc.add_paragraph()
    p.paragraph_format.space_after = Pt(space_after)
    p.paragraph_format.line_spacing = 1.18
    run = p.add_run(text)
    run.font.name = "Segoe UI"
    run.font.size = Pt(10.5)
    run.font.color.rgb = TEXT_BODY


def add_bullet(doc: Document, lead: str, body: str) -> None:
    p = doc.add_paragraph(style="List Bullet")
    p.paragraph_format.space_after = Pt(4)
    p.paragraph_format.line_spacing = 1.15
    if lead:
        r1 = p.add_run(lead + " ")
        r1.font.name = "Segoe UI"
        r1.font.size = Pt(10.5)
        r1.font.bold = True
        r1.font.color.rgb = TEXT_DARK
    r2 = p.add_run(body)
    r2.font.name = "Segoe UI"
    r2.font.size = Pt(10.5)
    r2.font.color.rgb = TEXT_BODY


def add_styled_table(doc: Document, headers: list[str], rows: list[list[str]], col_widths: list[float] | None = None) -> None:
    table = doc.add_table(rows=1 + len(rows), cols=len(headers))
    table.alignment = WD_TABLE_ALIGNMENT.CENTER
    set_table_borders(table)

    # Header row
    hdr_cells = table.rows[0].cells
    for j, h in enumerate(headers):
        set_cell_shading(hdr_cells[j], NAVY_HEX)
        set_cell_margins(hdr_cells[j], top=90, bottom=90, left=110, right=110)
        p = hdr_cells[j].paragraphs[0]
        p.paragraph_format.space_after = Pt(0)
        r = p.add_run(h)
        r.font.name = "Segoe UI"
        r.font.size = Pt(9.5)
        r.font.bold = True
        r.font.color.rgb = RGBColor(0xFF, 0xFF, 0xFF)

    # Data rows
    for i, row_data in enumerate(rows):
        cells = table.rows[i + 1].cells
        bg = LIGHT_BG_HEX if i % 2 == 1 else "FFFFFF"
        for j, val in enumerate(row_data):
            set_cell_shading(cells[j], bg)
            set_cell_margins(cells[j], top=70, bottom=70, left=110, right=110)
            p = cells[j].paragraphs[0]
            p.paragraph_format.space_after = Pt(0)
            r = p.add_run(val)
            r.font.name = "Segoe UI"
            r.font.size = Pt(9.5)
            r.font.bold = (j == 0)
            r.font.color.rgb = TEXT_DARK if j == 0 else TEXT_BODY

    if col_widths:
        for row in table.rows:
            for j, w in enumerate(col_widths):
                row.cells[j].width = Inches(w)

    spacer = doc.add_paragraph()
    spacer.paragraph_format.space_after = Pt(4)


def add_figure(doc: Document, img_path: Path, caption: str, width_in: float = 6.2) -> None:
    p_img = doc.add_paragraph()
    p_img.alignment = WD_ALIGN_PARAGRAPH.CENTER
    p_img.paragraph_format.space_before = Pt(6)
    p_img.paragraph_format.space_after = Pt(3)
    p_img.paragraph_format.keep_with_next = True
    p_img.add_run().add_picture(str(img_path), width=Inches(width_in))

    p_cap = doc.add_paragraph()
    p_cap.alignment = WD_ALIGN_PARAGRAPH.CENTER
    p_cap.paragraph_format.space_after = Pt(10)
    r = p_cap.add_run(caption)
    r.font.name = "Segoe UI"
    r.font.size = Pt(9)
    r.font.italic = True
    r.font.color.rgb = TEXT_MUTED


def add_page_number_to_footer(section) -> None:
    footer = section.footer
    p = footer.paragraphs[0]
    p.alignment = WD_ALIGN_PARAGRAPH.RIGHT
    r = p.add_run("Page ")
    r.font.name = "Segoe UI"
    r.font.size = Pt(9)
    r.font.color.rgb = TEXT_MUTED
    fld = parse_xml(r'<w:fldSimple %s w:instr="PAGE"/>' % nsdecls("w"))
    p._p.append(fld)


def build_report() -> None:
    cover_img = build_final_cover_image()

    doc = Document()

    # Configure Page 1 (Cover section — zero margins for full-bleed cover matching ReportCover.png)
    sec_cover = doc.sections[0]
    sec_cover.page_width = Inches(8.27)   # A4
    sec_cover.page_height = Inches(11.69)
    sec_cover.top_margin = Inches(0)
    sec_cover.bottom_margin = Inches(0)
    sec_cover.left_margin = Inches(0)
    sec_cover.right_margin = Inches(0)

    p_cov = doc.add_paragraph()
    p_cov.alignment = WD_ALIGN_PARAGRAPH.CENTER
    p_cov.paragraph_format.space_before = Pt(0)
    p_cov.paragraph_format.space_after = Pt(0)
    p_cov.add_run().add_picture(str(cover_img), width=Inches(8.27))

    # Start Section 2 (Main Report Content — standard A4 margins + header/footer)
    sec_main = doc.add_section()
    sec_main.page_width = Inches(8.27)
    sec_main.page_height = Inches(11.69)
    sec_main.top_margin = Inches(0.85)
    sec_main.bottom_margin = Inches(0.85)
    sec_main.left_margin = Inches(0.85)
    sec_main.right_margin = Inches(0.85)
    sec_main.header.is_linked_to_previous = False
    sec_main.footer.is_linked_to_previous = False

    hp = sec_main.header.paragraphs[0]
    hp.alignment = WD_ALIGN_PARAGRAPH.RIGHT
    hr = hp.add_run("Data Visualization — Final Project Report  |  Team 04")
    hr.font.name = "Segoe UI"
    hr.font.size = Pt(9)
    hr.font.color.rgb = TEXT_MUTED
    add_page_number_to_footer(sec_main)

    # Set default Normal style font
    normal = doc.styles["Normal"]
    normal.font.name = "Segoe UI"
    normal.font.size = Pt(10.5)
    normal.font.color.rgb = TEXT_BODY

    # ================================================================= OVERVIEW & EXEC SUMMARY
    add_section_heading(doc, "Project Overview & Executive Summary")
    add_styled_table(
        doc,
        ["Field", "Details"],
        [
            ["Project Title", "Cyber Security Attack Analysis"],
            ["Course & Lecturer", "Data Visualization  —  Lecturer: Sam Sreyleak"],
            ["Department", "Department of Computer Science, Specialized in Data Science (CADT — IDT)"],
            ["Team 04", "Seat Sreylenn, Ly Yeakkhai, Mak Khemara, Sy Isean, Chap Chanliya, Tho Vicheka"],
            ["Deliverables", "Cleaned CSV, 11 Interactive HTML Charts, Interactive KPI Dashboard, 11-Page PDF Pack, Jupyter Notebook, Presentation Deck & Final Report"],
        ],
        col_widths=[1.8, 4.77],
    )
    add_body(
        doc,
        "Modern Security Operations Centers (SOCs) generate tens of thousands of network security logs that are impossible to "
        "audit effectively in raw tabular form. This project transforms 40,000 logged cyberattack events (January 2020 – October 11, 2023) "
        "into a clean, reproducible analytical pipeline, 11 principle-driven visualizations, and an interactive KPI dashboard.",
    )
    add_body(
        doc,
        "Our analysis reveals a uniform threat landscape across attack types (~33% each), severity levels (~33% each), network segments, "
        "protocols, and 28 Indian states, alongside one standout operational anomaly: blocking rates remain flat at ~34% across all severity "
        "levels, leaving 33.3% of High-severity attacks Ignored. Because these even distributions confirm the Kaggle dataset is synthetic, "
        "our report transparently documents both the analytical methodology and the real-world SOC triage lessons it demonstrates.",
    )

    # ================================================================= 1. OBJECTIVES
    add_section_heading(doc, "1. Introduction, Topic Fit & Objectives")
    add_sub_heading(doc, "1.1 Problem Statement & Why This Topic Fits")
    add_body(
        doc,
        "Raw security event logs capture rich operational signals—timestamps, attack classifications, severity ratings, anomaly scores, "
        "detection alerts, and response actions—but tabular inspection obscures whether defenses respond in proportion to threat severity. "
        "Cyber Security Attack Analysis is an ideal Data Visualization topic because it combines temporal, categorical, ordered, continuous "
        "numerical, and geographic variables in a single real-world domain.",
    )
    add_sub_heading(doc, "1.2 Project Objectives & Target Audience")
    add_bullet(doc, "Primary Objective:", "Identify temporal trends and peak activity patterns from January 2020 to October 2023 across months, years, days of the week, and hours of the day.")
    add_bullet(doc, "Secondary Objective:", "Compare attack distribution across attack type, severity level, response action, protocol, traffic type, network segment, anomaly score, detection signals, and Indian states.")
    add_bullet(doc, "Target Audience:", "Course instructor evaluating visualization rigor (Week 3–4 Colour Theory & Week 7 Principles) and a hypothetical SOC team and IT management reviewing incident triage performance.")

    # ================================================================= 2. DATASET
    add_section_heading(doc, "2. Dataset Origin & Data Understanding")
    add_body(
        doc,
        "The dataset is sourced from Kaggle: \"Cyber Security Attacks\" (cybersecurity_attacks.csv) by Aashray Agur and Uma Venugopal. "
        "It contains 40,000 rows and 25 raw columns, where each row represents one logged network security event at second-level timestamp "
        "granularity spanning 1 January 2020 to 11 October 2023 across 28 Indian states (316 distinct cities).",
    )
    add_styled_table(
        doc,
        ["Variable Group", "Fields", "Key Characteristics"],
        [
            ["Temporal & Geographic", "Timestamp, Geo-location Data", "Second-level timestamps (2020–Oct 11, 2023); \"City, State\" across 28 Indian states"],
            ["Attack & Response", "Attack Type, Severity Level, Action Taken", "DDoS / Malware / Intrusion; Low / Medium / High; Blocked / Logged / Ignored"],
            ["Numeric Metrics", "Anomaly Scores, Packet Length, Source/Dest Port", "Scores 0–100 (mean 50.11); Packet Length 64–1,500 bytes; Ports 0–65,535"],
            ["Network & Device", "Protocol, Traffic Type, Network Segment, Device Info", "TCP/UDP/ICMP; HTTP/DNS/FTP; Segments A/B/C; User-Agent string (OS & Browser)"],
            ["Detection Signals (5)", "Malware Indicators, Alerts/Warnings, Proxy Info, Firewall Logs, IDS/IPS Alerts", "~50% blank per column; a blank indicates the signal did not trigger (not missing data)"],
        ],
        col_widths=[1.55, 2.22, 2.80],
    )
    add_body(
        doc,
        "Data Integrity & Privacy Note: Initial profiling confirmed zero duplicate rows and zero missing values in 20 of 25 columns. "
        "Because category counts are nearly uniform and payload text contains placeholder strings, the dataset is synthetic. Although names "
        "and IP addresses are fictitious, we exclude all personally identifiable fields from visuals and cleaned exports as standard practice.",
    )

    # ================================================================= 3. METHODOLOGY
    add_section_heading(doc, "3. Methodology: Cleaning, Visualization & Colour Theory")
    add_sub_heading(doc, "3.1 Data Cleaning, Feature Engineering & Validation")
    add_body(
        doc,
        "All cleaning and validation steps are automated and reproducible in analysis.py and analysis.ipynb (Python / pandas), "
        "saving a shared cleaned dataset (Datasets/cleaned_cybersecurity_attacks.csv, 40,000 rows × 37 columns):",
    )
    add_bullet(doc, "No-Imputation Signal Recoding:", "Blanks in the 5 detection columns mean \"not triggered.\" Dropping them would discard half the data, so each was recoded to a Yes/No flag and validated to sum back to 40,000.")
    add_bullet(doc, "Parsing & Standardization:", "Converted Timestamp to datetime; ordered Severity Level (Low < Medium < High); trimmed whitespace; split Geo-location Data into City and State; parsed Device Information into Device OS (5 families: Windows 17,953 to Android 3,289) and Browser Family (5 families: Chrome to Firefox) with 0 unparsed rows.")
    add_bullet(doc, "Derived Features & Validation:", "Created Year, Quarter, Month, DayOfWeek, Hour, binary Blocked, Anomaly Band, High Anomaly (≥75; 10,012 rows), and Packet Size Band. Confirmed 0 post-conversion duplicates and 0 out-of-range values for ports, packet lengths, and anomaly scores.")
    add_bullet(doc, "Privacy Cleanup:", "Dropped Payload Data, Source/Destination IP Address, User Information, raw Device Information, and raw Proxy Information.")

    add_styled_table(
        doc,
        ["Raw Signal Column", "Present (Yes)", "Blank (No)", "Recoded Flag Column", "Check (Yes + No)"],
        [
            ["Malware Indicators", "20,000 (50.0%)", "20,000 (50.0%)", "IoC Detected", "40,000"],
            ["Alerts/Warnings", "19,933 (49.8%)", "20,067 (50.2%)", "Alert Triggered", "40,000"],
            ["Proxy Information", "20,149 (50.4%)", "19,851 (49.6%)", "Proxy Used", "40,000"],
            ["Firewall Logs", "20,039 (50.1%)", "19,961 (49.9%)", "Firewall Log", "40,000"],
            ["IDS/IPS Alerts", "19,950 (49.9%)", "20,050 (50.1%)", "IDS/IPS Alert", "40,000"],
        ],
        col_widths=[1.55, 1.25, 1.25, 1.32, 1.20],
    )

    add_sub_heading(doc, "3.2 Visualization Principles (Week 7) & Colour Theory (Week 3–4)")
    add_body(
        doc,
        "Every chart was engineered and audited directly against the course's theoretical framework—combining Week 7's Five Principles "
        "of Data Visualization and Distribution Analysis with Week 3–4's Colour Theory:",
    )
    add_bullet(doc, "Principle 1 (Show the Data) & Distribution Analysis:", "Selected purpose-fit charts across 11 visuals, including both a Box Plot (median/IQR comparison) and a Histogram (bin width = 5) + KDE curve to reveal distribution shape.")
    add_bullet(doc, "Principle 2 (Make Meaning Clear):", "Every chart features a takeaway-driven title, plain-English axis labels with units, and targeted annotations (partial Oct 2023 callout, 33.3% Ignored callout, ≥75 threshold).")
    add_bullet(doc, "Principle 3 (Avoid Distortion — Lie Factor = 1):", "Anchored all bar charts and the monthly time-series chart to a zero y-axis baseline; widened the bubble chart color range so minor ~3.6% differences are not visually exaggerated.")
    add_bullet(doc, "Principle 4 (Accessibility) & Principle 5 (Focus on Content):", "Used colorblind-safe Okabe-Ito & ColorBrewer palettes, paired hues with distinct line styles (solid/dash/dot), enforced high-contrast dark/light bubble text, removed top/right chartjunk spines, and placed legends outside data areas.")

    add_styled_table(
        doc,
        ["Data Variable / Role", "Colour Theory Rule (Week 3–4)", "Assigned Palette (Zero Collisions)"],
        [
            ["Attack Type (Unordered)", "Distinct Hue + redundant line styles", "Okabe-Ito: Blue (#0072B2), Vermilion (#D55E00), Teal-Green (#009E73)"],
            ["Severity Level (Ordered)", "Lightness & Monochromatic Harmony", "ColorBrewer Purples: Low (#DADAEB) → Med (#9E9AC8) → High (#54278F)"],
            ["Action Taken (Focal Emphasis)", "Saturation Hierarchy & Deliberate Contrast", "Deep Teal Blocked (#2A7B88), Low-Sat Gray Logged (#94A3B8), Vivid Crimson Ignored (#C0264B)"],
            ["Aggregate Totals (All Events)", "Consistent Neutral Hue (no DDoS collision)", "Neutral Slate (#475569) with Amber-Brown (#B45309) KDE curve"],
        ],
        col_widths=[1.75, 2.05, 2.77],
    )

    # ================================================================= 4. FINDINGS
    add_section_heading(doc, "4. Visual Analysis & Key Findings")

    add_sub_heading(doc, "4.1 Finding 1 — Steady Attack Volume Over Time (With Partial Oct 2023)")
    add_body(
        doc,
        "Annual attack volume remains steady across full calendar years: 10,573 events in 2020, 10,538 in 2021, and 10,750 in 2022 "
        "(~280–320 monthly events per attack type). The sharp drop in October 2023 occurs solely because data collection ends on "
        "11 October 2023 (296 Q4 rows). Similarly, the day-of-week × hour heatmap confirms uniform 24/7 activity (~200–279 events per slot).",
    )
    add_figure(doc, EXPORT_DIR / "01_monthly_trend.png", "Figure 1: Monthly attack volume by type (y-axis starts at 0 for Lie Factor = 1; shaded callout flags partial Oct 2023).", width_in=6.3)

    add_sub_heading(doc, "4.2 Finding 2 — Balanced Attack Types, Severity & Network Exposure")
    add_body(
        doc,
        "No single threat category dominates the logs: DDoS (13,428; 33.6%), Malware (13,307; 33.3%), and Intrusion (13,265; 33.2%) "
        "occur at nearly identical rates. Within every attack type, Severity Level splits evenly across Low (33.0%), Medium (33.6%), "
        "and High (33.5%). Exposure across Network Segments (A/B/C) and Protocol × Traffic pairs (~4,400 events each) is equally uniform.",
    )
    add_figure(doc, EXPORT_DIR / "03_attack_type_bar.png", "Figure 2: Horizontal bar chart comparing total event counts across the three attack types.", width_in=5.8)
    add_figure(doc, EXPORT_DIR / "04_severity_stacked.png", "Figure 3: Stacked bar chart showing ordered Severity Level (monochromatic purple scale) across Attack Types.", width_in=5.8)

    add_sub_heading(doc, "4.3 Finding 3 (Key Finding) — Response Actions Do Not Scale With Severity")
    add_body(
        doc,
        "The most critical operational finding is that defensive response actions are completely decoupled from threat severity. "
        "Blocking remains flat across Low (34.0%), Medium (33.6%), and High (33.9%) severity events, while 33.3% of High-severity "
        "attacks are Ignored—virtually identical to Low-severity (33.4%). In a real SOC, leaving one-third of High-severity threats "
        "ignored would represent a major triage failure.",
    )
    add_figure(doc, EXPORT_DIR / "07_action_by_severity.png", "Figure 4: Response action share by severity—vivid crimson highlights Ignored attacks while low-saturation gray recedes Logged.", width_in=6.2)

    add_sub_heading(doc, "4.4 Finding 4 — Uniform Anomaly Score Distribution & ~50% Signal Triggers")
    add_body(
        doc,
        "Applying Week 7 distribution analysis, Figure 5 pairs a Histogram (bin width = 5) with a Kernel Density Estimate (KDE) curve, "
        "demonstrating that Anomaly Scores follow a flat Uniform distribution across 0–100 (mean = 50.11, 10,012 High-Anomaly events ≥75, "
        "zero outliers). Box plots confirm identical medians (~50) across every Attack Type × Severity group, and Figure 6 shows all five "
        "detection signals trigger at ~50% regardless of severity.",
    )
    add_figure(doc, EXPORT_DIR / "11_anomaly_histogram_kde.png", "Figure 5: Histogram (bin width = 5) and KDE curve confirming a Uniform distribution of Anomaly Scores (0–100).", width_in=6.1)
    add_figure(doc, EXPORT_DIR / "10_detection_flags_by_severity.png", "Figure 6: Trigger rates for all five detection signals remain ~50% across Low, Medium, and High severity.", width_in=6.1)

    add_sub_heading(doc, "4.5 Finding 5 — Even Geographic Spread Across 28 Indian States")
    add_body(
        doc,
        "Geo-location events span all 28 Indian states with no dominant geographic hotspot, ranging narrowly from 1,373 events "
        "(Madhya Pradesh) to 1,498 events (Manipur). Using a ranked horizontal bar chart in Neutral Slate keeps all 28 state labels "
        "legible without colliding with DDoS blue.",
    )
    add_figure(doc, EXPORT_DIR / "08_events_by_state.png", "Figure 7: Ranked horizontal bar chart of attack events across all 28 Indian states (Neutral Slate palette).", width_in=5.6)

    # ================================================================= 5. DASHBOARD
    add_section_heading(doc, "5. Interactive Dashboard & Reproducible Deliverables")
    add_body(
        doc,
        "To deliver an executive-ready analytical tool, all cleaned data and visualizations are unified inside a standalone interactive "
        "HTML dashboard (dashboard.html) alongside reproducible code and static publication exports:",
    )
    add_bullet(doc, "Interactive Dashboard (dashboard.html):", "Features a 4-card headline KPI row (Total Events, % Blocked, % High Severity, Mean Anomaly Score) and live filters for Attack Type, Severity Level, and Year that instantaneously recalculate all KPIs and 10 synchronized Plotly charts.")
    add_bullet(doc, "Reproducible Codebase:", "analysis.py and executed Jupyter Notebook analysis.ipynb (all 5 code cells verified with 0 errors) reproduce the cleaned CSV, 11 standalone interactive HTML charts (charts/), 11 high-DPI PNGs, and an 11-page PDF pack (exports/cybersecurity_attack_charts.pdf).")
    add_bullet(doc, "Team Presentation Deck:", "Cyber_Security_Attack_Analysis_Presentation.pptx (13 widescreen slides matching the CADT cover theme, ~18–20pt body text, embedded charts, and slide-by-slide speaker notes).")

    # ================================================================= 6. CONCLUSIONS
    add_section_heading(doc, "6. Conclusions, SOC Recommendations & Limitations")
    add_sub_heading(doc, "6.1 Actionable SOC Recommendations")
    add_bullet(doc, "Automate Blocking on High-Risk Threats:", "Configure automated firewall/IPS blocking rules for High-severity events and High-Anomaly scores (≥75) rather than relying on flat ~34% manual/random handling.")
    add_bullet(doc, "Audit Triage & Escalation Rules:", "Investigate why ~33% of High-severity alerts are Ignored and institute mandatory escalation workflows for unblocked critical events.")
    add_bullet(doc, "Calibrate Detection Signals:", "Correlate Firewall vs. Server log sources and tune anomaly scoring models so higher scores genuinely predict incident severity.")

    add_sub_heading(doc, "6.2 Limitations & Academic Integrity")
    add_body(
        doc,
        "Because every categorical split (~33% / ~50%) and the uniform anomaly distribution indicate that this Kaggle dataset is synthetic, "
        "the findings should not be interpreted as real-world Indian cybercrime statistics. Instead, this project demonstrates a rigorous, "
        "transparent, and accessible end-to-end Data Visualization workflow ready to be deployed directly on live enterprise SOC logs.",
    )

    # ================================================================= 7. TEAM ROLES
    add_section_heading(doc, "7. Team Roles & Responsibilities")
    add_styled_table(
        doc,
        ["Team Member", "Role & Key Contribution"],
        [
            ["Seat Sreylenn", "Data Cleaning Lead — pandas cleaning pipeline, flag recoding, OS/Browser parsing, validation checks"],
            ["Ly Yeakkhai", "Visualization Design — chart selection, Week 3–4 zero-collision colour palette, interactive dashboard layout"],
            ["Mak Khemara", "Dataset Research — Kaggle source profiling, variable documentation, synthetic-data & privacy review"],
            ["Sy Isean", "Report Writing — structured written report, key findings synthesis, and SOC recommendations"],
            ["Tho Vicheka", "Slide Deck & Accuracy — presentation slide structure, figure verification, and numerical cross-checking"],
            ["Chap Chanliya", "Presentation & QA — team delivery coordination, Week 7 accessibility audit, and consistency review"],
        ],
        col_widths=[1.65, 4.92],
    )

    # ================================================================= 8. REFERENCES
    add_section_heading(doc, "8. References")
    refs = [
        "Agur, A., & Venugopal, U. Cyber Security Attacks Dataset (cybersecurity_attacks.csv). Kaggle. https://www.kaggle.com/datasets/teamincribo/cyber-security-attacks",
        "Sam, S. (2026). Visualization Technique & Colour Theory (Week 3–4 Lecture Notes). Data Visualization, CADT — Institute of Digital Technology.",
        "Sam, S. (2026). Principles of Data Visualization and Distribution Analysis (Week 7 Lecture Notes). Data Visualization, CADT — Institute of Digital Technology.",
        "McKinney, W. pandas: Python Data Analysis Library. https://pandas.pydata.org",
        "Plotly Technologies Inc. Plotly Python Graphing Library. https://plotly.com/python/",
        "Hunter, J. D. Matplotlib: Visualization with Python. https://matplotlib.org",
    ]
    for ref in refs:
        add_bullet(doc, "", ref)

    doc.save(OUT_DOCX)
    print(f"Saved Final Report: {OUT_DOCX}")


if __name__ == "__main__":
    build_report()
