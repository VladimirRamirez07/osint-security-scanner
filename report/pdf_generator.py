from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import cm
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table,
    TableStyle, HRFlowable, KeepTogether
)
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT
from datetime import datetime
import os

# ── Paleta de colores ──────────────────────────────────────────
DARK_BG      = colors.HexColor("#0D1117")
ACCENT_BLUE  = colors.HexColor("#58A6FF")
ACCENT_GREEN = colors.HexColor("#3FB950")
ACCENT_RED   = colors.HexColor("#F85149")
ACCENT_YELLOW= colors.HexColor("#D29922")
LIGHT_GRAY   = colors.HexColor("#C9D1D9")
MID_GRAY     = colors.HexColor("#21262D")
BORDER_GRAY  = colors.HexColor("#30363D")
WHITE        = colors.white

def get_score_color(score: int):
    if score >= 75:
        return ACCENT_GREEN
    elif score >= 45:
        return ACCENT_YELLOW
    else:
        return ACCENT_RED

def get_score_label(score: int) -> str:
    if score >= 75:
        return "BUENO"
    elif score >= 45:
        return "REGULAR"
    else:
        return "CRITICO"

def build_styles():
    styles = getSampleStyleSheet()

    custom = {
        "Title": ParagraphStyle("Title", fontSize=26, textColor=WHITE,
                                 fontName="Helvetica-Bold", alignment=TA_CENTER,
                                 spaceAfter=4),
        "Subtitle": ParagraphStyle("Subtitle", fontSize=11, textColor=LIGHT_GRAY,
                                    fontName="Helvetica", alignment=TA_CENTER,
                                    spaceAfter=2),
        "SectionTitle": ParagraphStyle("SectionTitle", fontSize=14,
                                        textColor=ACCENT_BLUE, fontName="Helvetica-Bold",
                                        spaceBefore=16, spaceAfter=8),
        "Body": ParagraphStyle("Body", fontSize=9, textColor=LIGHT_GRAY,
                                fontName="Helvetica", spaceAfter=4, leading=14),
        "Code": ParagraphStyle("Code", fontSize=7.5, textColor=ACCENT_GREEN,
                                fontName="Courier", spaceAfter=4,
                                backColor=MID_GRAY, leading=12),
        "Badge_Good": ParagraphStyle("Badge_Good", fontSize=9, textColor=ACCENT_GREEN,
                                      fontName="Helvetica-Bold", alignment=TA_CENTER),
        "Badge_Bad": ParagraphStyle("Badge_Bad", fontSize=9, textColor=ACCENT_RED,
                                     fontName="Helvetica-Bold", alignment=TA_CENTER),
        "Badge_Warn": ParagraphStyle("Badge_Warn", fontSize=9, textColor=ACCENT_YELLOW,
                                      fontName="Helvetica-Bold", alignment=TA_CENTER),
        "Small": ParagraphStyle("Small", fontSize=8, textColor=LIGHT_GRAY,
                                  fontName="Helvetica"),
    }
    return custom

# ── Sección: Header del reporte ────────────────────────────────
def build_header(domain: str, overall_score: int, styles: dict) -> list:
    elements = []
    now = datetime.now().strftime("%Y-%m-%d %H:%M UTC")

    elements.append(Spacer(1, 0.3*cm))
    elements.append(Paragraph("🔍 OSINT Security Scanner", styles["Title"]))
    elements.append(Paragraph(f"Security Compliance Report — {domain}", styles["Subtitle"]))
    elements.append(Paragraph(f"Generated: {now}", styles["Small"]))
    elements.append(Spacer(1, 0.4*cm))
    elements.append(HRFlowable(width="100%", thickness=1, color=ACCENT_BLUE))
    elements.append(Spacer(1, 0.4*cm))

    score_color = get_score_color(overall_score)
    score_label = get_score_label(overall_score)

    score_data = [[
        Paragraph(f"<font color='#{score_color.hexval()[2:]}' size='36'><b>{overall_score}</b></font>", styles["Body"]),
        Paragraph(f"<b>Overall Score</b><br/><font color='#{score_color.hexval()[2:]}'>{score_label}</font>", styles["Body"]),
    ]]
    score_table = Table(score_data, colWidths=[3*cm, 10*cm])
    score_table.setStyle(TableStyle([
        ("BACKGROUND", (0,0), (-1,-1), MID_GRAY),
        ("ROUNDEDCORNERS", [6]),
        ("BOX", (0,0), (-1,-1), 1, BORDER_GRAY),
        ("VALIGN", (0,0), (-1,-1), "MIDDLE"),
        ("LEFTPADDING", (0,0), (-1,-1), 14),
        ("TOPPADDING", (0,0), (-1,-1), 10),
        ("BOTTOMPADDING", (0,0), (-1,-1), 10),
    ]))
    elements.append(score_table)
    elements.append(Spacer(1, 0.5*cm))
    return elements

# ── Sección: DNS ───────────────────────────────────────────────
def build_dns_section(dns_result, styles: dict) -> list:
    elements = []
    elements.append(Paragraph("📧 Email Security — DNS Records", styles["SectionTitle"]))

    rows = [
        [
            Paragraph("<b>Record</b>", styles["Body"]),
            Paragraph("<b>Status</b>", styles["Body"]),
            Paragraph("<b>Value</b>", styles["Body"]),
        ]
    ]

    def status_cell(valid, found):
        if not found:
            return Paragraph("✗ MISSING", styles["Badge_Bad"])
        return Paragraph("✓ VALID" if valid else "⚠ WEAK", 
                         styles["Badge_Good"] if valid else styles["Badge_Warn"])

    records = [
        ("SPF", dns_result.spf, dns_result.spf_valid),
        ("DKIM", dns_result.dkim, dns_result.dkim_valid),
        ("DMARC", dns_result.dmarc, dns_result.dmarc_valid),
    ]

    for name, value, valid in records:
        display_val = value[:80] + "..." if value and len(value) > 80 else (value or "Not found")
        rows.append([
            Paragraph(f"<b>{name}</b>", styles["Body"]),
            status_cell(valid, bool(value)),
            Paragraph(f"<font size='7'>{display_val}</font>", styles["Code"]),
        ])

    # Fila de política DMARC
    rows.append([
        Paragraph("<b>DMARC Policy</b>", styles["Body"]),
        Paragraph(
            f"{'✓' if dns_result.dmarc_policy == 'reject' else '⚠'} {dns_result.dmarc_policy.upper()}",
            styles["Badge_Good"] if dns_result.dmarc_policy == "reject" else styles["Badge_Warn"]
        ),
        Paragraph("reject = máxima protección anti-phishing", styles["Small"]),
    ])

    t = Table(rows, colWidths=[3.5*cm, 3*cm, 11*cm])
    t.setStyle(TableStyle([
        ("BACKGROUND", (0,0), (-1,0), ACCENT_BLUE),
        ("TEXTCOLOR", (0,0), (-1,0), WHITE),
        ("BACKGROUND", (0,1), (-1,-1), MID_GRAY),
        ("ROWBACKGROUNDS", (0,1), (-1,-1), [MID_GRAY, DARK_BG]),
        ("BOX", (0,0), (-1,-1), 1, BORDER_GRAY),
        ("INNERGRID", (0,0), (-1,-1), 0.5, BORDER_GRAY),
        ("VALIGN", (0,0), (-1,-1), "MIDDLE"),
        ("TOPPADDING", (0,0), (-1,-1), 7),
        ("BOTTOMPADDING", (0,0), (-1,-1), 7),
        ("LEFTPADDING", (0,0), (-1,-1), 8),
    ]))
    elements.append(t)

    score_color = get_score_color(dns_result.score)
    elements.append(Spacer(1, 0.2*cm))
    elements.append(Paragraph(
        f"DNS Score: <font color='#{score_color.hexval()[2:]}'><b>{dns_result.score}/100</b></font>",
        styles["Body"]
    ))
    return elements

# ── Sección: HTTP Headers ──────────────────────────────────────
def build_http_section(http_result, styles: dict) -> list:
    elements = []
    elements.append(Paragraph("🌐 HTTP Security Headers", styles["SectionTitle"]))

    if http_result.error:
        elements.append(Paragraph(f"⚠ Error al conectar: {http_result.error}", styles["Badge_Warn"]))
        return elements

    rows = [[
        Paragraph("<b>Header</b>", styles["Body"]),
        Paragraph("<b>Status</b>", styles["Body"]),
        Paragraph("<b>Description</b>", styles["Body"]),
    ]]

    all_headers = http_result.headers_found + http_result.headers_missing
    for h in all_headers:
        status = Paragraph("✓ PRESENT", styles["Badge_Good"]) if h.present \
                 else Paragraph("✗ MISSING", styles["Badge_Bad"])
        rows.append([
            Paragraph(f"<b><font size='8'>{h.name}</font></b>", styles["Body"]),
            status,
            Paragraph(f"<font size='8'>{h.description}</font>", styles["Small"]),
        ])

    t = Table(rows, colWidths=[6*cm, 3*cm, 8.5*cm])
    t.setStyle(TableStyle([
        ("BACKGROUND", (0,0), (-1,0), ACCENT_BLUE),
        ("TEXTCOLOR", (0,0), (-1,0), WHITE),
        ("ROWBACKGROUNDS", (0,1), (-1,-1), [MID_GRAY, DARK_BG]),
        ("BOX", (0,0), (-1,-1), 1, BORDER_GRAY),
        ("INNERGRID", (0,0), (-1,-1), 0.5, BORDER_GRAY),
        ("VALIGN", (0,0), (-1,-1), "MIDDLE"),
        ("TOPPADDING", (0,0), (-1,-1), 7),
        ("BOTTOMPADDING", (0,0), (-1,-1), 7),
        ("LEFTPADDING", (0,0), (-1,-1), 8),
    ]))
    elements.append(t)

    score_color = get_score_color(http_result.score)
    elements.append(Spacer(1, 0.2*cm))
    elements.append(Paragraph(
        f"HTTP Score: <font color='#{score_color.hexval()[2:]}'><b>{http_result.score}/100</b></font> "
        f"| HTTPS: {'✓ Enabled' if http_result.https_enabled else '✗ Disabled'} "
        f"| Server: {http_result.server_info or 'Unknown'}",
        styles["Body"]
    ))
    return elements

# ── Sección: Subdominios ───────────────────────────────────────
def build_subdomain_section(sub_result, styles: dict) -> list:
    elements = []
    elements.append(Paragraph("🔎 Subdomain Enumeration & Takeover Risk", styles["SectionTitle"]))

    summary = (
        f"Subdominios verificados: <b>{sub_result.total_checked}</b> | "
        f"Encontrados: <b>{len(sub_result.found)}</b> | "
        f"Vulnerables (Takeover): <b>{len(sub_result.vulnerable)}</b>"
    )
    elements.append(Paragraph(summary, styles["Body"]))
    elements.append(Spacer(1, 0.3*cm))

    if not sub_result.found:
        elements.append(Paragraph("No se encontraron subdominios activos.", styles["Small"]))
        return elements

    rows = [[
        Paragraph("<b>Subdomain</b>", styles["Body"]),
        Paragraph("<b>IP</b>", styles["Body"]),
        Paragraph("<b>HTTP</b>", styles["Body"]),
        Paragraph("<b>Takeover Risk</b>", styles["Body"]),
    ]]

    for s in sub_result.found:
        risk = Paragraph("🔴 VULNERABLE", styles["Badge_Bad"]) if s.takeover_risk \
               else Paragraph("✓ Safe", styles["Badge_Good"])
        rows.append([
            Paragraph(f"<font size='8'>{s.full_domain}</font>", styles["Body"]),
            Paragraph(f"<font size='8'>{s.ip or 'N/A'}</font>", styles["Small"]),
            Paragraph(f"<font size='8'>{s.http_status or 'N/A'}</font>", styles["Small"]),
            risk,
        ])

    t = Table(rows, colWidths=[7*cm, 3*cm, 2*cm, 5.5*cm])
    t.setStyle(TableStyle([
        ("BACKGROUND", (0,0), (-1,0), ACCENT_BLUE),
        ("TEXTCOLOR", (0,0), (-1,0), WHITE),
        ("ROWBACKGROUNDS", (0,1), (-1,-1), [MID_GRAY, DARK_BG]),
        ("BOX", (0,0), (-1,-1), 1, BORDER_GRAY),
        ("INNERGRID", (0,0), (-1,-1), 0.5, BORDER_GRAY),
        ("VALIGN", (0,0), (-1,-1), "MIDDLE"),
        ("TOPPADDING", (0,0), (-1,-1), 6),
        ("BOTTOMPADDING", (0,0), (-1,-1), 6),
        ("LEFTPADDING", (0,0), (-1,-1), 8),
    ]))
    elements.append(t)

    score_color = get_score_color(sub_result.score)
    elements.append(Spacer(1, 0.2*cm))
    elements.append(Paragraph(
        f"Subdomain Score: <font color='#{score_color.hexval()[2:]}'><b>{sub_result.score}/100</b></font>",
        styles["Body"]
    ))
    return elements

# ── Función principal ──────────────────────────────────────────
def generate_pdf(domain: str, dns_result, http_result, sub_result,
                 output_dir: str = "sample_reports") -> str:

    os.makedirs(output_dir, exist_ok=True)
    filename = f"{output_dir}/{domain.replace('.', '_')}_security_report.pdf"

    overall_score = round((dns_result.score + http_result.score + sub_result.score) / 3)

    doc = SimpleDocTemplate(
        filename,
        pagesize=A4,
        leftMargin=1.8*cm, rightMargin=1.8*cm,
        topMargin=1.5*cm, bottomMargin=1.5*cm,
        title=f"Security Report - {domain}",
    )

    styles = build_styles()
    elements = []

    elements += build_header(domain, overall_score, styles)
    elements += build_dns_section(dns_result, styles)
    elements.append(Spacer(1, 0.5*cm))
    elements += build_http_section(http_result, styles)
    elements.append(Spacer(1, 0.5*cm))
    elements += build_subdomain_section(sub_result, styles)

    # Footer
    elements.append(Spacer(1, 0.8*cm))
    elements.append(HRFlowable(width="100%", thickness=1, color=BORDER_GRAY))
    elements.append(Spacer(1, 0.2*cm))
    elements.append(Paragraph(
        "Generated by OSINT Security Scanner | github.com/VladimirRamirez07/osint-security-scanner | "
        "100% legal — public DNS & HTTP data only",
        ParagraphStyle("Footer", fontSize=7, textColor=BORDER_GRAY,
                       fontName="Helvetica", alignment=TA_CENTER)
    ))

    doc.build(elements)
    print(f"  [PDF] Reporte generado: {filename}")
    return filename