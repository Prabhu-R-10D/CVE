"""
CVE Vulnerability Report Generator
Creates a professional PDF report with executive summary, charts, and detailed findings
"""
import json
from pathlib import Path
from datetime import datetime
from collections import defaultdict

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch, mm
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, 
    PageBreak, Image, HRFlowable
)
from reportlab.graphics.shapes import Drawing, Rect, String
from reportlab.graphics.charts.piecharts import Pie
from reportlab.graphics.charts.barcharts import VerticalBarChart

BASE_DIR = Path(__file__).parent
REPORT_DIR = BASE_DIR / "reports"
ASSETS_DIR = BASE_DIR / "assets"
LOGO_PATH = ASSETS_DIR / "logo.png"

PRIMARY_COLOR = colors.HexColor("#1a365d")      
ACCENT_COLOR = colors.HexColor("#2b6cb0") 
DANGER_COLOR = colors.HexColor("#c53030") 
WARNING_COLOR = colors.HexColor("#dd6b20") 
SUCCESS_COLOR = colors.HexColor("#2f855a") 
LIGHT_BG = colors.HexColor("#f7fafc")


def format_analysis_value(val):
    """Helper to format LLM output (handles strings or dicts)"""
    if not val:
        return None
    
    val_str = str(val).lower().strip()
    if val_str == "analysis unavailable" or val_str == "llm analysis failed.":
        return None
    
    if isinstance(val, dict):
        items = []
        for k, v in val.items():
            k_clean = k.replace("_", " ").title()
            items.append(f"<b>{k_clean}:</b> {v}")
        return "<br/>".join(items)
    
    return str(val)


def load_report_data():
    """Load the latest CVE report"""
    reports = sorted(REPORT_DIR.glob("cve_applicability_report_*.json"))
    if not reports:
        raise FileNotFoundError(f"No reports found in {REPORT_DIR}")
    
    latest_report = reports[-1]
    with open(latest_report, 'r', encoding='utf-8') as f:
        return json.load(f), latest_report.name


def create_header_footer(canvas, doc):
    """Add header and footer to each page"""
    canvas.saveState()
    
    canvas.setStrokeColor(PRIMARY_COLOR)
    canvas.setLineWidth(2)
    canvas.line(30, A4[1] - 50, A4[0] - 30, A4[1] - 50)
    
    if LOGO_PATH.exists():
        canvas.drawImage(str(LOGO_PATH), 30, A4[1] - 45, width=15, height=15, preserveAspectRatio=True, mask='auto')
    
    canvas.setFont('Helvetica-Bold', 10)
    canvas.setFillColor(PRIMARY_COLOR)
    header_x = 50 if LOGO_PATH.exists() else 30
    canvas.drawString(header_x, A4[1] - 40, "CVE VULNERABILITY ASSESSMENT REPORT")
    canvas.drawRightString(A4[0] - 30, A4[1] - 40, datetime.now().strftime("%Y-%m-%d"))
    
    canvas.setFont('Helvetica', 8)
    canvas.setFillColor(colors.gray)
    canvas.drawString(30, 30, "CONFIDENTIAL - For Internal Use Only")
    canvas.drawRightString(A4[0] - 30, 30, f"Page {doc.page}")
    
    canvas.restoreState()


def create_cover_page(styles):
    """Create the cover page elements"""
    elements = []
    
    elements.append(Spacer(1, 1*inch))
    
    if LOGO_PATH.exists():
        logo = Image(str(LOGO_PATH), width=1.5*inch, height=1.5*inch)
        logo.hAlign = 'CENTER'
        elements.append(logo)
        elements.append(Spacer(1, 0.5*inch))
    else:
        elements.append(Spacer(1, 1*inch))
    
    title_style = ParagraphStyle(
        'CoverTitle',
        parent=styles['Heading1'],
        fontSize=36,
        textColor=PRIMARY_COLOR,
        alignment=1,
        spaceAfter=20
    )
    elements.append(Paragraph("CVE VULNERABILITY", title_style))
    elements.append(Paragraph("ASSESSMENT REPORT", title_style))
    
    elements.append(Spacer(1, 0.5*inch))
    
    subtitle_style = ParagraphStyle(
        'CoverSubtitle',
        parent=styles['Normal'],
        fontSize=14,
        textColor=ACCENT_COLOR,
        alignment=1,
        spaceAfter=40
    )
    elements.append(Paragraph("Security Vulnerability Analysis & Impact Assessment", subtitle_style))
    
    elements.append(HRFlowable(width="60%", thickness=3, color=ACCENT_COLOR, 
                               spaceBefore=20, spaceAfter=40))
    
    info_style = ParagraphStyle(
        'CoverInfo',
        parent=styles['Normal'],
        fontSize=12,
        textColor=colors.gray,
        alignment=1,
        spaceAfter=10
    )
    elements.append(Paragraph(f"Generated: {datetime.now().strftime('%B %d, %Y at %H:%M')}", info_style))
    
    source_name = getattr(styles, 'source_name', 'Dynamic Scan')
    elements.append(Paragraph(f"Report Source: {source_name}", info_style))
    
    elements.append(PageBreak())
    
    return elements


def create_executive_summary(data, styles):
    """Create executive summary section"""
    elements = []
    
    section_title = ParagraphStyle(
        'SectionTitle',
        parent=styles['Heading1'],
        fontSize=18,
        textColor=PRIMARY_COLOR,
        spaceBefore=20,
        spaceAfter=15,
        borderColor=PRIMARY_COLOR,
        borderWidth=0,
        borderPadding=5
    )
    elements.append(Paragraph("EXECUTIVE SUMMARY", section_title))
    elements.append(HRFlowable(width="100%", thickness=1, color=PRIMARY_COLOR, spaceAfter=20))
    
    total_vulns = len(data)
    components = defaultdict(list)
    for item in data:
        components[item['Component']].append(item)
    
    tier1_count = sum(1 for item in data if 'Tier' in str(item.get('Business Criticality', '')))
    internet_facing = sum(1 for item in data if item.get('Internet Facing', '').lower() == 'yes')
    
    stats_data = [
        ['METRIC', 'VALUE', 'STATUS'],
        ['Total Vulnerabilities', str(total_vulns), 'HIGH' if total_vulns > 10 else 'MEDIUM'],
        ['Affected Components', str(len(components)), '—'],
        ['Tier-1 Critical Systems', str(tier1_count), 'CRITICAL' if tier1_count > 0 else 'OK'],
        ['Internet-Facing Systems', str(internet_facing), 'HIGH' if internet_facing > 0 else 'LOW'],
    ]
    
    stats_table = Table(stats_data, colWidths=[3*inch, 1.5*inch, 1.5*inch])
    stats_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), PRIMARY_COLOR),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, 0), 11),
        ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
        ('FONTNAME', (0, 1), (-1, -1), 'Helvetica'),
        ('FONTSIZE', (0, 1), (-1, -1), 10),
        ('BACKGROUND', (0, 1), (-1, -1), LIGHT_BG),
        ('GRID', (0, 0), (-1, -1), 0.5, colors.gray),
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ('TOPPADDING', (0, 0), (-1, -1), 8),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
    ]))
    elements.append(stats_table)
    elements.append(Spacer(1, 30))
    
    findings_title = ParagraphStyle(
        'FindingsTitle',
        parent=styles['Heading2'],
        fontSize=14,
        textColor=ACCENT_COLOR,
        spaceBefore=15,
        spaceAfter=10
    )
    elements.append(Paragraph("Key Findings", findings_title))
    
    bullet_style = ParagraphStyle(
        'Bullet',
        parent=styles['Normal'],
        fontSize=10,
        leftIndent=20,
        spaceAfter=8,
        bulletIndent=10,
        bulletFontSize=10
    )
    
    for comp, vulns in components.items():
        elements.append(Paragraph(
            f"• <b>{comp}</b>: {len(vulns)} vulnerabilities detected",
            bullet_style
        ))
    
    elements.append(Spacer(1, 20))
    
    return elements


def create_vulnerability_breakdown(data, styles):
    """Create vulnerability breakdown by component"""
    elements = []
    
    elements.append(PageBreak())
    
    section_title = ParagraphStyle(
        'SectionTitle',
        parent=styles['Heading1'],
        fontSize=18,
        textColor=PRIMARY_COLOR,
        spaceBefore=10,
        spaceAfter=15
    )
    elements.append(Paragraph("VULNERABILITY BREAKDOWN BY COMPONENT", section_title))
    elements.append(HRFlowable(width="100%", thickness=1, color=PRIMARY_COLOR, spaceAfter=20))
    
    components = defaultdict(list)
    for item in data:
        components[item['Component']].append(item)
    
    for comp_name, vulns in components.items():
        comp_style = ParagraphStyle(
            'CompHeader',
            parent=styles['Heading2'],
            fontSize=13,
            textColor=ACCENT_COLOR,
            spaceBefore=20,
            spaceAfter=10,
            backColor=LIGHT_BG,
            borderPadding=8
        )
        elements.append(Paragraph(f"📦 {comp_name} ({len(vulns)} CVEs)", comp_style))
        
        first_vuln = vulns[0]
        details_style = ParagraphStyle(
            'Details',
            parent=styles['Normal'],
            fontSize=9,
            textColor=colors.gray,
            leftIndent=15,
            spaceAfter=5
        )
        elements.append(Paragraph(f"Application: {first_vuln.get('Application Name', 'N/A')}", details_style))
        elements.append(Paragraph(f"Installed Version: {first_vuln.get('Installed Version', 'N/A')}", details_style))
        elements.append(Paragraph(f"Environment: {first_vuln.get('Environment', 'N/A')} | Internet Facing: {first_vuln.get('Internet Facing', 'N/A')}", details_style))
        elements.append(Spacer(1, 10))
        
        cve_data = [['CVE ID', 'Published Date', 'State']]
        for v in vulns:
            pub_date = v.get('Published Date', '')[:10] if v.get('Published Date') else 'N/A'
            cve_data.append([
                v.get('CVE ID', 'N/A'),
                pub_date,
                v.get('CVE State', 'N/A')
            ])
        
        cve_table = Table(cve_data, colWidths=[1.5*inch, 1.5*inch, 2*inch])
        cve_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), ACCENT_COLOR),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 9),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 1), (-1, -1), 'Helvetica'),
            ('FONTSIZE', (0, 1), (-1, -1), 9),
            ('BACKGROUND', (0, 1), (-1, -1), colors.white),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.lightgrey),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
            ('TOPPADDING', (0, 0), (-1, -1), 6),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
            ('LEFTPADDING', (0, 0), (-1, -1), 8),
        ]))
        elements.append(cve_table)
        elements.append(Spacer(1, 15))

        # Expert Analysis Section
        analysis_shown = False
        for v in vulns:
            # Check if we have any valid analysis data
            issue_desc = format_analysis_value(v.get('Issue Description'))
            if not issue_desc:
                continue

            if not analysis_shown:
                analysis_shown = True

            analysis_header_style = ParagraphStyle(
                'AnalysisHeader',
                parent=styles['Normal'],
                fontSize=10,
                textColor=ACCENT_COLOR,
                fontName='Helvetica-Bold',
                spaceBefore=10,
                spaceAfter=15
            )
            elements.append(Paragraph(f"Analysis for {v['CVE ID']}:", analysis_header_style))
            
            analysis_body_style = ParagraphStyle(
                'AnalysisBody',
                parent=styles['Normal'],
                fontSize=10,
                leading=14,
                spaceBefore=0,
                spaceAfter=25,
                leftIndent=15,
                rightIndent=15,
                borderPadding=12,
                backColor=colors.Whiter(LIGHT_BG, 0.4),
                borderRadius=8,
                borderWidth=0
            )

            severity = str(v.get("Risk Severity", "Unknown")).title()
            severity_color = {
                "Critical": DANGER_COLOR,
                "High": DANGER_COLOR,
                "Medium": WARNING_COLOR,
                "Low": SUCCESS_COLOR
            }.get(severity, PRIMARY_COLOR)

            exposure = format_analysis_value(v.get('Exposure Classification')) or 'N/A'
            timeline = format_analysis_value(v.get('Required Timeline')) or 'N/A'
            impact = format_analysis_value(v.get('Impact')) or 'N/A'
            recommendation = format_analysis_value(v.get('Fix Recommendation')) or 'N/A'

            analysis_content = f"""
            <b>Issue Description:</b> {issue_desc}<br/>
            <b>Exposure:</b> {exposure} | 
            <b>Risk Severity:</b> <font color='{severity_color.hexval()}'><b>{severity}</b></font> | 
            <b>Timeline:</b> {timeline}<br/><br/>
            <b>Impact Analysis:</b><br/>{impact}<br/><br/>
            <b>Fix Recommendation:</b><br/>{recommendation}
            """
            elements.append(Paragraph(analysis_content, analysis_body_style))
            elements.append(Spacer(1, 5))
    
    return elements


def create_recommendations(styles):
    """Create recommendations section"""
    elements = []
    
    elements.append(PageBreak())
    
    section_title = ParagraphStyle(
        'SectionTitle',
        parent=styles['Heading1'],
        fontSize=18,
        textColor=PRIMARY_COLOR,
        spaceBefore=20,
        spaceAfter=15
    )
    elements.append(Paragraph("RECOMMENDATIONS", section_title))
    elements.append(HRFlowable(width="100%", thickness=1, color=PRIMARY_COLOR, spaceAfter=20))
    
    rec_style = ParagraphStyle(
        'Recommendation',
        parent=styles['Normal'],
        fontSize=10,
        spaceAfter=15,
        leftIndent=15
    )
    
    recommendations = [
        ("<b>1. Immediate Action Required</b>: Review all Tier-1 critical systems with identified vulnerabilities and prioritize patching based on exploitability.",
         DANGER_COLOR),
        ("<b>2. Patch Management</b>: Update affected components to their latest stable versions. Test patches in staging environment before production deployment.",
         WARNING_COLOR),
        ("<b>3. Internet-Facing Systems</b>: Apply additional security controls (WAF, rate limiting, monitoring) to internet-facing systems with known vulnerabilities.",
         WARNING_COLOR),
        ("<b>4. Continuous Monitoring</b>: Enable automated vulnerability scanning and integrate with CI/CD pipelines for early detection.",
         ACCENT_COLOR),
        ("<b>5. Vendor Communication</b>: Contact vendors for components where patches are not yet available to understand mitigation timelines.",
         ACCENT_COLOR),
    ]
    
    for rec_text, color in recommendations:
        rec_para_style = ParagraphStyle(
            'RecPara',
            parent=rec_style,
            borderColor=color,
            borderWidth=2,
            borderPadding=10,
            backColor=LIGHT_BG
        )
        elements.append(Paragraph(rec_text, rec_para_style))
    
    return elements


def generate_pdf_report(data=None, output_path=None):
    """Main function to generate the PDF report"""
    source_name = "Dynamic Scan"
    if data is None:
        data, source_name = load_report_data()
        print(f"Loading data from: {source_name}")
    
    print(f"Found {len(data)} vulnerabilities")
    
    if output_path is None:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_path = REPORT_DIR / f"CVE_Vulnerability_Report_{timestamp}.pdf"
    
    output_path = Path(output_path)
    
    doc = SimpleDocTemplate(
        str(output_path),
        pagesize=A4,
        rightMargin=30,
        leftMargin=30,
        topMargin=60,
        bottomMargin=50
    )
    
    styles = getSampleStyleSheet()
    styles.source_name = source_name
    
    elements = []
    
    elements.extend(create_cover_page(styles))
    
    elements.extend(create_executive_summary(data, styles))
    
    elements.extend(create_vulnerability_breakdown(data, styles))
    
    elements.extend(create_recommendations(styles))
    
    doc.build(elements, onFirstPage=create_header_footer, onLaterPages=create_header_footer)
    
    print(f"\n✅ PDF report generated: {output_path}")
    return output_path


if __name__ == "__main__":
    generate_pdf_report()
