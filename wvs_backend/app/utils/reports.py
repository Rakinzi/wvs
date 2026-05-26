import io
import os
from datetime import datetime, timezone, timedelta
from xml.sax.saxutils import escape

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.platypus import (
    BaseDocTemplate, Frame, HRFlowable, PageTemplate,
    Paragraph, Spacer, Table, TableStyle, Image,
)
from reportlab.lib.colors import HexColor

from app.utils.scan_helpers import build_best_practices, build_scan_summary

# ── Palette ──────────────────────────────────────────────────────────────────
BG        = HexColor('#020617')
SURFACE   = HexColor('#0F172A')
CARD      = HexColor('#0E1223')
ELEVATED  = HexColor('#1B2336')
BORDER    = HexColor('#334155')
TEXT      = HexColor('#F8FAFC')
MUTED     = HexColor('#94A3B8')
DIM       = HexColor('#64748B')
PRIMARY   = HexColor('#3B82F6')
SECURE    = HexColor('#22C55E')
WARN      = HexColor('#F59E0B')
DANGER    = HexColor('#EF4444')
INFO      = HexColor('#38BDF8')
PURPLE    = HexColor('#A78BFA')
WHITE     = colors.white

PAGE_W, PAGE_H = letter
MARGIN = 0.55 * inch


# ── Styles ────────────────────────────────────────────────────────────────────
def _styles():
    def s(name, font='Helvetica', color=TEXT, **kw):
        return ParagraphStyle(name, fontName=font, textColor=color, **kw)

    return {
        'h1':     s('h1',    font='Helvetica-Bold', fontSize=20, leading=26),
        'h2':     s('h2',    font='Helvetica-Bold', fontSize=13, leading=18, spaceBefore=10),
        'h3':     s('h3',    font='Helvetica-Bold', fontSize=10, leading=14),
        'body':   s('body',  color=MUTED,  fontSize=9,  leading=13),
        'body_w': s('body_w',              fontSize=9,  leading=13),
        'small':  s('small', color=DIM,   fontSize=8,  leading=11),
        'label':  s('label', font='Helvetica-Bold', color=MUTED, fontSize=8, leading=11),
        'mono':   s('mono',  font='Courier',        color=INFO,  fontSize=8, leading=11),
        'secure': s('secure',font='Helvetica-Bold', color=SECURE,fontSize=9, leading=13),
        'danger': s('danger',font='Helvetica-Bold', color=DANGER,fontSize=9, leading=13),
        'warn':   s('warn',  font='Helvetica-Bold', color=WARN,  fontSize=9, leading=13),
        'center': s('center',color=MUTED, fontSize=9, leading=13, alignment=TA_CENTER),
        'footer': s('footer',color=DIM,   fontSize=7, leading=10, alignment=TA_CENTER),
    }


# ── Page canvas decorations ───────────────────────────────────────────────────
def _draw_page(canvas, doc):
    canvas.saveState()
    w, h = letter

    # Background
    canvas.setFillColor(BG)
    canvas.rect(0, 0, w, h, fill=1, stroke=0)

    # Top accent bar
    canvas.setFillColor(PRIMARY)
    canvas.rect(0, h - 4, w, 4, fill=1, stroke=0)

    # Header band
    canvas.setFillColor(SURFACE)
    canvas.rect(0, h - 52, w, 48, fill=1, stroke=0)

    # Header text
    canvas.setFillColor(TEXT)
    canvas.setFont('Helvetica-Bold', 11)
    canvas.drawString(MARGIN, h - 32, 'WebVulnScanner')
    canvas.setFillColor(MUTED)
    canvas.setFont('Helvetica', 8)
    canvas.drawString(MARGIN, h - 44, 'Security Assessment Report')

    # Page number (right)
    canvas.setFillColor(DIM)
    canvas.setFont('Helvetica', 8)
    page_str = f'Page {doc.page}'
    canvas.drawRightString(w - MARGIN, h - 38, page_str)

    # Header bottom border
    canvas.setStrokeColor(BORDER)
    canvas.setLineWidth(0.5)
    canvas.line(MARGIN, h - 53, w - MARGIN, h - 53)

    # Footer
    canvas.setFillColor(ELEVATED)
    canvas.rect(0, 0, w, 36, fill=1, stroke=0)
    canvas.setStrokeColor(BORDER)
    canvas.line(MARGIN, 36, w - MARGIN, 36)
    canvas.setFillColor(DIM)
    canvas.setFont('Helvetica-Oblique', 7)
    canvas.drawCentredString(w / 2, 22, 'This report was automatically generated. Review with qualified security professionals.')
    canvas.drawCentredString(w / 2, 13, 'False positives may occur. Manual testing is recommended for critical systems.')

    canvas.restoreState()


# ── Helper flowables ──────────────────────────────────────────────────────────
def _divider(color=BORDER, thickness=0.5):
    return HRFlowable(width='100%', thickness=thickness, color=color, spaceAfter=6, spaceBefore=6)


def _section_header(title, sub, icon_char, icon_color, ST):
    icon_cell = Paragraph(f'<font color="#{icon_color.hexval()[2:]}">{icon_char}</font>',
                          ParagraphStyle('ic', fontName='Helvetica-Bold', fontSize=14,
                                         textColor=icon_color, alignment=TA_CENTER))
    title_cell = Paragraph(title, ST['h3'])
    sub_cell   = Paragraph(sub,   ST['small'])
    t = Table(
        [[icon_cell, [title_cell, sub_cell]]],
        colWidths=[24, PAGE_W - 2 * MARGIN - 24],
    )
    t.setStyle(TableStyle([
        ('VALIGN',      (0,0), (-1,-1), 'MIDDLE'),
        ('LEFTPADDING', (0,0), (-1,-1), 0),
        ('RIGHTPADDING',(0,0), (-1,-1), 0),
        ('TOPPADDING',  (0,0), (-1,-1), 8),
        ('BOTTOMPADDING',(0,0),(-1,-1), 8),
        ('BACKGROUND',  (0,0), (-1,-1), SURFACE),
        ('ROUNDEDCORNERS', [4]),
    ]))
    return t


def _finding_row(label, value, ST, label_w=100):
    return Table(
        [[Paragraph(label, ST['label']), Paragraph(str(value), ST['body_w'])]],
        colWidths=[label_w, PAGE_W - 2 * MARGIN - label_w],
    )


def _badge(text, bg_hex, fg_hex):
    style = ParagraphStyle(
        'badge', fontName='Helvetica-Bold', fontSize=8, leading=10,
        textColor=HexColor(fg_hex), alignment=TA_CENTER,
    )
    t = Table([[Paragraph(text, style)]], colWidths=[70])
    t.setStyle(TableStyle([
        ('BACKGROUND',    (0,0), (0,0), HexColor(bg_hex)),
        ('ROUNDEDCORNERS', [4]),
        ('TOPPADDING',    (0,0), (0,0), 3),
        ('BOTTOMPADDING', (0,0), (0,0), 3),
    ]))
    return t


def _safe_text(value, limit=None):
    text = "" if value is None else str(value)
    if limit is not None:
        text = text[:limit]
    return escape(text)


def _strip_html(text: str) -> str:
    """Remove HTML tags and collapse whitespace for clean PDF display."""
    import re
    text = re.sub(r'<[^>]+>', ' ', text)
    text = re.sub(r'&[a-z]+;', ' ', text)
    text = re.sub(r'\s+', ' ', text)
    return text.strip()


def _findings_block(items, color, ST):
    """Render a list of findings as a styled table block."""
    rows = []
    screenshots = []
    for item in items:
        name  = item.get('name') or item.get('type', 'Finding')
        sev   = item.get('severity') or item.get('risk', 'Info')
        evid  = item.get('evidence') or item.get('payload') or item.get('parameter', '')
        confidence = str(item.get('confidence') or '').replace('_', ' ').title()
        sev_colors = {
            'Critical': ('#4B0000', '#FF4444'),
            'High':     ('#3D2000', '#F59E0B'),
            'Medium':   ('#2D2000', '#F59E0B'),
            'Low':      ('#0D2D1A', '#22C55E'),
            'Info':     ('#0C2340', '#38BDF8'),
        }
        bg, fg = sev_colors.get(sev, ('#1B2336', '#94A3B8'))
        badge = _badge(sev, bg, fg)
        row_data = [[
            Paragraph(_safe_text(name), ParagraphStyle('fn', fontName='Helvetica-Bold', fontSize=9,
                                                       leading=12, textColor=color)),
            badge,
        ]]
        rows.append(row_data[0])
        if evid:
            rows.append([
                Paragraph(_safe_text(evid, 120), ParagraphStyle('ev', fontName='Helvetica', fontSize=8,
                                                                leading=11, textColor=MUTED)),
                '',
            ])
        if confidence:
            rows.append([
                Paragraph(f'Confidence: {_safe_text(confidence)}', ParagraphStyle('cv', fontName='Helvetica-Oblique', fontSize=8,
                                                                                  leading=10, textColor=DIM)),
                '',
            ])
        screenshot_path = item.get('screenshot_path')
        if isinstance(screenshot_path, str) and screenshot_path and os.path.exists(screenshot_path):
            screenshots.append((name, screenshot_path))

    if not rows:
        return []

    t = Table(rows, colWidths=[PAGE_W - 2 * MARGIN - 80, 80])
    ts = [
        ('BACKGROUND',    (0,0), (-1,-1), CARD),
        ('ROWBACKGROUNDS', (0,0), (-1,-1), [CARD, ELEVATED]),
        ('LINEBELOW',     (0,0), (-1,-2), 0.3, BORDER),
        ('TOPPADDING',    (0,0), (-1,-1), 5),
        ('BOTTOMPADDING', (0,0), (-1,-1), 5),
        ('LEFTPADDING',   (0,0), (-1,-1), 10),
        ('RIGHTPADDING',  (0,0), (-1,-1), 6),
        ('VALIGN',        (0,0), (-1,-1), 'TOP'),
    ]
    t.setStyle(TableStyle(ts))
    blocks = [t]
    for index, (name, screenshot_path) in enumerate(screenshots[:2], start=1):
        blocks.append(Spacer(1, 6))
        blocks.append(Paragraph(f'Evidence Screenshot {index}: {_safe_text(name, 70)}', ST['small']))
        blocks.append(Spacer(1, 4))
        blocks.append(Image(screenshot_path, width=4.8 * inch, height=2.7 * inch, kind='proportional'))
    return blocks


def _recs_block(items, ST):
    if not items:
        return []
    rows = [[Paragraph(f'• {_safe_text(r)}', ST['body'])] for r in items]
    t = Table(rows, colWidths=[PAGE_W - 2 * MARGIN])
    t.setStyle(TableStyle([
        ('BACKGROUND',    (0,0), (-1,-1), HexColor('#0C2340')),
        ('LINEABOVE',     (0,0), (0,0),   1.5, INFO),
        ('TOPPADDING',    (0,0), (-1,-1), 4),
        ('BOTTOMPADDING', (0,0), (-1,-1), 4),
        ('LEFTPADDING',   (0,0), (-1,-1), 10),
    ]))
    return [Spacer(1, 4), t]


def _obfuscate_email(email):
    return str(email).replace('@', ' [at] ')


def _score_bar(score, score_color, ST):
    bar_w = PAGE_W - 2 * MARGIN - 160
    filled_w = bar_w * score / 100

    score_label = Paragraph(f'<font color="#{score_color.hexval()[2:]}">{score}/100</font>',
                             ParagraphStyle('sc', fontName='Helvetica-Bold', fontSize=18,
                                            leading=22, textColor=score_color))

    # Draw bar via nested table
    bar_bg = Table([['']],  colWidths=[bar_w],   rowHeights=[8])
    bar_bg.setStyle(TableStyle([('BACKGROUND', (0,0), (0,0), BORDER), ('ROUNDEDCORNERS', [4])]))

    bar_fill = Table([['']],  colWidths=[max(filled_w, 2)], rowHeights=[8])
    bar_fill.setStyle(TableStyle([('BACKGROUND', (0,0), (0,0), score_color), ('ROUNDEDCORNERS', [4])]))

    label = Paragraph('Security Score', ST['label'])

    outer = Table(
        [[score_label, [label, bar_bg, bar_fill]]],
        colWidths=[80, bar_w + 80],
    )
    outer.setStyle(TableStyle([
        ('VALIGN',        (0,0), (-1,-1), 'MIDDLE'),
        ('LEFTPADDING',   (0,0), (-1,-1), 0),
        ('RIGHTPADDING',  (0,0), (-1,-1), 0),
        ('TOPPADDING',    (0,0), (-1,-1), 0),
        ('BOTTOMPADDING', (0,0), (-1,-1), 0),
    ]))
    return outer


# ── Main generator ────────────────────────────────────────────────────────────
def generate_report(results):
    buffer = io.BytesIO()
    ST = _styles()

    doc = BaseDocTemplate(
        buffer,
        pagesize=letter,
        leftMargin=MARGIN,
        rightMargin=MARGIN,
        topMargin=0.85 * inch,
        bottomMargin=0.7 * inch,
        title=f"Security Report — {results.get('url', '')}",
    )
    frame = Frame(MARGIN, 0.7 * inch, PAGE_W - 2 * MARGIN, PAGE_H - 1.55 * inch, id='main')
    doc.addPageTemplates([PageTemplate(id='main', frames=[frame], onPage=_draw_page)])

    story = []
    sp = lambda h=6: Spacer(1, h)

    summary   = results.get('summary') or build_scan_summary(results)
    url       = results.get('url', '—')
    scan_id   = results.get('scan_id', '—')
    timestamp  = results.get('timestamp')
    tz_offset  = results.get('tz_offset', 0)  # browser's getTimezoneOffset() — minutes behind UTC
    user_tz    = timezone(timedelta(minutes=-tz_offset))

    if timestamp:
        dt = datetime.fromisoformat(str(timestamp))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        dt_local = dt.astimezone(user_tz)
    else:
        dt_local = datetime.now(user_tz)

    tz_label = 'UTC' if tz_offset == 0 else f'UTC{"−" if tz_offset > 0 else "+"}{abs(tz_offset)//60:02d}:{abs(tz_offset)%60:02d}'
    ts_str   = dt_local.strftime(f'%Y-%m-%d %H:%M {tz_label}')

    sql_count      = summary.get('sqli_count', 0)
    ssl_issue      = summary.get('ssl_issue', False)
    is_mal         = summary.get('malicious', False)
    hdr_count      = summary.get('header_issue_count', 0)
    wp_count       = summary.get('wordpress_issue_count', 0)
    zap_count      = summary.get('zap_issue_count', 0)
    xss_count      = summary.get('xss_count', 0)
    tech_count     = summary.get('tech_issue_count', 0)
    advisory_count = summary.get('advisory_count', 0)
    exposure_count = summary.get('exposure_count', 0)
    total          = summary.get('total_issues', 0)

    risk  = ('Critical' if (total > 5 or is_mal) else
             'High'     if total > 3 else
             'Medium'   if total > 0 else 'Low')
    score = max(0, 100 - total * 15)

    risk_map = {
        'Critical': (HexColor('#4B0000'), DANGER),
        'High':     (HexColor('#3D2000'), WARN),
        'Medium':   (HexColor('#2D2000'), WARN),
        'Low':      (HexColor('#0D2D1A'), SECURE),
    }
    risk_bg, risk_fg = risk_map[risk]
    score_color = DANGER if score < 50 else WARN if score < 80 else SECURE

    # ── Hero ──────────────────────────────────────────────────────────────────
    story.append(sp(4))
    story.append(Paragraph('Security Assessment Report', ST['h1']))
    story.append(sp(4))
    story.append(_divider(PRIMARY, 1.5))
    story.append(sp(6))

    # Meta table
    meta_data = [
        [Paragraph('TARGET URL', ST['label']),
         Paragraph(url, ST['mono'])],
        [Paragraph('SCAN ID', ST['label']),
         Paragraph(str(scan_id), ST['mono'])],
        [Paragraph('GENERATED', ST['label']),
         Paragraph(ts_str, ST['body_w'])],
    ]
    meta_t = Table(meta_data, colWidths=[90, PAGE_W - 2 * MARGIN - 90])
    meta_t.setStyle(TableStyle([
        ('BACKGROUND',    (0,0), (-1,-1), SURFACE),
        ('TOPPADDING',    (0,0), (-1,-1), 5),
        ('BOTTOMPADDING', (0,0), (-1,-1), 5),
        ('LEFTPADDING',   (0,0), (-1,-1), 10),
        ('LINEBELOW',     (0,0), (-1,-2), 0.3, BORDER),
    ]))
    story.append(meta_t)
    story.append(sp(10))

    # Score + risk badges side by side
    score_bar = _score_bar(score, score_color, ST)
    risk_badge = _badge(f'{risk} Risk', risk_bg.hexval(), risk_fg.hexval())
    summary_row = Table(
        [[score_bar, risk_badge]],
        colWidths=[PAGE_W - 2 * MARGIN - 90, 90],
    )
    summary_row.setStyle(TableStyle([
        ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
        ('LEFTPADDING', (0,0), (-1,-1), 0),
        ('RIGHTPADDING',(0,0), (-1,-1), 0),
    ]))
    story.append(summary_row)
    story.append(sp(12))
    story.append(_divider())

    # ── Executive Summary ─────────────────────────────────────────────────────
    story.append(sp(4))
    story.append(Paragraph('Executive Summary', ST['h2']))
    story.append(sp(4))

    if total == 0:
        story.append(Paragraph('No security issues detected. The site appears well-protected.', ST['secure']))
    else:
        story.append(Paragraph(
            f'<b>{total}</b> security {"issue was" if total == 1 else "issues were"} detected '
            f'across this scan. These findings should be reviewed and remediated promptly.',
            ST['body'],
        ))
        story.append(sp(6))
        issue_rows = []
        for label, count, color in [
            ('SQL Injection',           sql_count,          DANGER),
            ('SSL/TLS Issue',           1 if ssl_issue else 0, WARN),
            ('HTTP Header Issues',      hdr_count,          INFO),
            ('WordPress Issues',        wp_count,           WARN),
            ('OWASP ZAP Alerts',        zap_count,          DANGER),
            ('XSS Vulnerabilities',     xss_count,          PURPLE),
            ('Technology Exposure',     tech_count,         INFO),
            ('Dependency Advisories',   advisory_count,     DANGER),
            ('Sensitive File Exposure', exposure_count,     WARN),
            ('Malicious Indicators',    1 if is_mal else 0, PURPLE),
        ]:
            if count > 0:
                icon = '●'
                row_style = ParagraphStyle('is', fontName='Helvetica-Bold', fontSize=9,
                                            leading=13, textColor=color)
                issue_rows.append([Paragraph(f'{icon}  {label}', row_style),
                                   Paragraph(str(count), row_style)])

        if issue_rows:
            issue_t = Table(issue_rows, colWidths=[PAGE_W - 2 * MARGIN - 50, 50])
            issue_t.setStyle(TableStyle([
                ('BACKGROUND',     (0,0), (-1,-1), CARD),
                ('ROWBACKGROUNDS', (0,0), (-1,-1), [CARD, ELEVATED]),
                ('LINEBELOW',      (0,0), (-1,-2), 0.3, BORDER),
                ('TOPPADDING',     (0,0), (-1,-1), 5),
                ('BOTTOMPADDING',  (0,0), (-1,-1), 5),
                ('LEFTPADDING',    (0,0), (-1,-1), 10),
                ('ALIGN',          (1,0), (1,-1),  'RIGHT'),
                ('RIGHTPADDING',   (1,0), (1,-1),  10),
            ]))
            story.append(issue_t)

    story.append(sp(10))
    story.append(_divider())

    # ── Detailed Findings ─────────────────────────────────────────────────────
    story.append(sp(4))
    story.append(Paragraph('Detailed Findings', ST['h2']))
    story.append(sp(8))

    findings = results.get('findings') or results

    # SQL Injection
    sqli = findings.get('sqli') or results.get('sqli') or []
    story.append(_section_header(
        'SQL Injection Analysis',
        f'{len(sqli)} vulnerabilities found' if sqli else 'No issues detected',
        '✗' if sqli else '✓',
        DANGER if sqli else SECURE, ST,
    ))
    story.append(sp(4))
    if sqli:
        story.extend(_findings_block(sqli, DANGER, ST))
        story.extend(_recs_block([
            'Use parameterized queries and prepared statements',
            'Validate and sanitize all user-supplied input',
            'Apply least-privilege database accounts',
            'Consider a Web Application Firewall (WAF)',
        ], ST))
    else:
        story.append(Paragraph('✓  No SQL injection vulnerabilities were detected.', ST['secure']))
    story.append(sp(10))

    # SSL/TLS
    ssl = findings.get('ssl') or results.get('ssl') or {}
    ssl_valid = ssl.get('valid', False)
    story.append(_section_header(
        'SSL/TLS Certificate',
        'Certificate issue detected' if not ssl_valid else 'Valid certificate',
        '✗' if not ssl_valid else '✓',
        WARN if not ssl_valid else SECURE, ST,
    ))
    story.append(sp(4))
    if ssl_valid:
        ssl_rows = [
            [Paragraph(k, ST['label']), Paragraph(str(v), ST['body_w'])]
            for k, v in [
                ('Issuer',   (ssl.get('issuer') or {}).get('organizationName') or (ssl.get('issuer') or {}).get('commonName')),
                ('Subject',  (ssl.get('subject') or {}).get('commonName')),
                ('Expires',  ssl.get('expires')),
                ('Protocol', ssl.get('protocol')),
            ] if v
        ]
        if ssl_rows:
            ssl_t = Table(ssl_rows, colWidths=[80, PAGE_W - 2 * MARGIN - 80])
            ssl_t.setStyle(TableStyle([
                ('BACKGROUND',    (0,0), (-1,-1), SURFACE),
                ('TOPPADDING',    (0,0), (-1,-1), 4),
                ('BOTTOMPADDING', (0,0), (-1,-1), 4),
                ('LEFTPADDING',   (0,0), (-1,-1), 10),
                ('LINEBELOW',     (0,0), (-1,-2), 0.3, BORDER),
            ]))
            story.append(ssl_t)
    else:
        story.extend(_findings_block([{
            'name':     'Certificate Issue',
            'severity': 'High',
            'evidence': ssl.get('error', 'Invalid or untrusted certificate'),
        }], WARN, ST))
        story.extend(_recs_block([
            "Obtain a trusted certificate (Let's Encrypt is free)",
            'Use TLS 1.2+ with strong cipher suites',
            'Enable HSTS',
            'Set up automatic certificate renewal',
        ], ST))
    story.append(sp(10))

    # HTTP Headers
    header_data = findings.get('headers') or results.get('headers') or {}
    hdr_issues = header_data.get('issues') or []
    story.append(_section_header(
        'HTTP Header Security',
        f'{len(hdr_issues)} issue{"s" if len(hdr_issues) != 1 else ""} found' if hdr_issues else 'No issues',
        '✗' if hdr_issues else '✓',
        INFO if hdr_issues else SECURE, ST,
    ))
    story.append(sp(4))
    if hdr_issues:
        story.extend(_findings_block(hdr_issues, INFO, ST))
        story.extend(_recs_block(header_data.get('recommendations') or [], ST))
    else:
        story.append(Paragraph('✓  No HTTP header misconfigurations detected.', ST['secure']))
    story.append(sp(10))

    # WordPress
    wp = findings.get('wordpress') or results.get('wordpress') or {}
    wp_issues = wp.get('issues') or []
    is_wp = wp.get('is_wordpress', False)
    story.append(_section_header(
        'WordPress Security',
        'Not a WordPress site' if not is_wp else
        (f'{len(wp_issues)} issue{"s" if len(wp_issues) != 1 else ""} found' if wp_issues else 'No issues'),
        '—' if not is_wp else ('✗' if wp_issues else '✓'),
        DIM if not is_wp else (WARN if wp_issues else SECURE), ST,
    ))
    story.append(sp(4))
    if not is_wp:
        story.append(Paragraph('No WordPress installation detected on this target.', ST['body']))
    elif wp_issues:
        story.extend(_findings_block(wp_issues, WARN, ST))
        story.extend(_recs_block(wp.get('recommendations') or [], ST))
    else:
        story.append(Paragraph('✓  No WordPress hardening issues detected.', ST['secure']))
    story.append(sp(10))

    # OWASP ZAP
    zap = findings.get('zap') or results.get('zap') or {}
    zap_issues = zap.get('issues') or []
    zap_disabled = zap.get('status') in ('not_run', 'disabled', None) and not zap_issues
    story.append(_section_header(
        'OWASP ZAP Analysis',
        'Not enabled' if zap_disabled else
        (f'{len(zap_issues)} alert{"s" if len(zap_issues) != 1 else ""}' if zap_issues else 'No alerts'),
        '—' if zap_disabled else ('✗' if zap_issues else '✓'),
        DIM if zap_disabled else (DANGER if zap_issues else SECURE), ST,
    ))
    story.append(sp(4))
    if zap_disabled:
        story.append(Paragraph('OWASP ZAP was not run in this scan environment.', ST['body']))
    elif zap_issues:
        story.extend(_findings_block(zap_issues, DANGER, ST))
    else:
        story.append(Paragraph('✓  OWASP ZAP found no additional security alerts.', ST['secure']))
    story.append(sp(10))

    # Malicious Content
    mal = findings.get('malicious') or results.get('malicious') or {}
    story.append(_section_header(
        'Malicious Content Analysis',
        'Potential threats detected' if is_mal else 'No threats detected',
        '✗' if is_mal else '✓',
        PURPLE if is_mal else SECURE, ST,
    ))
    story.append(sp(4))
    if is_mal:
        indicators = [
            mal.get('score') is not None and {'name': 'Threat Score', 'severity': 'High',   'evidence': f'{mal["score"]}/10'},
            mal.get('phishing_match')     and {'name': 'Phishing Pattern Match', 'severity': 'Critical', 'evidence': 'Domain matches known phishing signatures'},
            (mal.get('dnsbl') or {}).get('blacklisted') and {'name': 'DNS Blacklist', 'severity': 'High', 'evidence': f'Listed in {(mal.get("dnsbl") or {}).get("total_detected", 0)} blacklists'},
        ]
        story.extend(_findings_block([i for i in indicators if i], PURPLE, ST))
        story.extend(_recs_block([
            'Do not enter sensitive information on this site',
            'Block this domain in your organisation',
            'If this is your site, investigate for compromise immediately',
            'Run a server-side malware scan',
        ], ST))
    else:
        story.append(Paragraph('✓  No malicious indicators detected.', ST['secure']))
        if mal.get('score') is not None:
            story.append(sp(4))
            story.append(Paragraph(f'Threat Score: {mal["score"]}/10', ST['body']))
    story.append(sp(10))

    # XSS
    xss_data   = findings.get('xss') or results.get('xss') or {}
    xss_issues = xss_data.get('issues') or []
    xss_reflected = [i for i in xss_issues if i.get('type') == 'Reflected XSS']
    csp_present = xss_data.get('csp_present', True)
    xss_ran = bool(xss_data)
    story.append(_section_header(
        'Cross-Site Scripting (XSS)',
        'Not run' if not xss_ran else (
            f'{len(xss_reflected)} reflected vector{"s" if len(xss_reflected) != 1 else ""} found'
            if xss_reflected else 'No reflected XSS detected'
        ),
        '—' if not xss_ran else ('✗' if xss_reflected else '✓'),
        DIM if not xss_ran else (PURPLE if xss_reflected else SECURE), ST,
    ))
    story.append(sp(4))
    if not xss_ran:
        story.append(Paragraph('XSS scan was not run in this scan.', ST['body']))
    elif xss_reflected:
        mapped = [{
            'name':     i.get('type', 'Reflected XSS'),
            'severity': i.get('severity', 'High'),
            'evidence': ' | '.join(filter(None, [
                i.get('vector'),
                f"Param: {i['parameter']}" if i.get('parameter') else None,
                f"Payload: {i['payload'][:60]}" if i.get('payload') else None,
            ])),
        } for i in xss_reflected]
        story.extend(_findings_block(mapped, PURPLE, ST))
        if not csp_present:
            story.extend(_findings_block([{
                'name':     'Content-Security-Policy header missing',
                'severity': 'Medium',
                'evidence': 'No CSP header detected — XSS is easier to exploit without it',
            }], WARN, ST))
        story.extend(_recs_block(xss_data.get('recommendations') or [
            'Encode all user-supplied output using context-aware encoding (HTML, JS, URL).',
            'Implement a strict Content-Security-Policy header.',
            'Use HttpOnly and Secure flags on all session cookies.',
        ], ST))
    else:
        story.append(Paragraph('✓  No reflected XSS vectors detected in tested parameters.', ST['secure']))
        if not csp_present:
            story.append(sp(4))
            story.extend(_findings_block([{
                'name':     'Content-Security-Policy header missing',
                'severity': 'Medium',
                'evidence': 'No CSP detected — add one as a defence-in-depth measure',
            }], WARN, ST))
    story.append(sp(10))

    # Technology Fingerprinting
    tech_data = findings.get('tech') or results.get('tech') or {}
    tech_issues = tech_data.get('issues') or []
    tech_ran = bool(tech_data)
    actionable_tech = [i for i in tech_issues if i.get('severity') != 'Info']
    story.append(_section_header(
        'Technology Fingerprinting',
        'Not run' if not tech_ran else (
            f'{len(actionable_tech)} actionable issue{"s" if len(actionable_tech) != 1 else ""} found'
            if actionable_tech else 'No actionable technology issues'
        ),
        '—' if not tech_ran else ('✗' if actionable_tech else '✓'),
        DIM if not tech_ran else (INFO if actionable_tech else SECURE), ST,
    ))
    story.append(sp(4))
    if not tech_ran:
        story.append(Paragraph('Technology fingerprinting was not run in this scan.', ST['body']))
    else:
        technologies = tech_data.get('technologies') or {}
        packages = tech_data.get('packages') or []
        advisories = tech_data.get('advisories') or []
        if technologies:
            tech_rows = [
                [Paragraph(category.replace('-', ' ').title(), ST['label']),
                 Paragraph(', '.join(values), ST['body_w'])]
                for category, values in technologies.items() if values
            ]
            if tech_rows:
                tech_t = Table(tech_rows, colWidths=[110, PAGE_W - 2 * MARGIN - 110])
                tech_t.setStyle(TableStyle([
                    ('BACKGROUND',    (0,0), (-1,-1), SURFACE),
                    ('TOPPADDING',    (0,0), (-1,-1), 4),
                    ('BOTTOMPADDING', (0,0), (-1,-1), 4),
                    ('LEFTPADDING',   (0,0), (-1,-1), 10),
                    ('LINEBELOW',     (0,0), (-1,-2), 0.3, BORDER),
                ]))
                story.append(tech_t)
                story.append(sp(6))
        if packages:
            package_rows = [
                [
                    Paragraph(pkg.get('name', 'package'), ST['label']),
                    Paragraph(f"{pkg.get('version', 'unknown')} ({pkg.get('ecosystem', 'npm')})", ST['body_w']),
                ]
                for pkg in packages[:20]
            ]
            package_t = Table(package_rows, colWidths=[110, PAGE_W - 2 * MARGIN - 110])
            package_t.setStyle(TableStyle([
                ('BACKGROUND',    (0,0), (-1,-1), SURFACE),
                ('TOPPADDING',    (0,0), (-1,-1), 4),
                ('BOTTOMPADDING', (0,0), (-1,-1), 4),
                ('LEFTPADDING',   (0,0), (-1,-1), 10),
                ('LINEBELOW',     (0,0), (-1,-2), 0.3, BORDER),
            ]))
            story.append(Paragraph('Detected Packages', ST['label']))
            story.append(sp(4))
            story.append(package_t)
            story.append(sp(6))
        if advisories:
            mapped_advisories = [{
                'name': f"{adv.get('package')}@{adv.get('version')}",
                'severity': adv.get('severity', 'Medium'),
                'evidence': ' | '.join(filter(None, [
                    ', '.join(adv.get('cves') or []) or adv.get('id'),
                    ', '.join(adv.get('cwes') or []) or 'CWE not published',
                    adv.get('summary'),
                    adv.get('fixed_versions') and f"Fixed in {', '.join(adv.get('fixed_versions')[:3])}",
                ])),
            } for adv in advisories[:20]]
            story.append(Paragraph('Published Vulnerabilities', ST['label']))
            story.append(sp(4))
            story.extend(_findings_block(mapped_advisories, DANGER, ST))
        if tech_issues:
            story.extend(_findings_block(tech_issues, INFO, ST))
        else:
            story.append(Paragraph('✓  No risky technology exposure indicators detected.', ST['secure']))
        if tech_data.get('recommendations'):
            story.extend(_recs_block(tech_data.get('recommendations') or [], ST))
    story.append(sp(10))

    # Sensitive File Exposure
    exp_data   = findings.get('exposure') or results.get('exposure') or {}
    exp_issues = exp_data.get('issues') or []
    exp_ran    = bool(exp_data)
    exp_critical = [i for i in exp_issues if i.get('severity') in ('Critical', 'High')]
    story.append(_section_header(
        'Sensitive File Exposure',
        'Not run' if not exp_ran else (
            f'{len(exp_issues)} path{"s" if len(exp_issues) != 1 else ""} exposed'
            if exp_issues else 'No sensitive files exposed'
        ),
        '—' if not exp_ran else ('✗' if exp_issues else '✓'),
        DIM if not exp_ran else (DANGER if exp_critical else (WARN if exp_issues else SECURE)), ST,
    ))
    story.append(sp(4))
    if not exp_ran:
        story.append(Paragraph('Sensitive file exposure scan was not run.', ST['body']))
    elif exp_issues:
        from reportlab.platypus import KeepTogether
        discovered_emails = exp_data.get('discovered_emails') or []
        if discovered_emails:
            story.extend(_findings_block([
                {
                    'name': 'Discovered email address',
                    'severity': 'Info',
                    'evidence': _obfuscate_email(email),
                }
                for email in discovered_emails[:20]
            ], INFO, ST))
            story.append(sp(4))
        from reportlab.platypus import KeepTogether
        for i in exp_issues:
            sev = i.get('severity', 'Medium')
            sev_colors = {
                'Critical': DANGER, 'High': DANGER,
                'Medium': WARN, 'Low': INFO,
            }
            sev_color = sev_colors.get(sev, DIM)
            cl = i.get('content_length')
            issue_url = _safe_text(i.get('url') or i.get('path') or '')
            issue_emails = i.get('emails') or []

            # Build structured metadata rows
            meta_rows = [
                [Paragraph('SEVERITY', ST['label']),
                 Paragraph(f'<font color="#{sev_color.hexval()[2:]}">{sev}</font>', ST['body_w'])],
                [Paragraph('URL', ST['label']),
                 Paragraph(issue_url, ST['mono'])],
            ]
            if cl:
                meta_rows.append([
                    Paragraph('SIZE', ST['label']),
                    Paragraph(f'{cl:,} bytes', ST['body_w']),
                ])
            if issue_emails:
                meta_rows.append([
                    Paragraph('EMAILS FOUND', ST['label']),
                    Paragraph(
                        ', '.join(_obfuscate_email(e) for e in issue_emails[:5]),
                        ST['body_w'],
                    ),
                ])

            # Content preview — strip HTML, show only plaintext files
            raw_preview = (i.get('content_preview') or '').strip()
            import re as _re
            looks_like_html = bool(_re.search(r'<\s*(html|head|body|div|script)\b', raw_preview, _re.I))
            if raw_preview and not looks_like_html:
                clean = _strip_html(raw_preview)[:400]
                if clean:
                    meta_rows.append([
                        Paragraph('PREVIEW', ST['label']),
                        Paragraph(
                            escape(clean),
                            ParagraphStyle('prev', fontName='Courier', fontSize=7,
                                           leading=10, textColor=INFO),
                        ),
                    ])

            meta_t = Table(
                meta_rows,
                colWidths=[72, PAGE_W - 2 * MARGIN - 72],
                style=TableStyle([
                    ('BACKGROUND',    (0, 0), (-1, -1), CARD),
                    ('LINEBELOW',     (0, 0), (-1, -2), 0.3, BORDER),
                    ('TOPPADDING',    (0, 0), (-1, -1), 4),
                    ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
                    ('LEFTPADDING',   (0, 0), (-1, -1), 10),
                    ('VALIGN',        (0, 0), (-1, -1), 'TOP'),
                ]),
            )

            title_row = Table(
                [[Paragraph(
                    f'<b>{_safe_text(i.get("name", "Exposed path"))}</b>',
                    ParagraphStyle('etitle', fontName='Helvetica-Bold', fontSize=9,
                                   leading=12, textColor=TEXT),
                )]],
                colWidths=[PAGE_W - 2 * MARGIN],
                style=TableStyle([
                    ('BACKGROUND',    (0, 0), (-1, -1), sev_color if sev in ('Critical', 'High') else ELEVATED),
                    ('LEFTPADDING',   (0, 0), (-1, -1), 10),
                    ('TOPPADDING',    (0, 0), (-1, -1), 6),
                    ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
                    ('LINEABOVE',     (0, 0), (-1, 0),  1.5, sev_color),
                ]),
            )
            story.append(KeepTogether([title_row, meta_t, sp(6)]))
        story.extend(_recs_block(exp_data.get('recommendations') or [
            'Block access to sensitive paths in your web server configuration.',
            'Remove backup files, debug pages, and credentials from the web root.',
            'Rotate any credentials that may have been exposed.',
        ], ST))
    else:
        story.append(Paragraph('✓  No sensitive files or credentials exposed at common paths.', ST['secure']))
    story.append(sp(10))

    # DNS Security
    dns_data   = findings.get('dns') or results.get('dns') or {}
    dns_issues = dns_data.get('issues') or []
    dns_ran    = bool(dns_data)
    dns_high   = [i for i in dns_issues if i.get('severity') in ('Critical', 'High')]
    story.append(_section_header(
        'DNS Security (SPF / DMARC / DKIM)',
        'Not run' if not dns_ran else (
            f'{len(dns_issues)} issue{"s" if len(dns_issues) != 1 else ""}' if dns_issues else 'Pass'
        ),
        '—' if not dns_ran else ('✗' if dns_issues else '✓'),
        DIM if not dns_ran else (DANGER if dns_high else (WARN if dns_issues else SECURE)), ST,
    ))
    story.append(sp(4))
    if not dns_ran:
        story.append(Paragraph('DNS security scan was not run.', ST['body']))
    elif dns_issues:
        story.extend(_findings_block(dns_issues, DANGER if dns_high else WARN, ST))
        story.extend(_recs_block(dns_data.get('recommendations') or [], ST))
    else:
        story.append(Paragraph('✓  SPF, DMARC, DKIM, and CAA records are properly configured.', ST['secure']))
    story.append(sp(10))

    # Open Redirect
    redir_data   = findings.get('redirect') or results.get('redirect') or {}
    redir_issues = redir_data.get('issues') or []
    redir_ran    = bool(redir_data)
    story.append(_section_header(
        'Open Redirect',
        'Not run' if not redir_ran else (
            f'{len(redir_issues)} redirect{"s" if len(redir_issues) != 1 else ""} found' if redir_issues else 'Pass'
        ),
        '—' if not redir_ran else ('✗' if redir_issues else '✓'),
        DIM if not redir_ran else (DANGER if redir_issues else SECURE), ST,
    ))
    story.append(sp(4))
    if not redir_ran:
        story.append(Paragraph('Open redirect scan was not run.', ST['body']))
    elif redir_issues:
        story.extend(_findings_block(redir_issues, DANGER, ST))
        story.extend(_recs_block(redir_data.get('recommendations') or [], ST))
    else:
        story.append(Paragraph('✓  No open redirect vulnerabilities detected.', ST['secure']))
    story.append(sp(10))

    # Subdomain Takeover
    take_data   = findings.get('takeover') or results.get('takeover') or {}
    take_issues = take_data.get('issues') or []
    take_ran    = bool(take_data)
    story.append(_section_header(
        'Subdomain Takeover',
        'Not run' if not take_ran else (
            f'{len(take_issues)} vulnerable subdomain{"s" if len(take_issues) != 1 else ""}' if take_issues else 'Pass'
        ),
        '—' if not take_ran else ('✗' if take_issues else '✓'),
        DIM if not take_ran else (DANGER if take_issues else SECURE), ST,
    ))
    story.append(sp(4))
    if not take_ran:
        story.append(Paragraph('Subdomain takeover scan was not run.', ST['body']))
    elif take_issues:
        story.extend(_findings_block(take_issues, DANGER, ST))
        story.extend(_recs_block(take_data.get('recommendations') or [], ST))
        subs = take_data.get('subdomains_checked') or []
        if subs:
            story.append(Paragraph(
                f'Subdomains checked: {", ".join(subs[:20])}',
                ST['small'],
            ))
    else:
        checked = take_data.get('subdomains_checked') or []
        story.append(Paragraph(
            f'✓  No dangling CNAMEs or unclaimed service fingerprints found'
            f'{" across " + str(len(checked)) + " subdomains" if checked else ""}.',
            ST['secure'],
        ))
    story.append(sp(10))

    # Product Readiness / UX sections
    sections = results.get('sections') or {}
    for section_key, color in [
        ('accessibility', INFO),
        ('responsive_ux', WARN),
        ('performance_ux', INFO),
        ('form_usability', WARN),
        ('visual_ai', PURPLE),
    ]:
        section = sections.get(section_key) or {}
        if section.get('status') == 'not_run':
            continue
        story.append(_section_header(
            section.get('label', section_key.replace('_', ' ').title()),
            f"{section.get('issue_count', 0)} issue{'s' if section.get('issue_count', 0) != 1 else ''}" if section.get('issue_count', 0) else 'No issues',
            '✗' if section.get('issue_count', 0) else '✓',
            color if section.get('issue_count', 0) else SECURE,
            ST,
        ))
        story.append(sp(4))
        if section.get('issue_count', 0):
            story.extend(_findings_block(section.get('top_findings') or [], color, ST))
            story.extend(_recs_block(section.get('recommendations') or [], ST))
        else:
            story.append(Paragraph('✓  No issues detected in this category.', ST['secure']))
        story.append(sp(10))

    # ── Conclusion ────────────────────────────────────────────────────────────
    story.append(_divider())
    story.append(sp(4))
    story.append(Paragraph('Conclusion & Recommended Next Steps', ST['h2']))
    story.append(sp(6))

    if total == 0:
        story.append(Paragraph(
            'No security vulnerabilities were detected in this scan. '
            'Continue scanning regularly and keep all software up to date.',
            ST['secure'],
        ))
    else:
        steps = []
        if sql_count:      steps.append(('SQL Injection',       'Migrate to parameterised queries and review all input handling code.'))
        if ssl_issue:      steps.append(('SSL/TLS',             'Renew or replace the certificate with one from a trusted CA.'))
        if hdr_count:      steps.append(('HTTP Headers',        'Add missing security headers (CSP, HSTS, X-Frame-Options, etc.).'))
        if wp_count:       steps.append(('WordPress',           'Update core, themes and plugins; restrict XML-RPC and REST exposure.'))
        if zap_count:      steps.append(('ZAP Alerts',          'Triage each alert and patch confirmed vulnerabilities.'))
        if xss_count:      steps.append(('XSS',                 'Encode all output and implement a Content-Security-Policy header.'))
        if tech_count:     steps.append(('Technology Exposure', 'Patch outdated client libraries, disable directory indexes, and reduce version disclosure.'))
        if advisory_count: steps.append(('Dependency Risk',     'Upgrade vulnerable packages, review CVE/CWE exposure, and automate dependency scanning in CI/CD.'))
        if exposure_count: steps.append(('File Exposure',       'Block sensitive paths in the web server and rotate any exposed credentials.'))
        if is_mal:         steps.append(('Malicious Site',      'Investigate server compromise, rotate credentials, and notify users.'))
        dns_count = summary.get('dns_issue_count', 0)
        redir_count = summary.get('redirect_count', 0)
        take_count = summary.get('takeover_count', 0)
        if dns_count:      steps.append(('DNS Security',        'Configure SPF (-all), DMARC (p=quarantine or reject), DKIM signing, and CAA records.'))
        if redir_count:    steps.append(('Open Redirect',       'Validate all redirect targets against a strict server-side allowlist.'))
        if take_count:     steps.append(('Subdomain Takeover',  'Remove dangling CNAME records and claim or delete unclaimed service deployments.'))

        rows = [[
            Paragraph(f'{i+1}. {t}', ParagraphStyle('st', fontName='Helvetica-Bold', fontSize=9,
                                                       leading=12, textColor=TEXT)),
            Paragraph(desc, ST['body']),
        ] for i, (t, desc) in enumerate(steps)]

        t = Table(rows, colWidths=[110, PAGE_W - 2 * MARGIN - 110])
        t.setStyle(TableStyle([
            ('BACKGROUND',     (0,0), (-1,-1), CARD),
            ('ROWBACKGROUNDS', (0,0), (-1,-1), [CARD, ELEVATED]),
            ('LINEBELOW',      (0,0), (-1,-2), 0.3, BORDER),
            ('TOPPADDING',     (0,0), (-1,-1), 6),
            ('BOTTOMPADDING',  (0,0), (-1,-1), 6),
            ('LEFTPADDING',    (0,0), (-1,-1), 10),
            ('VALIGN',         (0,0), (-1,-1), 'TOP'),
        ]))
        story.append(t)

    story.append(sp(12))
    story.append(_divider())
    story.append(sp(4))
    story.append(Paragraph('Developer Best Practices', ST['h2']))
    story.append(sp(6))
    practices = build_best_practices(results)
    if practices:
        story.extend(_recs_block(practices, ST))

    story.append(sp(16))

    doc.build(story)
    buffer.seek(0)
    return buffer
