import io
import os
from datetime import datetime, timezone, timedelta
from xml.sax.saxutils import escape

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.units import inch
from reportlab.platypus import (
    BaseDocTemplate, Frame, HRFlowable, PageTemplate,
    Paragraph, Spacer, Table, TableStyle, Image, KeepTogether,
)
from reportlab.lib.colors import HexColor

from app.utils.scan_helpers import build_best_practices, build_risk_rating, build_scan_summary, build_security_score, owasp_coverage_summary

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
def _draw_brand_mark(canvas, x, y, size=28):
    """Draw a compact LaunchGuard mark in report headers."""
    canvas.saveState()
    s = size

    canvas.setFillColor(HexColor('#07111F'))
    canvas.roundRect(x, y, s, s, 6, fill=1, stroke=0)

    shield = canvas.beginPath()
    shield.moveTo(x + s * 0.5, y + s * 0.88)
    shield.lineTo(x + s * 0.22, y + s * 0.72)
    shield.lineTo(x + s * 0.22, y + s * 0.36)
    shield.curveTo(x + s * 0.22, y + s * 0.2, x + s * 0.34, y + s * 0.12, x + s * 0.5, y + s * 0.06)
    shield.curveTo(x + s * 0.66, y + s * 0.12, x + s * 0.78, y + s * 0.2, x + s * 0.78, y + s * 0.36)
    shield.lineTo(x + s * 0.78, y + s * 0.72)
    shield.close()
    canvas.setStrokeColor(WHITE)
    canvas.setLineWidth(1.5)
    canvas.drawPath(shield, fill=0, stroke=1)

    canvas.setStrokeColor(PRIMARY)
    canvas.setLineWidth(2.2)
    canvas.line(x + s * 0.22, y + s * 0.72, x + s * 0.22, y + s * 0.36)
    canvas.line(x + s * 0.22, y + s * 0.72, x + s * 0.5, y + s * 0.88)

    canvas.setStrokeColor(INFO)
    canvas.setLineWidth(3)
    canvas.line(x + s * 0.35, y + s * 0.48, x + s * 0.47, y + s * 0.34)
    canvas.line(x + s * 0.47, y + s * 0.34, x + s * 0.68, y + s * 0.6)

    canvas.setStrokeColor(HexColor('#2DD4BF'))
    canvas.setLineWidth(1.5)
    canvas.arc(x - s * 0.1, y + s * 0.08, x + s * 1.12, y + s * 0.84, 205, 120)
    canvas.setFillColor(HexColor('#2DD4BF'))
    canvas.circle(x + s * 0.88, y + s * 0.66, s * 0.06, fill=1, stroke=0)

    canvas.restoreState()


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

    # Header brand
    _draw_brand_mark(canvas, MARGIN, h - 42, 28)
    canvas.setFillColor(TEXT)
    canvas.setFont('Helvetica-Bold', 11)
    canvas.drawString(MARGIN + 36, h - 30, 'LaunchGuard')
    canvas.setFillColor(MUTED)
    canvas.setFont('Helvetica', 8)
    canvas.drawString(MARGIN + 36, h - 42, 'Launch Readiness Report')

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


def _action_for_finding(item: dict) -> str:
    title = str(item.get('title') or item.get('name') or '').lower()
    remediation = item.get('technical_remediation') or item.get('remediation') or item.get('recommendation')
    if remediation:
        return str(remediation)
    if 'terraform' in title or 'secret' in title or 'credential' in title or 'sensitive' in title:
        return 'Verify the exposure manually, block the path, and rotate any affected credentials.'
    if 'content-security-policy' in title or 'csp' in title:
        return 'Add a Content-Security-Policy tuned to the site assets and third-party services.'
    if 'strict-transport-security' in title or 'hsts' in title:
        return 'Add Strict-Transport-Security after confirming HTTPS is enforced everywhere.'
    if 'x-frame-options' in title or 'clickjack' in title or 'frame' in title:
        return 'Add frame-ancestors in CSP or X-Frame-Options: SAMEORIGIN.'
    if 'spf' in title or 'dmarc' in title or 'dkim' in title:
        return 'Configure email authentication DNS records if the domain sends mail.'
    if 'tap target' in title:
        return 'Increase the tappable area to at least 44 by 44 pixels on mobile.'
    if 'label' in title or 'accessible name' in title:
        return 'Add visible labels or concise aria-label values for the affected controls.'
    return 'Fix or verify this finding before relying on the page in production.'


def _business_summary(summary: dict, verdict_label: str, total: int) -> str:
    blockers = int(summary.get('launch_blocker_count') or 0)
    high_signal = []
    if summary.get('exposure_count'):
        high_signal.append('possible sensitive file exposure')
    if summary.get('secrets_count'):
        high_signal.append('public secret exposure')
    if summary.get('header_issue_count'):
        high_signal.append('missing browser security headers')
    if summary.get('dns_issue_count'):
        high_signal.append('email-domain DNS protections')
    if summary.get('accessibility_issue_count'):
        high_signal.append('accessibility blockers')
    if summary.get('performance_issue_count'):
        high_signal.append('mobile performance budget risk')

    concerns = ', '.join(high_signal[:4]) if high_signal else 'the findings listed below'
    if blockers:
        return (
            f'LaunchGuard detected <b>{total}</b> finding{"s" if total != 1 else ""}. '
            f'The current launch verdict is <b>{escape(verdict_label)}</b> because {blockers} launch-blocking '
            f'item{"s" if blockers != 1 else ""} require attention. The most important concerns are {escape(concerns)}. '
            'Fix or verify the launch blockers first, then handle lower-severity hardening work.'
        )
    if total:
        return (
            f'LaunchGuard detected <b>{total}</b> finding{"s" if total != 1 else ""}. '
            f'The current launch verdict is <b>{escape(verdict_label)}</b>. The main concerns are {escape(concerns)}. '
            'These items should be prioritized by user impact and exploitability.'
        )
    return 'No launch-blocking findings were detected in this scan. Continue monitoring headers, dependencies, and release configuration before shipping.'


def _group_findings(items: list[dict]) -> list[dict]:
    grouped: dict[tuple[str, str], dict] = {}
    for item in items:
        name = item.get('name') or item.get('alert') or item.get('title') or item.get('type') or 'Finding'
        sev = item.get('severity') or item.get('risk') or 'Info'
        key = (str(name), str(sev))
        if key not in grouped:
            grouped[key] = dict(item)
            grouped[key]['name'] = str(name)
            grouped[key]['severity'] = str(sev).title()
            grouped[key]['occurrences'] = 1
            urls = []
            if item.get('url'):
                urls.append(str(item.get('url')))
            grouped[key]['affected_urls'] = urls
        else:
            grouped[key]['occurrences'] += 1
            if item.get('url'):
                url = str(item.get('url'))
                if url not in grouped[key]['affected_urls']:
                    grouped[key]['affected_urls'].append(url)

    result = []
    for item in grouped.values():
        if item.get('occurrences', 1) > 1:
            evidence = item.get('evidence') or item.get('description') or ''
            suffix = f"Found on {item['occurrences']} pages/resources."
            urls = item.get('affected_urls') or []
            if urls:
                suffix += f" Examples: {', '.join(urls[:3])}."
            item['evidence'] = f"{suffix} {evidence}".strip()
        result.append(item)
    return result


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
        owasp_cat = item.get('owasp_category') or ''
        if owasp_cat:
            rows.append([
                Paragraph(f'OWASP: {_safe_text(owasp_cat)}', ParagraphStyle('oc', fontName='Helvetica-Oblique', fontSize=7.5,
                                                                             leading=10, textColor=INFO)),
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


def _compact_table(title, headers, rows, ST, *, max_rows=20):
    clean_rows = rows[:max_rows]
    if not clean_rows:
        return []
    style = ParagraphStyle('ct', fontName='Helvetica', fontSize=7, leading=9, textColor=MUTED)
    head_style = ParagraphStyle('cth', fontName='Helvetica-Bold', fontSize=7, leading=9, textColor=TEXT)
    table_rows = [[Paragraph(_safe_text(header, 40), head_style) for header in headers]]
    for row in clean_rows:
        table_rows.append([Paragraph(_safe_text(cell, 95), style) for cell in row])
    col_width = (PAGE_W - 2 * MARGIN) / max(1, len(headers))
    table = Table(table_rows, colWidths=[col_width] * len(headers), repeatRows=1)
    table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), ELEVATED),
        ('BACKGROUND', (0, 1), (-1, -1), CARD),
        ('ROWBACKGROUNDS', (0, 1), (-1, -1), [CARD, SURFACE]),
        ('GRID', (0, 0), (-1, -1), 0.25, BORDER),
        ('TOPPADDING', (0, 0), (-1, -1), 4),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
        ('LEFTPADDING', (0, 0), (-1, -1), 5),
        ('RIGHTPADDING', (0, 0), (-1, -1), 5),
        ('VALIGN', (0, 0), (-1, -1), 'TOP'),
    ]))
    blocks = [Spacer(1, 6), Paragraph(_safe_text(title), ST['h3']), Spacer(1, 3), table]
    if len(rows) > max_rows:
        blocks.append(Paragraph(f'{len(rows) - max_rows} additional rows omitted from PDF table.', ST['small']))
    return blocks


def _active_check_summary(results, ST):
    config = results.get('scan_config') or {}
    if not config:
        return []
    accounts = config.get('auth_test_accounts') or []
    rows = [[
        'Active checks',
        'enabled' if config.get('enable_active_checks') else 'disabled',
    ], [
        'Request budget',
        config.get('active_check_budget') or 'default',
    ], [
        'Auth test accounts',
        f'{len(accounts)} supplied (redacted)',
    ], [
        'Protected paths',
        len(config.get('protected_paths') or []),
    ], [
        'IDOR templates',
        len(config.get('idor_paths') or []),
    ]]
    return _compact_table('Pre-production Controls Summary', ['Control', 'Value'], rows, ST, max_rows=10)


def _technical_evidence_blocks(section_key, results, ST):
    payload = results.get(section_key) or {}
    blocks = []
    if section_key == 'app_controls':
        endpoints = payload.get('discovered_endpoints') or []
        blocks.extend(_compact_table(
            'Discovered API Endpoints',
            ['Endpoint'],
            [[endpoint] for endpoint in endpoints],
            ST,
            max_rows=30,
        ))
        js_files = payload.get('javascript_files') or []
        blocks.extend(_compact_table(
            'JavaScript Sources',
            ['File', 'Endpoints'],
            [[item.get('url'), len(item.get('endpoints') or [])] for item in js_files],
            ST,
            max_rows=20,
        ))
        specs = payload.get('openapi_specs') or []
        blocks.extend(_compact_table(
            'OpenAPI Specs',
            ['Spec URL', 'Endpoints'],
            [[item.get('url'), item.get('endpoint_count')] for item in specs],
            ST,
            max_rows=10,
        ))
        form_matrix = payload.get('form_matrix') or []
        blocks.extend(_compact_table(
            'Form Safety Matrix',
            ['Selector', 'Class', 'Method', 'Testing'],
            [[item.get('selector'), item.get('classification'), item.get('method'), 'bounded' if item.get('safe_to_submit') else 'manual'] for item in form_matrix],
            ST,
            max_rows=25,
        ))
    elif section_key == 'abuse_controls':
        routes = ((payload.get('discovery') or {}).get('routes') or [])
        blocks.extend(_compact_table(
            'Discovered Auth/Admin Routes',
            ['Path', 'Kind', 'HTTP'],
            [[item.get('path'), item.get('kind'), item.get('status_code')] for item in routes],
            ST,
            max_rows=25,
        ))
        observations = payload.get('observations') or []
        blocks.extend(_compact_table(
            'Rate-limit Observations',
            ['Endpoint', 'Method', 'Requests', 'Control'],
            [[item.get('endpoint'), item.get('method'), item.get('requests_sent'), item.get('control_reason') or ('yes' if item.get('control_detected') else 'no')] for item in observations],
            ST,
            max_rows=20,
        ))
    elif section_key == 'broken_links':
        checked = payload.get('checked_links') or []
        broken = [item for item in checked if not item.get('ok')]
        blocks.extend(_compact_table(
            'Broken Link Evidence',
            ['Source', 'Target', 'Status', 'Reason'],
            [[item.get('source_url'), item.get('target_url'), item.get('status_code'), item.get('reason')] for item in broken],
            ST,
            max_rows=30,
        ))
        if checked:
            blocks.extend(_compact_table(
                'Link Check Summary',
                ['Checked', 'Broken'],
                [[len(checked), len(broken)]],
                ST,
                max_rows=1,
            ))
    elif section_key == 'exposed_services':
        services = payload.get('open_services') or []
        blocks.extend(_compact_table(
            'Open Services',
            ['Host', 'Port', 'Risk', 'HTTP/Banner'],
            [[item.get('host'), item.get('port'), item.get('risk'), (item.get('http') or {}).get('server') or (item.get('http') or {}).get('status_code') or 'tcp'] for item in services],
            ST,
            max_rows=30,
        ))
        ports = payload.get('ports_checked') or []
        if ports:
            blocks.extend(_compact_table(
                'Port Check Scope',
                ['Ports Checked'],
                [[', '.join(str(port) for port in ports)]],
                ST,
                max_rows=1,
            ))
    return blocks


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

    label = Paragraph('LaunchGuard Score', ST['label'])

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


def _owasp_table(coverage: list, ST) -> list:
    if not coverage:
        return []
    STATUS_COLORS = {
        "covered_no_findings":   SECURE,
        "covered_with_findings": WARN,
        "not_tested":            DIM,
    }
    STATUS_LABELS = {
        "covered_no_findings":   "Covered",
        "covered_with_findings": "Issues Found",
        "not_tested":            "Not Tested",
    }
    header_style = ParagraphStyle("owh", fontName="Helvetica-Bold", fontSize=7.5, leading=10, textColor=TEXT)
    cell_style   = ParagraphStyle("owc", fontName="Helvetica",      fontSize=7.5, leading=10, textColor=MUTED)

    col_w = [200, 85, 55, PAGE_W - 2 * MARGIN - 340]
    rows = [[
        Paragraph("Category",     header_style),
        Paragraph("Status",       header_style),
        Paragraph("Findings",     header_style),
        Paragraph("Scanners Run", header_style),
    ]]
    for item in coverage:
        status = item.get("status", "not_tested")
        color  = STATUS_COLORS.get(status, DIM)
        label  = STATUS_LABELS.get(status, status)
        hex_color = color.hexval()[2:]
        rows.append([
            Paragraph(_safe_text(f"{item['id']} – {item['name']}"), cell_style),
            Paragraph(f'<font color="#{hex_color}">{label}</font>', cell_style),
            Paragraph(_safe_text(str(item.get("finding_count", 0))), cell_style),
            Paragraph(_safe_text(", ".join(item.get("scanners_run", [])) or "—"), cell_style),
        ])

    t = Table(rows, colWidths=col_w, repeatRows=1)
    t.setStyle(TableStyle([
        ("BACKGROUND",     (0, 0), (-1,  0), ELEVATED),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [CARD, SURFACE]),
        ("GRID",           (0, 0), (-1, -1), 0.25, BORDER),
        ("TOPPADDING",     (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING",  (0, 0), (-1, -1), 4),
        ("LEFTPADDING",    (0, 0), (-1, -1), 5),
        ("RIGHTPADDING",   (0, 0), (-1, -1), 5),
        ("VALIGN",         (0, 0), (-1, -1), "TOP"),
    ]))
    footnote = Paragraph(
        "Coverage is based on the scan profile used. 'Not Tested' categories were not included in this scan.",
        ST["small"],
    )
    return [t, Spacer(1, 4), footnote]


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
        title=f"LaunchGuard Report — {results.get('url', '')}",
    )
    frame = Frame(MARGIN, 0.7 * inch, PAGE_W - 2 * MARGIN, PAGE_H - 1.55 * inch, id='main')
    doc.addPageTemplates([PageTemplate(id='main', frames=[frame], onPage=_draw_page)])

    story = []

    def sp(h=6):
        return Spacer(1, h)

    summary   = results.get('summary') or build_scan_summary(results)
    verdict_data = results.get('launch_verdict') or {}
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
    nikto_count    = summary.get('nikto_issue_count', 0)
    xss_count      = summary.get('xss_count', 0)
    tech_count     = summary.get('tech_issue_count', 0)
    advisory_count = summary.get('advisory_count', 0)
    exposure_count = summary.get('exposure_count', 0)
    secrets_count  = summary.get('secrets_count', 0)
    malware_artifact_count = summary.get('malware_artifact_count', 0)
    total          = summary.get('total_issues', 0)

    risk  = build_risk_rating(summary)
    score = build_security_score(summary)

    risk_map = {
        'Critical': (HexColor('#4B0000'), DANGER),
        'High':     (HexColor('#3D2000'), WARN),
        'Medium':   (HexColor('#2D2000'), WARN),
        'Low':      (HexColor('#0D2D1A'), SECURE),
    }
    risk_bg, risk_fg = risk_map[risk]
    score_color = DANGER if score < 50 else WARN if score < 80 else SECURE
    verdict_key = verdict_data.get('verdict') or 'ready_to_ship'
    verdict_label = verdict_data.get('label') or str(verdict_key).replace('_', ' ').title()
    verdict_color = {
        'blocked': DANGER,
        'fix_before_shipping': WARN,
        'monitor_after_launch': INFO,
        'ready_to_ship': SECURE,
    }.get(verdict_key, INFO)

    # ── Hero ──────────────────────────────────────────────────────────────────
    story.append(sp(4))
    story.append(Paragraph('LaunchGuard Readiness Report', ST['h1']))
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

    # Launch verdict
    story.append(_section_header('Launch Verdict', verdict_label, '!', verdict_color, ST))
    story.append(sp(4))
    story.append(Paragraph(escape(verdict_data.get('summary') or 'No launch verdict was generated.'), ST['body_w']))
    if verdict_data.get('next_action'):
        story.append(sp(3))
        story.append(Paragraph(f"<b>Next action:</b> {escape(str(verdict_data.get('next_action')))}", ST['body']))
    profile = verdict_data.get('scan_profile') or {}
    if profile:
        story.append(sp(3))
        story.append(Paragraph(
            f"<b>Scan profile:</b> {escape(str(profile.get('label') or profile.get('key') or 'Configured scan'))}. "
            f"{escape(str(profile.get('description') or ''))}",
            ST['small'],
        ))
    top_blockers = verdict_data.get('top_blockers') or []
    important_issues = verdict_data.get('important_issues') or []
    if top_blockers or important_issues:
        story.append(sp(6))
        rows = [[Paragraph('Priority', ST['label']), Paragraph('Issue', ST['label']), Paragraph('Action', ST['label'])]]
        for index, item in enumerate((top_blockers or important_issues)[:5], start=1):
            title = escape(str(item.get('title') or 'Finding'))
            impact = escape(str(item.get('launch_impact') or 'fix_before_ship').replace('_', ' ').title())
            rows.append([
                Paragraph(str(index), ST['body_w']),
                Paragraph(f"<b>{impact}:</b> {title}", ST['body']),
                Paragraph(escape(_action_for_finding(item)), ST['body']),
            ])
        actions_t = Table(rows, colWidths=[44, 190, PAGE_W - 2 * MARGIN - 234])
        actions_t.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,-1), CARD),
            ('BACKGROUND', (0,0), (-1,0), SURFACE),
            ('BOX', (0,0), (-1,-1), 0.4, BORDER),
            ('LINEBELOW', (0,0), (-1,-2), 0.3, BORDER),
            ('TOPPADDING', (0,0), (-1,-1), 6),
            ('BOTTOMPADDING', (0,0), (-1,-1), 6),
            ('LEFTPADDING', (0,0), (-1,-1), 8),
            ('RIGHTPADDING', (0,0), (-1,-1), 8),
        ]))
        story.append(actions_t)
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

    # ── Site Screenshots ──────────────────────────────────────────────────────
    screenshots_data = results.get('screenshots') or {}
    shot_map = screenshots_data.get('screenshots') if isinstance(screenshots_data, dict) else {}
    if shot_map:
        story.append(sp(4))
        story.append(Paragraph('Site Screenshots', ST['h2']))
        story.append(sp(6))
        shot_cells = []
        labels = {'desktop': 'Desktop (1440px)', 'mobile': 'Mobile (390px)'}
        for vp in ('desktop', 'mobile'):
            path = shot_map.get(vp)
            if path and os.path.isfile(path):
                avail_w = (PAGE_W - 2 * MARGIN - 12) / 2
                try:
                    # Mobile screenshots are portrait (390px wide); render them at
                    # ~55% column width so they appear phone-sized next to the desktop.
                    if vp == 'mobile':
                        img_w = avail_w * 0.55
                        img = Image(path, width=img_w, height=img_w * (844 / 390), kind='proportional')
                    else:
                        img = Image(path, width=avail_w, height=avail_w * 0.6)
                    label = Paragraph(labels.get(vp, vp), ParagraphStyle(
                        'sl', fontName='Helvetica-Bold', fontSize=8,
                        textColor=MUTED, leading=11, alignment=TA_CENTER,
                    ))
                    shot_cells.append([label, img])
                except Exception:
                    pass
        if shot_cells:
            col_w = (PAGE_W - 2 * MARGIN - 12) / 2
            for label_row, img_row in [(s[0], s[1]) for s in shot_cells]:
                pass
            # Build side-by-side if both viewports present, else single
            if len(shot_cells) == 2:
                side_by_side = Table(
                    [[shot_cells[0][1], shot_cells[1][1]],
                     [shot_cells[0][0], shot_cells[1][0]]],
                    colWidths=[col_w, col_w],
                    hAlign='CENTER',
                )
                side_by_side.setStyle(TableStyle([
                    ('ALIGN',         (0,0), (-1,-1), 'CENTER'),
                    ('VALIGN',        (0,0), (-1,-1), 'TOP'),
                    ('LEFTPADDING',   (0,0), (-1,-1), 6),
                    ('RIGHTPADDING',  (0,0), (-1,-1), 6),
                    ('TOPPADDING',    (0,0), (-1,-1), 4),
                    ('BOTTOMPADDING', (0,0), (-1,-1), 4),
                    ('BACKGROUND',    (0,0), (-1,-1), SURFACE),
                    ('ROUNDEDCORNERS',(0,0), (-1,-1), [6,6,6,6]),
                ]))
                story.append(side_by_side)
            else:
                c = shot_cells[0]
                single = Table([[c[1]], [c[0]]], colWidths=[PAGE_W - 2 * MARGIN], hAlign='CENTER')
                single.setStyle(TableStyle([
                    ('ALIGN',         (0,0), (-1,-1), 'CENTER'),
                    ('BACKGROUND',    (0,0), (-1,-1), SURFACE),
                    ('TOPPADDING',    (0,0), (-1,-1), 4),
                    ('BOTTOMPADDING', (0,0), (-1,-1), 4),
                ]))
                story.append(single)
        story.append(sp(12))
        story.append(_divider())

    # ── Executive Summary ─────────────────────────────────────────────────────
    story.append(sp(4))
    story.append(Paragraph('Executive Summary', ST['h2']))
    story.append(sp(4))

    if total == 0:
        story.append(Paragraph(_business_summary(summary, verdict_label, total), ST['secure']))
    else:
        story.append(Paragraph(_business_summary(summary, verdict_label, total), ST['body']))
        story.append(sp(6))
        issue_rows = []
        for label, count, color in [
            ('SQL Injection',           sql_count,          DANGER),
            ('SSL/TLS Issue',           1 if ssl_issue else 0, WARN),
            ('HTTP Header Issues',      hdr_count,          INFO),
            ('WordPress Issues',        wp_count,           WARN),
            ('OWASP ZAP Alerts',        zap_count,          DANGER),
            ('Nikto Findings',          nikto_count,        WARN),
            ('XSS Vulnerabilities',     xss_count,          PURPLE),
            ('Technology Exposure',     tech_count,         INFO),
            ('Dependency Advisories',   advisory_count,     DANGER),
            ('Sensitive File Exposure', exposure_count,     WARN),
            ('Hardcoded Secrets',       secrets_count,      DANGER),
            ('Malware Artifacts',       malware_artifact_count, DANGER),
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

    # ── OWASP Top 10 2021 Compliance Table ────────────────────────────────────
    story.append(sp(4))
    story.append(Paragraph('OWASP Top 10 2021 – Coverage Summary', ST['h2']))
    story.append(sp(4))
    story.append(Paragraph(
        'The table below shows which OWASP Top 10 2021 categories were evaluated in this scan '
        'and whether findings were detected.',
        ST['body'],
    ))
    story.append(sp(6))
    story.extend(_owasp_table(owasp_coverage_summary(results), ST))
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
        story.extend(_findings_block(_group_findings(zap_issues), DANGER, ST))
    else:
        story.append(Paragraph('✓  OWASP ZAP found no additional security alerts.', ST['secure']))
    story.append(sp(10))

    # Nikto
    nikto = findings.get('nikto') or results.get('nikto') or {}
    nikto_issues = nikto.get('issues') or []
    nikto_disabled = nikto.get('status') in ('not_run', 'disabled', 'unavailable', None) and not nikto_issues
    story.append(_section_header(
        'Nikto Web Server Scan',
        'Not available' if nikto_disabled else
        (f'{len(nikto_issues)} finding{"s" if len(nikto_issues) != 1 else ""}' if nikto_issues else 'No findings'),
        '—' if nikto_disabled else ('✗' if nikto_issues else '✓'),
        DIM if nikto_disabled else (WARN if nikto_issues else SECURE), ST,
    ))
    story.append(sp(4))
    if nikto_disabled:
        story.append(Paragraph('Nikto was not run in this scan environment.', ST['body']))
    elif nikto_issues:
        story.extend(_findings_block(nikto_issues, WARN, ST))
        story.extend(_recs_block(nikto.get('recommendations') or [], ST))
    else:
        story.append(Paragraph('✓  Nikto found no additional web server findings.', ST['secure']))
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
            status_code = i.get('status_code') or (i.get('verification') or {}).get('http_status')
            content_type = i.get('content_type') or (i.get('verification') or {}).get('content_type')
            confidence = str(i.get('confidence') or (i.get('verification') or {}).get('confidence') or 'unknown').title()
            detection_reason = i.get('detection_reason') or (i.get('verification') or {}).get('detection_reason')
            manual_required = i.get('manual_verification_required')
            if manual_required is None:
                manual_required = (i.get('verification') or {}).get('manual_verification_required')

            # Build structured metadata rows
            meta_rows = [
                [Paragraph('SEVERITY', ST['label']),
                 Paragraph(f'<font color="#{sev_color.hexval()[2:]}">{sev}</font>', ST['body_w'])],
                [Paragraph('URL', ST['label']),
                 Paragraph(issue_url, ST['mono'])],
            ]
            if status_code:
                meta_rows.append([
                    Paragraph('HTTP STATUS', ST['label']),
                    Paragraph(str(status_code), ST['body_w']),
                ])
            if content_type:
                meta_rows.append([
                    Paragraph('CONTENT TYPE', ST['label']),
                    Paragraph(_safe_text(content_type, 120), ST['body_w']),
                ])
            if cl:
                meta_rows.append([
                    Paragraph('SIZE', ST['label']),
                    Paragraph(f'{cl:,} bytes', ST['body_w']),
                ])
            meta_rows.append([
                Paragraph('CONFIDENCE', ST['label']),
                Paragraph(confidence, ST['body_w']),
            ])
            if detection_reason:
                meta_rows.append([
                    Paragraph('WHY FLAGGED', ST['label']),
                    Paragraph(_safe_text(detection_reason, 260), ST['body_w']),
                ])
            meta_rows.append([
                Paragraph('MANUAL VERIFY', ST['label']),
                Paragraph('Yes' if manual_required else 'No', ST['body_w']),
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

    # Hardcoded Secrets & API Keys
    sec_data   = findings.get('secrets') or results.get('secrets') or {}
    sec_issues = sec_data.get('issues') or []
    sec_ran    = bool(sec_data)
    sec_critical = [i for i in sec_issues if i.get('severity') in ('Critical', 'High')]
    story.append(_section_header(
        'Hardcoded Secrets & API Keys',
        'Not run' if not sec_ran else (
            f'{len(sec_issues)} secret{"s" if len(sec_issues) != 1 else ""} detected'
            if sec_issues else 'No hardcoded secrets detected'
        ),
        '—' if not sec_ran else ('✗' if sec_issues else '✓'),
        DIM if not sec_ran else (DANGER if sec_critical else (WARN if sec_issues else SECURE)), ST,
    ))
    story.append(sp(4))
    if not sec_ran:
        story.append(Paragraph('Hardcoded secrets scan was not run.', ST['body']))
    elif sec_issues:
        for i in sec_issues:
            sev = i.get('severity', 'Medium')
            sev_colors = {'Critical': DANGER, 'High': DANGER, 'Medium': WARN, 'Low': INFO}
            sev_color = sev_colors.get(sev, DIM)
            meta_rows = [
                [Paragraph('SEVERITY', ST['label']),
                 Paragraph(f'<font color="#{sev_color.hexval()[2:]}">{sev}</font>', ST['body_w'])],
                [Paragraph('SOURCE', ST['label']),
                 Paragraph(_safe_text(i.get('source') or ''), ST['mono'])],
                [Paragraph('VALUE', ST['label']),
                 Paragraph(_safe_text(i.get('match_redacted') or ''), ST['mono'])],
            ]
            if i.get('line'):
                meta_rows.append([
                    Paragraph('LINE', ST['label']),
                    Paragraph(str(i.get('line')), ST['body_w']),
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
                    f'<b>{_safe_text(i.get("name", "Secret"))}</b>',
                    ParagraphStyle('stitle', fontName='Helvetica-Bold', fontSize=9,
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
        story.extend(_recs_block(sec_data.get('recommendations') or [
            'Remove hardcoded API keys and secrets from client-side code immediately.',
            'Rotate any exposed credentials — treat them as fully compromised.',
            'Use environment variables or a secrets manager (AWS Secrets Manager, HashiCorp Vault).',
            'Add pre-commit hooks (git-secrets, truffleHog) to prevent future leaks.',
        ], ST))
    else:
        story.append(Paragraph('✓  No hardcoded API keys or secrets detected in page source or JavaScript files.', ST['secure']))
    story.append(sp(10))

    # Downloaded Artifact Malware Analysis
    malware_data = findings.get('malware_analysis') or results.get('malware_analysis') or {}
    malware_issues = malware_data.get('issues') or []
    malware_ran = bool(malware_data)
    story.append(_section_header(
        'Downloaded Artifact Malware Analysis',
        'Not run' if not malware_ran else (
            f'{len(malware_issues)} malware-related finding{"s" if len(malware_issues) != 1 else ""}'
            if malware_issues else 'No malware indicators detected'
        ),
        '—' if not malware_ran else ('✗' if malware_issues else '✓'),
        DIM if not malware_ran else (DANGER if malware_issues else SECURE), ST,
    ))
    story.append(sp(4))
    if not malware_ran:
        story.append(Paragraph('Downloaded artifact malware analysis was not run.', ST['body']))
    elif malware_issues:
        story.extend(_findings_block(malware_issues, DANGER, ST))
        story.extend(_recs_block(malware_data.get('recommendations') or [], ST))
    else:
        story.append(Paragraph('✓  No malware indicators were detected in same-origin downloadable artifacts.', ST['secure']))
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

    # SSRF
    ssrf_data   = findings.get('ssrf') or results.get('ssrf') or {}
    ssrf_issues = ssrf_data.get('issues') or []
    ssrf_ran    = bool(ssrf_data) and ssrf_data.get('status') != 'disabled'
    story.append(_section_header(
        'Server-Side Request Forgery (SSRF)',
        'Active checks disabled' if not ssrf_ran else (
            f'{len(ssrf_issues)} issue{"s" if len(ssrf_issues) != 1 else ""} found' if ssrf_issues else 'Pass'
        ),
        '—' if not ssrf_ran else ('✗' if ssrf_issues else '✓'),
        DIM if not ssrf_ran else (DANGER if ssrf_issues else SECURE), ST,
    ))
    story.append(sp(4))
    if not ssrf_ran:
        story.append(Paragraph(
            'SSRF active probing was disabled for this scan. Enable active checks to test for SSRF vulnerabilities.',
            ST['body'],
        ))
    elif ssrf_issues:
        story.extend(_findings_block(ssrf_issues, DANGER, ST))
        story.extend(_recs_block(ssrf_data.get('recommendations') or [], ST))
    else:
        story.append(Paragraph('✓  No SSRF indicators detected in tested parameters.', ST['secure']))
    story.append(sp(10))

    # Logging & Monitoring
    log_data   = findings.get('logging_monitor') or results.get('logging_monitor') or {}
    log_issues = log_data.get('issues') or []
    log_ran    = bool(log_data)
    story.append(_section_header(
        'Security Logging & Monitoring',
        'Not run' if not log_ran else (
            f'{len(log_issues)} issue{"s" if len(log_issues) != 1 else ""} found' if log_issues else 'Pass'
        ),
        '—' if not log_ran else ('✗' if log_issues else '✓'),
        DIM if not log_ran else (WARN if log_issues else SECURE), ST,
    ))
    story.append(sp(4))
    if not log_ran:
        story.append(Paragraph('Logging & monitoring scan was not run.', ST['body']))
    elif log_issues:
        story.extend(_findings_block(log_issues, WARN, ST))
        story.extend(_recs_block(log_data.get('recommendations') or [], ST))
    else:
        story.append(Paragraph('✓  Logging and monitoring signals look healthy.', ST['secure']))
    story.append(sp(10))

    # Authentication Controls
    auth_data   = findings.get('auth') or results.get('auth') or {}
    auth_issues = auth_data.get('issues') or []
    auth_ran    = bool(auth_data)
    story.append(_section_header(
        'Authentication Controls',
        'Not run' if not auth_ran else (
            f'{len(auth_issues)} issue{"s" if len(auth_issues) != 1 else ""} found' if auth_issues else 'Pass'
        ),
        '—' if not auth_ran else ('✗' if auth_issues else '✓'),
        DIM if not auth_ran else (WARN if auth_issues else SECURE), ST,
    ))
    story.append(sp(4))
    if not auth_ran:
        story.append(Paragraph('Authentication controls scan was not run.', ST['body']))
    elif auth_issues:
        story.extend(_findings_block(auth_issues, WARN, ST))
        story.extend(_recs_block(auth_data.get('recommendations') or [], ST))
    else:
        story.append(Paragraph('✓  No authentication control gaps detected.', ST['secure']))
    story.append(sp(10))

    # Software & Data Integrity
    integ_data   = findings.get('integrity') or results.get('integrity') or {}
    integ_issues = integ_data.get('issues') or []
    integ_ran    = bool(integ_data)
    story.append(_section_header(
        'Software & Data Integrity',
        'Not run' if not integ_ran else (
            f'{len(integ_issues)} issue{"s" if len(integ_issues) != 1 else ""} found' if integ_issues else 'Pass'
        ),
        '—' if not integ_ran else ('✗' if integ_issues else '✓'),
        DIM if not integ_ran else (WARN if integ_issues else SECURE), ST,
    ))
    story.append(sp(4))
    if not integ_ran:
        story.append(Paragraph('Software integrity scan was not run.', ST['body']))
    elif integ_issues:
        story.extend(_findings_block(integ_issues, WARN, ST))
        story.extend(_recs_block(integ_data.get('recommendations') or [], ST))
    else:
        story.append(Paragraph('✓  No software integrity gaps detected.', ST['secure']))
    story.append(sp(10))

    # Product Readiness / UX sections
    sections = results.get('sections') or {}
    story.extend(_active_check_summary(results, ST))
    if results.get('scan_config'):
        story.append(sp(8))
    for section_key, color in [
        ('accessibility', INFO),
        ('responsive_ux', WARN),
        ('performance_ux', INFO),
        ('form_usability', WARN),
        ('seo', INFO),
        ('broken_links', WARN),
        ('app_controls', WARN),
        ('exposed_services', DANGER),
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
        story.extend(_technical_evidence_blocks(section_key, results, ST))
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
        step_candidates = [
            (sql_count, 'SQL Injection', 'Migrate to parameterised queries and review all input handling code.'),
            (ssl_issue, 'SSL/TLS', 'Renew or replace the certificate with one from a trusted CA.'),
            (hdr_count, 'HTTP Headers', 'Add missing security headers (CSP, HSTS, X-Frame-Options, etc.).'),
            (wp_count, 'WordPress', 'Update core, themes and plugins; restrict XML-RPC and REST exposure.'),
            (zap_count, 'ZAP Alerts', 'Triage each alert and patch confirmed vulnerabilities.'),
            (nikto_count, 'Nikto Findings', 'Review web server defaults, exposed files, and version-specific Nikto findings.'),
            (xss_count, 'XSS', 'Encode all output and implement a Content-Security-Policy header.'),
            (tech_count, 'Technology Exposure', 'Patch outdated client libraries, disable directory indexes, and reduce version disclosure.'),
            (advisory_count, 'Dependency Risk', 'Upgrade vulnerable packages, review CVE/CWE exposure, and automate dependency scanning in CI/CD.'),
            (exposure_count, 'File Exposure', 'Block sensitive paths in the web server and rotate any exposed credentials.'),
            (secrets_count, 'Public Secret Exposure', 'Remove API keys from public client-side assets, rotate all exposed credentials immediately, and use server-side secret management.'),
            (malware_artifact_count, 'Malware Artifacts', 'Remove suspicious downloads, verify artifact integrity, and only publish signed release files from trusted CI.'),
            (is_mal, 'Malicious Site', 'Investigate server compromise, rotate credentials, and notify users.'),
        ]
        for condition, title, description in step_candidates:
            if condition:
                steps.append((title, description))
        dns_count = summary.get('dns_issue_count', 0)
        redir_count = summary.get('redirect_count', 0)
        take_count = summary.get('takeover_count', 0)
        if dns_count:
            steps.append(('DNS Security', 'Configure SPF (-all), DMARC (p=quarantine or reject), DKIM signing, and CAA records.'))
        if redir_count:
            steps.append(('Open Redirect', 'Validate all redirect targets against a strict server-side allowlist.'))
        if take_count:
            steps.append(('Subdomain Takeover', 'Remove dangling CNAME records and claim or delete unclaimed service deployments.'))

        rows = [[
            Paragraph(f'{i+1}. {t}', ParagraphStyle('st', fontName='Helvetica-Bold', fontSize=9,
                                                       leading=12, textColor=TEXT)),
            Paragraph(desc, ST['body']),
        ] for i, (t, desc) in enumerate(steps)]

        if not rows:
            story.append(Paragraph('No priority remediation steps identified.', ST['body']))
            story.append(sp(12))
        else:
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

    limitations = verdict_data.get('limitations') or []
    if limitations:
        story.append(sp(10))
        story.append(Paragraph('Report Limitations', ST['h2']))
        story.append(sp(4))
        for limitation in limitations:
            story.append(Paragraph(escape(str(limitation)), ST['small']))
            story.append(sp(3))

    story.append(sp(16))

    doc.build(story)
    buffer.seek(0)
    return buffer
