"""reset false malicious flags from weak dnsbl hits

Revision ID: 20260522_0004
Revises: 20260522_0003
Create Date: 2026-05-22 00:30:00
"""

from __future__ import annotations

from alembic import op
import sqlalchemy as sa


revision = "20260522_0004"
down_revision = "20260522_0003"
branch_labels = None
depends_on = None


scan_result_table = sa.table(
    "scan_result",
    sa.column("id", sa.Integer()),
    sa.column("findings", sa.JSON()),
)

scan_job_table = sa.table(
    "scan_job",
    sa.column("id", sa.Integer()),
    sa.column("findings", sa.JSON()),
)

malicious_site_table = sa.table(
    "malicious_site",
    sa.column("id", sa.Integer()),
    sa.column("source", sa.String(length=50)),
    sa.column("reason", sa.String(length=255)),
)


def _is_weak_dnsbl_false_positive(findings: dict | None) -> bool:
    if not isinstance(findings, dict):
        return False

    malicious = findings.get("malicious") or {}
    dnsbl = malicious.get("dnsbl") or {}

    return (
        malicious.get("is_malicious") is True
        and not malicious.get("phishing_match", False)
        and not dnsbl.get("domain_blacklisted", False)
        and dnsbl.get("ip_blacklisted", False)
        and (malicious.get("score") or 0) < 5
    )


def _rewrite_findings(findings: dict | None):
    if not _is_weak_dnsbl_false_positive(findings):
        return findings, False

    from app.utils.scan_helpers import build_scan_sections, build_scan_summary

    rewritten = dict(findings)
    malicious = dict(rewritten.get("malicious") or {})
    dnsbl = dict(malicious.get("dnsbl") or {})

    malicious["is_malicious"] = False
    if dnsbl.get("ip_blacklisted", False):
        malicious["score_reasons"] = [
            "Hosted on IP listed in blacklists"
        ]
        malicious["score"] = min(malicious.get("score") or 0, 2)
    else:
        malicious["score_reasons"] = []
        malicious["score"] = 0

    rewritten["malicious"] = malicious
    rewritten["summary"] = build_scan_summary(rewritten)
    rewritten["sections"] = build_scan_sections(rewritten)
    return rewritten, True


def _rewrite_table(bind, table) -> None:
    rows = bind.execute(sa.select(table.c.id, table.c.findings)).fetchall()
    for row in rows:
        findings = row.findings
        rewritten, changed = _rewrite_findings(findings)
        if changed:
            bind.execute(
                table.update().where(table.c.id == row.id).values(findings=rewritten)
            )


def upgrade():
    bind = op.get_bind()

    bind.execute(
        malicious_site_table.delete().where(
            sa.and_(
                malicious_site_table.c.source == "scan",
                sa.or_(
                    malicious_site_table.c.reason.is_(None),
                    malicious_site_table.c.reason == "",
                    malicious_site_table.c.reason == "Listed in DNS blacklists",
                ),
            )
        )
    )

    _rewrite_table(bind, scan_result_table)
    _rewrite_table(bind, scan_job_table)


def downgrade():
    # Data cleanup cannot be reconstructed automatically.
    pass
