from __future__ import annotations

import re
import uuid

from flask import Blueprint, jsonify, request
from flask_jwt_extended import jwt_required, get_jwt_identity

from app import db, limiter
from app.auth import get_current_user
from app.models import NewsArticle
from app.utils.time_utils import utc_now

bp = Blueprint('news', __name__)


def _slugify(text: str) -> str:
    text = text.lower().strip()
    text = re.sub(r'[^\w\s-]', '', text)
    text = re.sub(r'[\s_-]+', '-', text)
    text = re.sub(r'^-+|-+$', '', text)
    return text[:280]


def _unique_slug(base: str, exclude_id: int | None = None) -> str:
    slug = base
    n = 1
    while True:
        q = NewsArticle.query.filter_by(slug=slug)
        if exclude_id:
            q = q.filter(NewsArticle.id != exclude_id)
        if not q.first():
            return slug
        slug = f"{base}-{n}"
        n += 1


# ── Public endpoints ──────────────────────────────────────────────────────────

@bp.get('/news')
@limiter.limit('120/minute')
def list_articles():
    page = max(1, request.args.get('page', 1, type=int))
    per_page = min(20, max(1, request.args.get('per_page', 12, type=int)))
    category = request.args.get('category')
    severity = request.args.get('severity')
    tag = request.args.get('tag')

    q = NewsArticle.query.filter_by(published=True).order_by(NewsArticle.published_at.desc())
    if category:
        q = q.filter(NewsArticle.category == category)
    if severity:
        q = q.filter(NewsArticle.severity == severity)

    articles = q.all()

    if tag:
        articles = [a for a in articles if tag in (a.tags or [])]

    total = len(articles)
    start = (page - 1) * per_page
    page_items = articles[start:start + per_page]

    return jsonify({
        'data': {
            'articles': [a.to_dict() for a in page_items],
            'total': total,
            'page': page,
            'per_page': per_page,
            'pages': max(1, -(-total // per_page)),
        }
    }), 200


@bp.get('/news/<slug>')
@limiter.limit('120/minute')
def get_article(slug):
    article = NewsArticle.query.filter_by(slug=slug, published=True).first()
    if not article:
        return jsonify({'error': 'Article not found'}), 404
    return jsonify({'data': article.to_dict(body=True)}), 200


# ── Admin endpoints ───────────────────────────────────────────────────────────

@bp.post('/news')
@jwt_required()
@limiter.limit('30/minute')
def create_article():
    current_user = get_current_user()
    if not current_user.is_admin:
        return jsonify({'error': 'Admin access required'}), 403

    body = request.get_json(silent=True) or {}
    title = str(body.get('title') or '').strip()
    if not title:
        return jsonify({'error': 'title is required'}), 422

    summary = str(body.get('summary') or '').strip()
    content = str(body.get('body') or '').strip()
    if not summary or not content:
        return jsonify({'error': 'summary and body are required'}), 422

    slug = _unique_slug(_slugify(str(body.get('slug') or title)))
    published = bool(body.get('published', False))
    published_at = utc_now() if published else None

    article = NewsArticle(
        title=title,
        slug=slug,
        summary=summary,
        body=content,
        category=str(body.get('category') or 'General').strip(),
        tags=body.get('tags') or [],
        severity=body.get('severity') or None,
        cve_ids=body.get('cve_ids') or [],
        source_url=body.get('source_url') or None,
        published=published,
        published_at=published_at,
        author_id=current_user.id,
    )
    db.session.add(article)
    db.session.commit()
    return jsonify({'data': article.to_dict(body=True)}), 201


@bp.patch('/news/<article_id>')
@jwt_required()
@limiter.limit('60/minute')
def update_article(article_id):
    current_user = get_current_user()
    if not current_user.is_admin:
        return jsonify({'error': 'Admin access required'}), 403

    article = NewsArticle.query.filter_by(public_id=article_id).first()
    if not article:
        return jsonify({'error': 'Article not found'}), 404

    body = request.get_json(silent=True) or {}

    if 'title' in body:
        article.title = str(body['title']).strip()
    if 'slug' in body:
        article.slug = _unique_slug(_slugify(str(body['slug'])), exclude_id=article.id)
    if 'summary' in body:
        article.summary = str(body['summary']).strip()
    if 'body' in body:
        article.body = str(body['body']).strip()
    if 'category' in body:
        article.category = str(body['category']).strip()
    if 'tags' in body:
        article.tags = body['tags'] or []
    if 'severity' in body:
        article.severity = body['severity'] or None
    if 'cve_ids' in body:
        article.cve_ids = body['cve_ids'] or []
    if 'source_url' in body:
        article.source_url = body['source_url'] or None
    if 'published' in body:
        was_published = article.published
        article.published = bool(body['published'])
        if article.published and not was_published:
            article.published_at = utc_now()
        elif not article.published:
            article.published_at = None

    db.session.commit()
    return jsonify({'data': article.to_dict(body=True)}), 200


@bp.delete('/news/<article_id>')
@jwt_required()
@limiter.limit('30/minute')
def delete_article(article_id):
    current_user = get_current_user()
    if not current_user.is_admin:
        return jsonify({'error': 'Admin access required'}), 403

    article = NewsArticle.query.filter_by(public_id=article_id).first()
    if not article:
        return jsonify({'error': 'Article not found'}), 404

    db.session.delete(article)
    db.session.commit()
    return jsonify({'message': 'Deleted'}), 200


@bp.get('/news/admin/all')
@jwt_required()
@limiter.limit('60/minute')
def admin_list_all():
    current_user = get_current_user()
    if not current_user.is_admin:
        return jsonify({'error': 'Admin access required'}), 403

    page = max(1, request.args.get('page', 1, type=int))
    per_page = min(50, max(1, request.args.get('per_page', 20, type=int)))

    q = NewsArticle.query.order_by(NewsArticle.created_at.desc())
    total = q.count()
    articles = q.offset((page - 1) * per_page).limit(per_page).all()

    return jsonify({
        'data': {
            'articles': [a.to_dict() for a in articles],
            'total': total,
            'page': page,
            'per_page': per_page,
            'pages': max(1, -(-total // per_page)),
        }
    }), 200
