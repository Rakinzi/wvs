from __future__ import annotations

from flask_jwt_extended import get_jwt_identity

from app import db
from app.models import User


def get_current_user() -> User | None:
    identity = get_jwt_identity()
    if identity is None:
        return None

    try:
        user_id = int(identity)
    except (TypeError, ValueError):
        return User.query.filter_by(username=identity).first()

    return db.session.get(User, user_id)
