from __future__ import annotations

import re
from typing import Any

import sqlalchemy as sa
from celery import Celery
from sqlalchemy import create_engine
from sqlalchemy.orm import Query, declarative_base, declared_attr, relationship, scoped_session, sessionmaker

from app.config import get_config


class CompatQuery(Query):
    def first_or_404(self):
        value = self.first()
        if value is None:
            from fastapi import HTTPException
            raise HTTPException(status_code=404, detail="Not found")
        return value


class _QueryDescriptor:
    def __get__(self, obj: Any, owner: type):
        return db.session.query(owner)


class ModelBase:
    query = _QueryDescriptor()

    @declared_attr.directive
    def __tablename__(cls) -> str:
        name = re.sub(r"(?<!^)(?=[A-Z])", "_", cls.__name__).lower()
        return name


class SQLAlchemyCompat:
    Column = sa.Column
    Integer = sa.Integer
    String = sa.String
    Text = sa.Text
    DateTime = sa.DateTime
    Boolean = sa.Boolean
    JSON = sa.JSON
    ForeignKey = sa.ForeignKey
    Index = sa.Index
    func = sa.func
    text = sa.text

    def __init__(self) -> None:
        self.Model = declarative_base(cls=ModelBase)
        self.session = scoped_session(sessionmaker(query_cls=CompatQuery, autoflush=False))
        self.engine = None

    @property
    def metadata(self):
        return self.Model.metadata

    def relationship(self, *args: Any, **kwargs: Any):
        return relationship(*args, **kwargs)

    def backref(self, *args: Any, **kwargs: Any):
        from sqlalchemy.orm import backref
        return backref(*args, **kwargs)

    def init_db(self, database_url: str) -> None:
        self.engine = create_engine(database_url, pool_pre_ping=True, future=True)
        self.session.configure(bind=self.engine)

    def create_all(self) -> None:
        if self.engine is None:
            raise RuntimeError("Database engine is not initialized")
        self.metadata.create_all(self.engine)

    def drop_all(self) -> None:
        if self.engine is None:
            raise RuntimeError("Database engine is not initialized")
        self.metadata.drop_all(self.engine)

    def get_or_404(self, model, ident):
        value = self.session.get(model, ident)
        if value is None:
            from fastapi import HTTPException
            raise HTTPException(status_code=404, detail="Not found")
        return value


class _Limiter:
    """No-op rate limiter shim — real limiting is done at the FastAPI layer."""
    def limit(self, *args, **kwargs):
        def decorator(fn):
            return fn
        return decorator

    def init_app(self, *args, **kwargs):
        pass


db = SQLAlchemyCompat()
celery: Celery | None = None
limiter = _Limiter()


def init_celery(config):
    global celery
    if celery is None:
        celery = Celery("wvs")

    celery.conf.update(
        broker_url=config["CELERY_BROKER_URL"],
        result_backend=config["CELERY_RESULT_BACKEND"],
        task_serializer=config["CELERY_TASK_SERIALIZER"],
        accept_content=config["CELERY_ACCEPT_CONTENT"],
        result_serializer=config["CELERY_RESULT_SERIALIZER"],
        task_track_started=config["CELERY_TASK_TRACK_STARTED"],
        task_time_limit=config["CELERY_TASK_TIME_LIMIT"],
        timezone=config["CELERY_TIMEZONE"],
        enable_utc=True,
        broker_connection_retry_on_startup=config["BROKER_CONNECTION_RETRY_ON_STARTUP"],
        imports=config["CELERY_IMPORTS"],
        beat_schedule=config["CELERY_BEAT_SCHEDULE"],
        task_default_queue=config["SECURITY_SCAN_QUEUE"],
        task_annotations={
            "app.tasks.run_full_scan_job": {"rate_limit": config["UX_SCAN_RATE_LIMIT"]},
        },
    )
    return celery
