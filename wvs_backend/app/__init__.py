from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from celery import Celery

db = SQLAlchemy()
celery = Celery()

def create_app(config_class='app.config.Config'):
    app = Flask(__name__)
    app.config.from_object(config_class)

    db.init_app(app)
    celery.conf.update(app.config)

    from app.routes.scans import bp as scans_bp
    app.register_blueprint(scans_bp)

    with app.app_context():
        db.create_all()

    return app

def make_celery(app=None):
    celery = Celery(
        app.import_name,
        backend=app.config['CELERY_RESULT_BACKEND'],
        broker=app.config['CELERY_BROKER_URL']
    )
    celery.conf.update(app.config)
    return celery