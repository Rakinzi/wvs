from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from celery import Celery

db = SQLAlchemy()
celery = Celery(__name__)

def create_app(config_class='app.config.Config'):
    app = Flask(__name__)
    app.config.from_object(config_class)
    
    # Initialize Celery with app configuration
    celery.conf.update(
        broker_url=app.config['CELERY_BROKER_URL'],
        result_backend=app.config['CELERY_RESULT_BACKEND']
    )
    
    # Initialize SQLAlchemy
    db.init_app(app)
    
    # Register blueprints
    from app.routes.scans import bp as scans_bp
    app.register_blueprint(scans_bp)

    # Create database tables
    with app.app_context():
        db.create_all()

    return app

def make_celery(app=None):
    celery = Celery(
        app.import_name,
        broker=app.config['CELERY_BROKER_URL'],
        backend=app.config['CELERY_RESULT_BACKEND']
    )
    celery.conf.update(app.config)
    return celery