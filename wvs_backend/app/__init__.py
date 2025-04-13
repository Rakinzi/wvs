from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_jwt_extended import JWTManager
from celery import Celery
from flask_cors import CORS

db = SQLAlchemy()
jwt = JWTManager()
celery = Celery('app')

def create_app(config_class='app.config.Config'):
    app = Flask(__name__)
    app.config.from_object(config_class)
    
    # Initialize extensions
    db.init_app(app)
    jwt.init_app(app)
    CORS(app)
    
    # Configure Celery
    celery.conf.update(
        broker_url=app.config['CELERY_BROKER_URL'],
        result_backend=app.config['CELERY_RESULT_BACKEND'],
        task_serializer='json',
        accept_content=['json'],
        result_serializer='json',
        timezone='UTC',
        enable_utc=True,
        broker_connection_retry_on_startup=True,
        imports=('app.tasks',),
    )
    
    # Register blueprints
    from app.routes.scans import bp as scans_bp
    from app.routes.users import bp as users_bp
    from app.routes.malicious import bp as malicious_bp
    from app.routes.dashboard import bp as dashboard_bp
    from app.routes.blocked_access import bp as blocked_access_bp
    
    app.register_blueprint(blocked_access_bp)
    app.register_blueprint(dashboard_bp)
    app.register_blueprint(scans_bp)
    app.register_blueprint(users_bp)
    app.register_blueprint(malicious_bp)

    # Create database tables
    with app.app_context():
        db.create_all()

    return app