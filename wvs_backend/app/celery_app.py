# app/celery_app.py
from flask import Flask
from celery import Celery
from datetime import timedelta

def create_celery_app(app=None):
    """
    Create a new Celery app and tie it to the Flask app's configuration.
    
    Args:
        app (Flask, optional): The Flask application. Defaults to None.
    
    Returns:
        Celery: The configured Celery app.
    """
    app = app or create_app()
    
    celery = Celery(
        app.import_name,
        broker=app.config['CELERY_BROKER_URL'],
        backend=app.config['CELERY_RESULT_BACKEND'],
        include=['app.tasks.ssl_checks'],
    )
    
    # Use the Flask app's configuration as the Celery configuration
    celery.conf.update(app.config.get('CELERY', {}))
    
    class ContextTask(celery.Task):
        """Make celery tasks work with Flask app context"""
        def __call__(self, *args, **kwargs):
            with app.app_context():
                return self.run(*args, **kwargs)
    
    celery.Task = ContextTask
    return celery

def create_app():
    """Create and configure the Flask app."""
    app = Flask(__name__)
    
    # Load the default configuration
    app.config.from_object('app.config.Config')
    
    # Load environment specific configuration
    app.config.from_envvar('APP_CONFIG_FILE', silent=True)
    
    # Ensure CELERY configuration exists
    if 'CELERY' not in app.config:
        app.config['CELERY'] = {
            'broker_url': 'amqp://guest:guest@localhost:5672//',
            'result_backend': 'rpc://',
            'imports': ['app.tasks.ssl_checks'],
            'beat_schedule': {
                'check-ssl-tls-updates-daily': {
                    'task': 'app.tasks.check_ssl_tls_updates',
                    'schedule': timedelta(hours=24),
                },
            },
        }
    
    return app

# Create the celery app
celery_app = create_celery_app()