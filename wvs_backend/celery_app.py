from app import create_app, celery

# Create the Flask application instance
flask_app = create_app()

# Update Celery config
celery.conf.update(flask_app.config)

# Define the base task class
class ContextTask(celery.Task):
    abstract = True
    
    def __call__(self, *args, **kwargs):
        with flask_app.app_context():
            return self.run(*args, **kwargs)

# Update the Celery application with the custom task class
celery.Task = ContextTask

# Import tasks AFTER setting up the Celery application
from app.tasks import scan_website