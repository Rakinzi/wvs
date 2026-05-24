from app import celery, create_app


flask_app = create_app()
celery_app = celery
