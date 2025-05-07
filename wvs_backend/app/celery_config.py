# app/celery_config.py
from celery.schedules import timedelta

# Basic Celery configuration with RabbitMQ
broker_url = 'amqp://guest:guest@localhost:5672//'
result_backend = 'rpc://'  # Using RPC backend with RabbitMQ
task_serializer = 'json'
accept_content = ['json']
result_serializer = 'json'
enable_utc = True
timezone = 'UTC'

# Define periodic tasks
beat_schedule = {
    'check-ssl-tls-updates-daily': {
        'task': 'app.tasks.check_ssl_tls_updates',
        'schedule': timedelta(hours=24),  # Run every 24 hours
        'options': {
            'expires': 3600,  # Task expires after 1 hour
        },
    },
}

# Default task settings
task_default_queue = 'default'