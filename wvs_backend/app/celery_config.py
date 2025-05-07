# app/celery_config.py
from celery.schedules import crontab

# Existing Celery configuration...

# Add periodic task for SSL checks
CELERYBEAT_SCHEDULE = {
    'check-ssl-tls-updates-daily': {
        'task': 'app.tasks.check_ssl_tls_updates',
        'schedule': crontab(hour=3, minute=0),  # Run at 3:00 AM every day
        # You can also use timedelta for simpler scheduling:
        # 'schedule': timedelta(hours=24),
    },
}