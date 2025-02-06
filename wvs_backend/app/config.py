import os

class Config:
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL') or 'sqlite:///scans.db'
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    CELERY_BROKER_URL = 'amqp://guest:guest@localhost:5672//'
    CELERY_RESULT_BACKEND = 'rpc://'
    CELERY_TASK_SERIALIZER = 'json'
    CELERY_RESULT_SERIALIZER = 'json'
    CELERY_ACCEPT_CONTENT = ['json']
    CELERY_TASK_TRACK_STARTED = True
    BROKER_CONNECTION_RETRY_ON_STARTUP = True
    CELERY_TASK_TIME_LIMIT = 30 * 60
    DNSBL_ENABLED = True
    PHISHING_DB_URL = 'https://raw.githubusercontent.com/mitchellkrogza/Phishing.Database/master/phishing-domains-ACTIVE.txt'
    REPORT_FOLDER = 'reports'