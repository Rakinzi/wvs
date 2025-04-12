import os
from datetime import timedelta
import urllib.parse

# Encode password with special characters (if needed)
# Replace 'your_root_password' with your actual MySQL root password
root_password = urllib.parse.quote_plus("@Changeme123")

class Config:
    # Database config - Using root user
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL') or f'mysql+pymysql://root:{root_password}@localhost/wvs_scanner'
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    
    # JWT config
    JWT_SECRET_KEY = os.environ.get('JWT_SECRET_KEY') or 'development-jwt-secret'
    JWT_ACCESS_TOKEN_EXPIRES = timedelta(hours=1)
    
    # Celery config
    CELERY_BROKER_URL = os.environ.get('CELERY_BROKER_URL') or 'amqp://guest:guest@localhost:5672//'
    CELERY_RESULT_BACKEND = os.environ.get('CELERY_RESULT_BACKEND') or 'rpc://'
    CELERY_TASK_SERIALIZER = 'json'
    CELERY_RESULT_SERIALIZER = 'json'
    CELERY_ACCEPT_CONTENT = ['json']
    CELERY_TASK_TRACK_STARTED = True
    BROKER_CONNECTION_RETRY_ON_STARTUP = True
    CELERY_TASK_TIME_LIMIT = 30 * 60
    
    # Scanner config
    DNSBL_ENABLED = True
    PHISHING_DB_URL = 'https://raw.githubusercontent.com/mitchellkrogza/Phishing.Database/master/phishing-domains-ACTIVE.txt'
    REPORT_FOLDER = 'reports'
    MAX_SCAN_TIME = 60  # Maximum scan time in seconds
    
    # Security settings
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'development-secret-key'
    
    # Cross-Origin settings
    CORS_HEADERS = 'Content-Type,Authorization'

class DevelopmentConfig(Config):
    DEBUG = True
    
class ProductionConfig(Config):
    DEBUG = False
    
    # Use more secure settings in production
    JWT_COOKIE_SECURE = True
    JWT_ACCESS_TOKEN_EXPIRES = timedelta(minutes=30)
    
    # Use environment variables for all secrets in production
    JWT_SECRET_KEY = os.environ.get('JWT_SECRET_KEY')
    SECRET_KEY = os.environ.get('SECRET_KEY')
    
    # Database URL must be set in environment
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL')
    
    # Redis for production Celery
    CELERY_BROKER_URL = os.environ.get('REDIS_URL')
    CELERY_RESULT_BACKEND = os.environ.get('REDIS_URL')

# Default to development config unless production is explicitly specified
config = ProductionConfig if os.environ.get('FLASK_ENV') == 'production' else DevelopmentConfig