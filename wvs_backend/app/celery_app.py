from app import db, init_celery
from app.config import get_config


def _config_mapping(config: type) -> dict:
    return {
        key: value
        for cls in reversed(config.__mro__)
        for key, value in vars(cls).items()
        if key.isupper()
    }


config = get_config()
config.validate()
db.init_db(config.SQLALCHEMY_DATABASE_URI)
celery_app = init_celery(_config_mapping(config))
