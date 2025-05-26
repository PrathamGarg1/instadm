import os
from dotenv import load_dotenv

load_dotenv()

class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'dev-secret-key'
    UPLOAD_FOLDER = 'uploads'
    MAX_CONTENT_LENGTH = 16 * 1024 * 1024  # 16MB
    
    # Lemon Squeezy Configuration
    LEMON_SQUEEZY_API_KEY = os.environ.get('LEMON_SQUEEZY_API_KEY')
    LEMON_SQUEEZY_STORE_ID = os.environ.get('LEMON_SQUEEZY_STORE_ID')
    LEMON_SQUEEZY_VARIANT_ID = os.environ.get('LEMON_SQUEEZY_VARIANT_ID')
    LEMON_SQUEEZY_WEBHOOK_SECRET = os.environ.get('LEMON_SQUEEZY_WEBHOOK_SECRET')
    
    # Database
    DATABASE_URL = os.environ.get('DATABASE_URL') or 'sqlite:///app.db'

class ProductionConfig(Config):
    DEBUG = False
    TESTING = False

class DevelopmentConfig(Config):
    DEBUG = True
    TESTING = False

class TestingConfig(Config):
    DEBUG = True
    TESTING = True
    DATABASE_URL = 'sqlite:///test.db'

config = {
    'development': DevelopmentConfig,
    'production': ProductionConfig,
    'testing': TestingConfig,
    'default': DevelopmentConfig
}
