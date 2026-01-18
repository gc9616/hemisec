"""
Configuration settings for the Notes API
"""

import os

class Config:
    """Base configuration"""
    
    # Security
    JWT_SECRET_KEY = os.environ.get('JWT_SECRET_KEY', None)  # Must be set in production
    JWT_TOKEN_EXPIRY_HOURS = 24
    
    # Biometric settings
    BIOMETRIC_THRESHOLD = float(os.environ.get('BIOMETRIC_THRESHOLD', '0.85'))
    
    # Database
    DATABASE_PATH = os.path.join(os.path.dirname(__file__), 'notes_app.db')
    
    # Argon2 parameters (high security)
    ARGON2_TIME_COST = 3      # Number of iterations
    ARGON2_MEMORY_COST = 65536  # 64 MB
    ARGON2_PARALLELISM = 4    # Number of threads
    ARGON2_HASH_LEN = 32      # Hash length in bytes
    ARGON2_SALT_LEN = 16      # Salt length in bytes
    
    # Input validation
    MAX_USERNAME_LENGTH = 50
    MIN_USERNAME_LENGTH = 3
    MIN_PASSWORD_LENGTH = 8
    MAX_NOTE_TITLE_LENGTH = 200
    MAX_NOTE_CONTENT_LENGTH = 50000
    
    # CORS settings
    CORS_ORIGINS = os.environ.get('CORS_ORIGINS', '*').split(',')
    
    # Flask settings
    FLASK_HOST = os.environ.get('FLASK_HOST', '0.0.0.0')
    FLASK_PORT = int(os.environ.get('FLASK_PORT', '8080'))
    FLASK_DEBUG = os.environ.get('FLASK_DEBUG', 'False').lower() == 'true'


class DevelopmentConfig(Config):
    """Development configuration"""
    FLASK_DEBUG = True
    

class ProductionConfig(Config):
    """Production configuration"""
    FLASK_DEBUG = False
    

# Configuration dictionary
config = {
    'development': DevelopmentConfig,
    'production': ProductionConfig,
    'default': DevelopmentConfig
}
