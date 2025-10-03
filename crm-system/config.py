import os
from datetime import timedelta

class Config:
“”“Base configuration”””
SECRET_KEY = os.environ.get(‘SECRET_KEY’) or ‘dev-secret-key-please-change-in-production’
SQLALCHEMY_TRACK_MODIFICATIONS = False

```
# Session configuration
PERMANENT_SESSION_LIFETIME = timedelta(days=7)
SESSION_COOKIE_SECURE = False  # Set to True in production with HTTPS
SESSION_COOKIE_HTTPONLY = True
SESSION_COOKIE_SAMESITE = 'Lax'

# Pagination
ITEMS_PER_PAGE = 25

# File uploads
MAX_CONTENT_LENGTH = 16 * 1024 * 1024  # 16MB max file size
UPLOAD_FOLDER = 'uploads'
ALLOWED_EXTENSIONS = {'pdf', 'doc', 'docx', 'xls', 'xlsx', 'txt', 'png', 'jpg', 'jpeg'}

# Email configuration (if needed later)
MAIL_SERVER = os.environ.get('MAIL_SERVER')
MAIL_PORT = int(os.environ.get('MAIL_PORT') or 587)
MAIL_USE_TLS = os.environ.get('MAIL_USE_TLS', 'true').lower() in ['true', 'on', '1']
MAIL_USERNAME = os.environ.get('MAIL_USERNAME')
MAIL_PASSWORD = os.environ.get('MAIL_PASSWORD')

# Lead scoring weights
LEAD_SCORE_WEIGHTS = {
    'email_opened': 5,
    'email_clicked': 10,
    'website_visit': 3,
    'form_submitted': 15,
    'demo_requested': 25,
    'pricing_page_viewed': 10,
    'engagement_high': 20,
    'company_size_match': 10,
    'industry_match': 5
}

# Opportunity stages
OPPORTUNITY_STAGES = [
    'prospecting',
    'qualification', 
    'proposal',
    'negotiation',
    'closed_won',
    'closed_lost'
]

# Default probability by stage
STAGE_PROBABILITIES = {
    'prospecting': 10,
    'qualification': 25,
    'proposal': 50,
    'negotiation': 75,
    'closed_won': 100,
    'closed_lost': 0
}
```

class DevelopmentConfig(Config):
“”“Development configuration”””
DEBUG = True
SQLALCHEMY_DATABASE_URI = os.environ.get(‘DEV_DATABASE_URL’) or   
‘sqlite:///crm_dev.db’
SQLALCHEMY_ECHO = True  # Log all SQL queries

class ProductionConfig(Config):
“”“Production configuration”””
DEBUG = False
SQLALCHEMY_DATABASE_URI = os.environ.get(‘DATABASE_URL’) or   
‘sqlite:///crm.db’
SESSION_COOKIE_SECURE = True  # Require HTTPS

```
# Additional security headers
SECURITY_HEADERS = {
    'Strict-Transport-Security': 'max-age=31536000; includeSubDomains',
    'X-Content-Type-Options': 'nosniff',
    'X-Frame-Options': 'SAMEORIGIN',
    'X-XSS-Protection': '1; mode=block'
}
```

class TestingConfig(Config):
“”“Testing configuration”””
TESTING = True
SQLALCHEMY_DATABASE_URI = ‘sqlite:///crm_test.db’
WTF_CSRF_ENABLED = False

config = {
‘development’: DevelopmentConfig,
‘production’: ProductionConfig,
‘testing’: TestingConfig,
‘default’: DevelopmentConfig
}