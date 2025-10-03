“””
Data Necromancer - OSINT Threat Intelligence Platform
Module: Configuration Management
File: app/config.py

Enterprise-grade configuration management with validation,
environment variable handling, and security best practices.

Author: Data Necromancer Team
Version: 1.0.0
License: MIT
“””

import os
import secrets
from typing import Optional, List, Dict, Any
from pathlib import Path
from pydantic import (
BaseSettings,
Field,
validator,
PostgresDsn,
EmailStr,
AnyHttpUrl,
SecretStr
)
from pydantic.networks import HttpUrl
from functools import lru_cache
import logging

# Setup module logger

logger = logging.getLogger(**name**)

class SecuritySettings(BaseSettings):
“””
Security-related configuration settings
All sensitive values use SecretStr for secure handling
“””

```
# JWT Configuration
SECRET_KEY: SecretStr = Field(
    default_factory=lambda: SecretStr(secrets.token_urlsafe(32)),
    description="JWT secret key - auto-generated if not provided"
)
ALGORITHM: str = Field(
    default="HS256",
    description="JWT signing algorithm"
)
ACCESS_TOKEN_EXPIRE_MINUTES: int = Field(
    default=30,
    ge=5,
    le=1440,
    description="Access token expiration in minutes"
)
REFRESH_TOKEN_EXPIRE_DAYS: int = Field(
    default=7,
    ge=1,
    le=30,
    description="Refresh token expiration in days"
)

# Password Policy
PASSWORD_MIN_LENGTH: int = Field(default=12, ge=8)
PASSWORD_REQUIRE_UPPERCASE: bool = True
PASSWORD_REQUIRE_LOWERCASE: bool = True
PASSWORD_REQUIRE_NUMBERS: bool = True
PASSWORD_REQUIRE_SPECIAL: bool = True

# Rate Limiting
RATE_LIMIT_PER_MINUTE: int = Field(default=60, ge=1)
RATE_LIMIT_PER_HOUR: int = Field(default=1000, ge=1)

# Encryption
ENCRYPTION_KEY: SecretStr = Field(
    default_factory=lambda: SecretStr(secrets.token_urlsafe(32)),
    description="Fernet encryption key for sensitive data"
)

# API Keys (for external services)
GITHUB_TOKEN: Optional[SecretStr] = Field(
    default=None,
    description="GitHub Personal Access Token"
)
PASTEBIN_API_KEY: Optional[SecretStr] = Field(
    default=None,
    description="Pastebin Pro API key"
)
VIRUSTOTAL_API_KEY: Optional[SecretStr] = Field(
    default=None,
    description="VirusTotal API key"
)
SHODAN_API_KEY: Optional[SecretStr] = Field(
    default=None,
    description="Shodan API key"
)

# CORS Settings
ALLOWED_ORIGINS: List[str] = Field(
    default=["http://localhost:3000", "http://localhost:8000"],
    description="Allowed CORS origins"
)
ALLOWED_METHODS: List[str] = Field(
    default=["GET", "POST", "PUT", "DELETE", "PATCH"],
    description="Allowed HTTP methods"
)

class Config:
    env_prefix = "SECURITY_"
    case_sensitive = True
    env_file = ".env"
    env_file_encoding = "utf-8"
```

class DatabaseSettings(BaseSettings):
“””
Database configuration with PostgreSQL and Redis support
“””

```
# PostgreSQL Configuration
POSTGRES_USER: str = Field(default="datanecromancer")
POSTGRES_PASSWORD: SecretStr = Field(...)
POSTGRES_HOST: str = Field(default="localhost")
POSTGRES_PORT: int = Field(default=5432, ge=1, le=65535)
POSTGRES_DB: str = Field(default="data_necromancer")

# SQLAlchemy Configuration
SQLALCHEMY_DATABASE_URI: Optional[PostgresDsn] = None
SQLALCHEMY_POOL_SIZE: int = Field(default=20, ge=5, le=100)
SQLALCHEMY_MAX_OVERFLOW: int = Field(default=40, ge=10, le=200)
SQLALCHEMY_POOL_TIMEOUT: int = Field(default=30, ge=5, le=120)
SQLALCHEMY_POOL_RECYCLE: int = Field(default=3600, ge=300)
SQLALCHEMY_ECHO: bool = Field(default=False)

# Redis Configuration (for caching and task queue)
REDIS_HOST: str = Field(default="localhost")
REDIS_PORT: int = Field(default=6379, ge=1, le=65535)
REDIS_PASSWORD: Optional[SecretStr] = None
REDIS_DB: int = Field(default=0, ge=0, le=15)
REDIS_URL: Optional[str] = None

# Connection Pool
POOL_PRE_PING: bool = Field(
    default=True,
    description="Test connections before using them"
)

@validator("SQLALCHEMY_DATABASE_URI", pre=True, always=True)
def assemble_db_connection(cls, v: Optional[str], values: Dict[str, Any]) -> str:
    """
    Construct PostgreSQL connection URI from components
    """
    if isinstance(v, str):
        return v
    
    password = values.get("POSTGRES_PASSWORD")
    if password:
        password = password.get_secret_value()
    
    return PostgresDsn.build(
        scheme="postgresql+asyncpg",
        user=values.get("POSTGRES_USER"),
        password=password,
        host=values.get("POSTGRES_HOST"),
        port=str(values.get("POSTGRES_PORT")),
        path=f"/{values.get('POSTGRES_DB') or ''}",
    )

@validator("REDIS_URL", pre=True, always=True)
def assemble_redis_url(cls, v: Optional[str], values: Dict[str, Any]) -> str:
    """
    Construct Redis connection URI
    """
    if isinstance(v, str):
        return v
    
    password = values.get("REDIS_PASSWORD")
    auth = f":{password.get_secret_value()}@" if password else ""
    
    return (
        f"redis://{auth}"
        f"{values.get('REDIS_HOST')}:"
        f"{values.get('REDIS_PORT')}/"
        f"{values.get('REDIS_DB')}"
    )

class Config:
    env_prefix = "DB_"
    case_sensitive = True
    env_file = ".env"
```

class SMTPSettings(BaseSettings):
“””
Email/SMTP configuration for alerts
“””

```
SMTP_HOST: str = Field(default="smtp.gmail.com")
SMTP_PORT: int = Field(default=587, ge=1, le=65535)
SMTP_USER: EmailStr = Field(...)
SMTP_PASSWORD: SecretStr = Field(...)
SMTP_USE_TLS: bool = Field(default=True)
SMTP_USE_SSL: bool = Field(default=False)

# Email Settings
EMAIL_FROM: EmailStr = Field(...)
EMAIL_FROM_NAME: str = Field(default="Data Necromancer Alerts")
ALERT_RECIPIENTS: List[EmailStr] = Field(default_factory=list)

# Email Templates
EMAIL_TEMPLATES_DIR: Path = Field(
    default=Path(__file__).parent / "templates" / "emails"
)

class Config:
    env_prefix = "SMTP_"
    env_file = ".env"
```

class AlertSettings(BaseSettings):
“””
Alert and notification configuration
“””

```
# Slack Integration
SLACK_ENABLED: bool = Field(default=False)
SLACK_WEBHOOK_URL: Optional[HttpUrl] = None
SLACK_CHANNEL: str = Field(default="#security-alerts")

# Discord Integration
DISCORD_ENABLED: bool = Field(default=False)
DISCORD_WEBHOOK_URL: Optional[HttpUrl] = None

# Telegram Integration
TELEGRAM_ENABLED: bool = Field(default=False)
TELEGRAM_BOT_TOKEN: Optional[SecretStr] = None
TELEGRAM_CHAT_ID: Optional[str] = None

# Alert Thresholds
ALERT_MIN_SEVERITY: str = Field(
    default="medium",
    regex="^(low|medium|high|critical)$"
)
ALERT_COOLDOWN_MINUTES: int = Field(default=60, ge=1)
ALERT_MAX_PER_HOUR: int = Field(default=50, ge=1)

class Config:
    env_prefix = "ALERT_"
    env_file = ".env"
```

class ScanningSettings(BaseSettings):
“””
Scanning and monitoring configuration
“””

```
# Rate Limiting for External APIs
API_RATE_LIMIT_DELAY: float = Field(
    default=1.0,
    ge=0.1,
    description="Seconds between API requests"
)
REQUEST_TIMEOUT: int = Field(default=30, ge=5, le=120)
MAX_RETRIES: int = Field(default=3, ge=0, le=10)
RETRY_BACKOFF_FACTOR: float = Field(default=2.0, ge=1.0)

# Concurrent Scanning
MAX_CONCURRENT_SCANS: int = Field(default=5, ge=1, le=20)
MAX_WORKERS: int = Field(default=10, ge=1, le=50)

# URL Discovery
URL_DISCOVERY_MAX_DEPTH: int = Field(default=3, ge=1, le=10)
URL_DISCOVERY_MAX_URLS: int = Field(default=1000, ge=10)

# Pastebin Monitoring
PASTEBIN_CHECK_INTERVAL_MINUTES: int = Field(default=15, ge=5)
PASTEBIN_MAX_RESULTS: int = Field(default=100, ge=10)

# GitHub Scanning
GITHUB_MAX_RESULTS_PER_QUERY: int = Field(default=100, ge=10, le=1000)
GITHUB_SCAN_PRIVATE_REPOS: bool = Field(default=False)

# Results Retention
RESULTS_RETENTION_DAYS: int = Field(default=90, ge=7)
ARCHIVE_OLD_RESULTS: bool = Field(default=True)

class Config:
    env_prefix = "SCAN_"
    env_file = ".env"
```

class ApplicationSettings(BaseSettings):
“””
Main application configuration
“””

```
# Application Metadata
APP_NAME: str = Field(default="Data Necromancer")
APP_VERSION: str = Field(default="1.0.0")
APP_DESCRIPTION: str = Field(
    default="Enterprise OSINT Threat Intelligence Platform"
)

# Environment
ENVIRONMENT: str = Field(
    default="development",
    regex="^(development|staging|production)$"
)
DEBUG: bool = Field(default=False)
TESTING: bool = Field(default=False)

# API Configuration
API_V1_PREFIX: str = Field(default="/api/v1")
API_HOST: str = Field(default="0.0.0.0")
API_PORT: int = Field(default=8000, ge=1024, le=65535)
API_WORKERS: int = Field(default=4, ge=1, le=16)

# Logging
LOG_LEVEL: str = Field(
    default="INFO",
    regex="^(DEBUG|INFO|WARNING|ERROR|CRITICAL)$"
)
LOG_FILE: Path = Field(default=Path("logs/data_necromancer.log"))
LOG_MAX_BYTES: int = Field(default=10485760)  # 10MB
LOG_BACKUP_COUNT: int = Field(default=5)
LOG_FORMAT: str = Field(
    default="%(asctime)s - %(name)s - %(levelname)s - [%(filename)s:%(lineno)d] - %(message)s"
)

# File Storage
UPLOAD_DIR: Path = Field(default=Path("uploads"))
MAX_UPLOAD_SIZE: int = Field(default=10485760)  # 10MB
ALLOWED_EXTENSIONS: List[str] = Field(
    default=[".txt", ".csv", ".json", ".xml"]
)

# Pagination
DEFAULT_PAGE_SIZE: int = Field(default=50, ge=10, le=500)
MAX_PAGE_SIZE: int = Field(default=1000, ge=100)

# Session
SESSION_COOKIE_NAME: str = Field(default="data_necromancer_session")
SESSION_COOKIE_SECURE: bool = Field(default=True)
SESSION_COOKIE_HTTPONLY: bool = Field(default=True)
SESSION_COOKIE_SAMESITE: str = Field(default="lax")

@validator("LOG_FILE", "UPLOAD_DIR", pre=True, always=True)
def create_directories(cls, v: Path) -> Path:
    """
    Ensure directories exist
    """
    if isinstance(v, str):
        v = Path(v)
    v.parent.mkdir(parents=True, exist_ok=True)
    return v

@property
def is_production(self) -> bool:
    """Check if running in production"""
    return self.ENVIRONMENT == "production"

@property
def is_development(self) -> bool:
    """Check if running in development"""
    return self.ENVIRONMENT == "development"

class Config:
    env_prefix = "APP_"
    env_file = ".env"
    case_sensitive = True
```

class Settings(BaseSettings):
“””
Master settings class combining all configuration sections
“””

```
# Sub-configurations
app: ApplicationSettings = Field(default_factory=ApplicationSettings)
security: SecuritySettings = Field(default_factory=SecuritySettings)
database: DatabaseSettings = Field(default_factory=DatabaseSettings)
smtp: SMTPSettings = Field(default_factory=SMTPSettings)
alerts: AlertSettings = Field(default_factory=AlertSettings)
scanning: ScanningSettings = Field(default_factory=ScanningSettings)

class Config:
    env_file = ".env"
    env_file_encoding = "utf-8"
    case_sensitive = True

def validate_all(self) -> bool:
    """
    Validate all configuration settings
    
    Returns:
        True if all settings are valid
        
    Raises:
        ValueError: If any settings are invalid
    """
    try:
        # Validate database connection can be built
        if not self.database.SQLALCHEMY_DATABASE_URI:
            raise ValueError("Database URI could not be constructed")
        
        # Validate Redis connection
        if not self.database.REDIS_URL:
            raise ValueError("Redis URL could not be constructed")
        
        # Validate critical paths exist
        if not self.app.LOG_FILE.parent.exists():
            raise ValueError(f"Log directory does not exist: {self.app.LOG_FILE.parent}")
        
        # Validate production requirements
        if self.app.is_production:
            if self.app.DEBUG:
                raise ValueError("DEBUG must be False in production")
            if not self.app.SESSION_COOKIE_SECURE:
                raise ValueError("SESSION_COOKIE_SECURE must be True in production")
        
        logger.info("All configuration settings validated successfully")
        return True
        
    except Exception as e:
        logger.error(f"Configuration validation failed: {str(e)}")
        raise

def get_secret_value(self, key: str) -> Optional[str]:
    """
    Safely retrieve secret value
    
    Args:
        key: Secret key name
        
    Returns:
        Decrypted secret value or None
    """
    try:
        value = getattr(self.security, key, None)
        if value and hasattr(value, 'get_secret_value'):
            return value.get_secret_value()
        return value
    except Exception as e:
        logger.error(f"Error retrieving secret {key}: {str(e)}")
        return None
```

@lru_cache()
def get_settings() -> Settings:
“””
Get cached settings instance
This function is cached to ensure settings are loaded only once

```
Returns:
    Settings instance
"""
logger.info("Loading application settings...")
settings = Settings()
settings.validate_all()
logger.info(f"Settings loaded successfully for environment: {settings.app.ENVIRONMENT}")
return settings
```

# Export settings instance

settings = get_settings()

if **name** == “**main**”:
# Test configuration loading
print(f”Application: {settings.app.APP_NAME} v{settings.app.APP_VERSION}”)
print(f”Environment: {settings.app.ENVIRONMENT}”)
print(f”Debug Mode: {settings.app.DEBUG}”)
print(f”Database: {settings.database.POSTGRES_DB}@{settings.database.POSTGRES_HOST}”)
print(f”API: {settings.app.API_HOST}:{settings.app.API_PORT}”)
print(“✅ Configuration loaded successfully!”)