import os
from pathlib import Path
from datetime import timedelta


BASE_DIR = Path(__file__).resolve().parent


class Config:
    SECRET_KEY = os.environ.get("SECRET_KEY", "dev-only-change-me")
    DATABASE = os.environ.get("DATABASE_PATH", str(BASE_DIR / "instance" / "evoting.db"))

    PERMANENT_SESSION_LIFETIME = timedelta(minutes=30)

    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Lax"
    SESSION_COOKIE_SECURE = os.environ.get("COOKIE_SECURE", "0") == "1"
    MAX_CONTENT_LENGTH = 1024 * 1024
    WTF_CSRF_TIME_LIMIT = 3600


class TestConfig(Config):
    TESTING = True
    WTF_CSRF_ENABLED = False
    DATABASE = ":memory:"