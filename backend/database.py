"""SQLite locally; persistent PostgreSQL for Vercel deployments."""
import os
from contextlib import contextmanager
from threading import RLock
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import NullPool

HOSTED = os.getenv("VERCEL") == "1"
DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./accesslease.db")
if DATABASE_URL.startswith("postgres://"):
    DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql+psycopg://", 1)
elif DATABASE_URL.startswith("postgresql://"):
    DATABASE_URL = DATABASE_URL.replace("postgresql://", "postgresql+psycopg://", 1)
if HOSTED and not DATABASE_URL.startswith("postgresql+psycopg://"):
    raise RuntimeError("Set DATABASE_URL to a persistent PostgreSQL connection in Vercel settings")
options = {"connect_args": {"check_same_thread": False}} if DATABASE_URL.startswith("sqlite") else {"poolclass": NullPool, "connect_args": {"connect_timeout": 10}}
engine = create_engine(DATABASE_URL, pool_pre_ping=True, echo=False, **options)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
_local_lock = RLock()

@contextmanager
def write_lock():
    """Serialize governance writes across workers using a PostgreSQL transaction lock."""
    with _local_lock:
        if engine.dialect.name == 'postgresql':
            with engine.begin() as connection:
                connection.execute(text("SELECT pg_advisory_xact_lock(:key)"), {"key": 180018})
                yield
        else:
            yield

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
