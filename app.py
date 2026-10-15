"""Vercel entrypoint; the same FastAPI app serves frontend and API."""
from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).resolve().parent / "backend"))
from main import app
