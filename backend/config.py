"""
config.py — Single source of truth for all environment variables.
"""

import os
from dotenv import load_dotenv

load_dotenv()

GEMINI_API_KEY    = os.getenv("GEMINI_API_KEY", "")
METASPLOITABLE_IP = os.getenv("METASPLOITABLE_IP", "192.168.56.101")
SQLITE_PATH       = os.getenv("SQLITE_PATH", "./arta.db")
SESSIONS_TMP      = os.getenv("SESSIONS_TMP", "/tmp/arta_sessions")
SANDBOX_DIR       = os.getenv("SANDBOX_DIR", "/tmp/arta_sandbox")
NVD_API_KEY       = os.getenv("NVD_API_KEY", "")         # optional — raises NVD rate limit
EXPLOITDB_CSV     = os.getenv("EXPLOITDB_CSV", "./data/exploitdb.csv")
FRONTEND_URL      = os.getenv("FRONTEND_URL", "http://localhost:3000")
DEMO_MODE         = os.getenv("DEMO_MODE", "false").lower() == "true"
