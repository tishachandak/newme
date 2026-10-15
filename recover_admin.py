"""Run locally as the installation owner; recovery codes are never exposed by HTTP."""
import argparse
from datetime import datetime, timedelta, timezone
import hashlib
import os
from pathlib import Path
import secrets
import sqlite3
import sys
import webbrowser
from urllib.parse import urlencode

ROOT=Path(__file__).resolve().parent

def issue_local_code(database,username,link=False):
    database=Path(database).resolve()
    if not database.is_file():raise ValueError('Database not found. Start the app first.')
    # mode=rw refuses to create a different, empty database by mistake.
    with sqlite3.connect(database.as_uri()+'?mode=rw',uri=True) as db:
        db.execute('BEGIN IMMEDIATE')
        admin=db.execute('SELECT id FROM admin_accounts WHERE username=?',(username,)).fetchone()
        if not admin:raise ValueError('Administrator username not found (case-sensitive)')
        db.execute('CREATE TABLE IF NOT EXISTS password_recovery (token_hash VARCHAR(64) PRIMARY KEY, admin_id INTEGER NOT NULL REFERENCES admin_accounts(id), expires_at DATETIME NOT NULL)')
        now=datetime.now(timezone.utc).replace(tzinfo=None)
        token=secrets.token_hex(32) if link else f'{secrets.randbelow(1000000):06d}'
        while db.execute('SELECT 1 FROM password_recovery WHERE token_hash=?',(hashlib.sha256(token.encode()).hexdigest(),)).fetchone():
            token=secrets.token_hex(32) if link else f'{secrets.randbelow(1000000):06d}'
        db.execute('CREATE TABLE IF NOT EXISTS recovery_attempts (code_hash VARCHAR(64) PRIMARY KEY, failures INTEGER NOT NULL)')
        db.execute('DELETE FROM recovery_attempts WHERE code_hash IN (SELECT token_hash FROM password_recovery WHERE admin_id=?)',(admin[0],))
        db.execute('DELETE FROM password_recovery WHERE admin_id=?',(admin[0],))
        db.execute('INSERT INTO password_recovery(token_hash,admin_id,expires_at) VALUES (?,?,?)',(hashlib.sha256(token.encode()).hexdigest(),admin[0],(now+timedelta(minutes=15)).isoformat(sep=' ')))
        db.execute('INSERT INTO audit_events(timestamp,actor,action,target_type,target_id,reason) VALUES (?,?,?,?,?,?)',(now.isoformat(sep=' '),'LOCAL_OPERATOR','PASSWORD_RECOVERY_ISSUED','admin',str(admin[0]),'One-time recovery code issued; valid for 15 minutes'))
    return token

def main():
    parser=argparse.ArgumentParser(description='Generate a one-time, 15-minute password recovery code.')
    parser.add_argument('--username');parser.add_argument('--database',help='Explicit local SQLite file; defaults to backend/accesslease.db')
    args=parser.parse_args()
    username=args.username or input('Saved administrator username (case-sensitive): ').strip()
    try:
        url=os.getenv('DATABASE_URL','')
        if url and not args.database:
            # Hosted database operators use an authenticated database connection from their own environment.
            sys.path.insert(0,str(ROOT/'backend'))
            from database import engine,SessionLocal
            from features import PasswordRecovery,RecoveryAttempt,issue_password_recovery
            PasswordRecovery.__table__.create(engine,checkfirst=True)
            RecoveryAttempt.__table__.create(engine,checkfirst=True)
            with SessionLocal() as db:token=issue_password_recovery(db,username,link=True)
        else:
            token=issue_local_code(args.database or ROOT/'backend'/'accesslease.db',username,link=True)
        reset_url='http://127.0.0.1:8000/reset-password#'+urlencode({'token':token})
        webbrowser.open(reset_url)
        print('Private reset page opened in your browser. Enter your new password twice and solve the CAPTCHA.')
        print('Link expires in 15 minutes. Keep the app running. No recovery code needs typing.')
    except Exception:
        print('Unable to issue a code. Check the exact saved username, database path, and environment. No password was changed.')
        return 1
    return 0

if __name__=='__main__':raise SystemExit(main())
