# password_audit.py
import re
import bcrypt

def password_strength(password: str):
    score = 0
    issues = []
    if len(password) >= 12:
        score += 2
    elif len(password) >= 8:
        score += 1
    else:
        issues.append('too short (recommend >=8 chars)')
    if re.search(r'[a-z]', password): score += 1
    if re.search(r'[A-Z]', password): score += 1
    if re.search(r'\d', password): score += 1
    if re.search(r'[^A-Za-z0-9]', password): score += 1
    # common words check (simple)
    common = ['password','1234','qwerty','admin']
    lower = password.lower()
    for c in common:
        if c in lower:
            issues.append(f'contains common word: {c}')
    return score, issues

def hash_password(password: str) -> str:
    hashed = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
    return hashed.decode('utf-8')

def verify_password(password: str, hashed: str) -> bool:
    return bcrypt.checkpw(password.encode('utf-8'), hashed.encode('utf-8'))
