# auth.py
import bcrypt
import time
from functools import wraps
from flask import request, jsonify

# NOTE: in-memory store for demo only
USERS = {}
TOKENS = {}

def register_user(username: str, password: str):
    if username in USERS:
        return False, "user exists"
    hashed = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
    USERS[username] = hashed
    return True, "registered"

def login_user(username: str, password: str):
    h = USERS.get(username)
    if not h: return False, "user not found"
    if not bcrypt.checkpw(password.encode('utf-8'), h):
        return False, "invalid password"
    # simplistic token: not JWT; for demo only
    token = f"token-{username}-{int(time.time())}"
    TOKENS[token] = username
    return True, token

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        if 'Authorization' in request.headers:
            token = request.headers.get('Authorization').split()[-1]
        if not token:
            return jsonify({"error":"token missing"}), 401
        user = TOKENS.get(token)
        if not user:
            return jsonify({"error":"invalid token"}), 401
        return f(user, *args, **kwargs)
    return decorated
