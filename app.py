# app.py
from flask import Flask, request, jsonify
from scanner import scan_ports
from http_checker import check_http
from password_audit import password_strength, hash_password, verify_password
from crypto_utils import encrypt_file, decrypt_file
from auth import register_user, login_user, token_required

app = Flask(__name__)
app.config['SECRET_KEY'] = 'replace-with-a-secure-random-value'  # change in production

@app.route('/')
def index():
    return jsonify({"project": "SecureKit", "endpoints": ["/scan_ports","/check_http","/password_audit","/encrypt_file"]})

# Port scanning (authorized use only)
@app.route('/scan_ports', methods=['POST'])
@token_required
def scan_ports_endpoint(current_user):
    payload = request.json or {}
    host = payload.get('host')
    ports = payload.get('ports')  # list or "1-1024"
    if not host:
        return jsonify({"error": "host required"}), 400
    result = scan_ports(host, ports)
    return jsonify(result)

# Basic HTTP checks
@app.route('/check_http', methods=['POST'])
@token_required
def check_http_endpoint(current_user):
    data = request.json or {}
    url = data.get('url')
    if not url:
        return jsonify({"error": "url required"}), 400
    findings = check_http(url)
    return jsonify(findings)

# Password audit example
@app.route('/password_audit', methods=['POST'])
def password_audit_endpoint():
    data = request.json or {}
    pw = data.get('password')
    if not pw:
        return jsonify({"error":"password required"}), 400
    score, issues = password_strength(pw)
    hashed = hash_password(pw)
    return jsonify({"score": score, "issues": issues, "bcrypt_hash": hashed})

# File encrypt/decrypt (small files)
@app.route('/encrypt_file', methods=['POST'])
@token_required
def encrypt_file_endpoint(current_user):
    data = request.json or {}
    plaintext = data.get('text')
    password = data.get('password')
    if not plaintext or not password:
        return jsonify({"error":"text and password required"}), 400
    encrypted = encrypt_file(plaintext.encode('utf-8'), password)
    return jsonify({"ciphertext_hex": encrypted.hex()})

@app.route('/decrypt_file', methods=['POST'])
@token_required
def decrypt_file_endpoint(current_user):
    data = request.json or {}
    ciphertext_hex = data.get('ciphertext_hex')
    password = data.get('password')
    if not ciphertext_hex or not password:
        return jsonify({"error":"ciphertext_hex and password required"}), 400
    try:
        decrypted = decrypt_file(bytes.fromhex(ciphertext_hex), password)
        return jsonify({"plaintext": decrypted.decode('utf-8')})
    except Exception as e:
        return jsonify({"error": str(e)}), 400

# Simple auth endpoints
@app.route('/register', methods=['POST'])
def register():
    data = request.json or {}
    username = data.get('username')
    password = data.get('password')
    if not username or not password:
        return jsonify({"error":"username and password required"}), 400
    ok, msg = register_user(username, password)
    return jsonify({"ok": ok, "msg": msg})

@app.route('/login', methods=['POST'])
def login():
    data = request.json or {}
    username = data.get('username')
    password = data.get('password')
    ok, token_or_msg = login_user(username, password)
    if not ok:
        return jsonify({"error": token_or_msg}), 401
    return jsonify({"token": token_or_msg})

if __name__ == '__main__':
    app.run(debug=True)
