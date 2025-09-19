# http_checker.py
import requests

def check_http(url: str) -> dict:
    findings = {}
    try:
        r = requests.get(url, timeout=8, allow_redirects=True)
        headers = {k.lower(): v for k, v in r.headers.items()}
        findings['status_code'] = r.status_code
        findings['server'] = headers.get('server')
        # insecure headers checks
        findings['x_frame_options'] = headers.get('x-frame-options')
        findings['content_security_policy'] = headers.get('content-security-policy')
        findings['strict_transport_security'] = headers.get('strict-transport-security')
        findings['cookies'] = r.cookies.get_dict()
        # simple heuristics
        issues = []
        if not headers.get('strict-transport-security'):
            issues.append('HSTS missing (Strict-Transport-Security header)')
        if not headers.get('content-security-policy'):
            issues.append('CSP missing')
        if not headers.get('x-frame-options'):
            issues.append('X-Frame-Options missing (clickjacking risk)')
        findings['issues'] = issues
    except Exception as e:
        findings['error'] = str(e)
    return findings
