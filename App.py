from flask import Flask, request, jsonify, send_file
from flask_cors import CORS
import requests
import base64
import re
import socket
import ssl
import whois
import Levenshtein
from datetime import datetime

app = Flask(__name__, static_folder='.')
CORS(app)

VT_API_KEY = "0138513bb4e381f402a777e264a31a5511b46bea744be5da0e5db790075619656c63d4f5210ac8c1"

FAMOUS_DOMAINS = [
    "google.com", "facebook.com", "paypal.com", "microsoft.com",
    "netflix.com", "amazon.com", "apple.com", "instagram.com"
]

PHISHING_KEYWORDS = [
    "login", "verify", "update", "secure", "account", "banking",
    "confirm", "suspend", "alert", "signin", "password"
]

def extract_domain(url):
    match = re.search(r'https?://([a-zA-Z0-9.-]+)', url)
    return match.group(1) if match else url.split("/")[0]

def extract_ip(domain):
    try:
        return socket.gethostbyname(domain)
    except:
        return None

def check_virustotal(url):
    try:
        url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
        headers = {"x-apikey": VT_API_KEY}
        r = requests.get(f"https://www.virustotal.com/api/v3/urls/{url_id}", headers=headers, timeout=10)
        if r.status_code == 200:
            stats = r.json()['data']['attributes']['last_analysis_stats']
            malicious = stats.get('malicious', 0)
            suspicious = stats.get('suspicious', 0)
            return {"malicious": malicious, "suspicious": suspicious, "total_engines": sum(stats.values()), "flagged": malicious + suspicious}
        return {"malicious": 0, "suspicious": 0, "total_engines": 72, "flagged": 0}
    except:
        return {"malicious": 0, "suspicious": 0, "total_engines": 72, "flagged": 0}

def check_domain_age(domain):
    try:
        w = whois.whois(domain)
        created = w.creation_date
        if isinstance(created, list):
            created = created[0]
        if created:
            age_days = (datetime.now() - created).days
            return {"age_days": age_days, "created": str(created)[:10], "registrar": str(w.registrar or "Unknown")[:50], "country": str(w.country or "Unknown")}
        return {"age_days": 999, "created": "Unknown", "registrar": "Unknown", "country": "Unknown"}
    except:
        return {"age_days": 999, "created": "Unknown", "registrar": "Unknown", "country": "Unknown"}

def check_ssl(domain):
    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.socket(), server_hostname=domain) as conn:
            conn.settimeout(5)
            conn.connect((domain, 443))
            cert = conn.getpeercert()
            expires_str = cert.get('notAfter', '')
            expires = datetime.strptime(expires_str, "%b %d %H:%M:%S %Y %Z") if expires_str else None
            days_left = (expires - datetime.now()).days if expires else 0
            return {"valid": True, "issuer": "Valid SSL", "expires": str(expires)[:10] if expires else "Unknown", "days_left": days_left}
    except:
        return {"valid": False, "issuer": "Invalid/No SSL", "expires": "N/A", "days_left": 0}

def check_redirects(url):
    try:
        headers = {"User-Agent": "Mozilla/5.0"}
        r = requests.get(url, allow_redirects=True, timeout=8, headers=headers)
        chain = [h.url for h in r.history] + [r.url]
        return {"count": len(r.history), "final_url": r.url, "chain": chain[:10]}
    except:
        return {"count": 0, "final_url": url, "chain": [url]}

def check_ip_reputation(domain):
    ip = extract_ip(domain)
    if not ip:
        return {"ip": "Unknown", "abuse_score": 0, "total_reports": 0, "country": "Unknown"}
    return {"ip": ip, "abuse_score": 0, "total_reports": 0, "country": "Unknown"}

def check_typosquatting(domain):
    hits = []
    clean = domain.lower().split(":")[0]
    for famous in FAMOUS_DOMAINS:
        dist = Levenshtein.distance(clean, famous)
        if 0 < dist <= 3:
            hits.append({"target": famous, "distance": dist})
    return hits

def check_keywords(url):
    found = [kw for kw in PHISHING_KEYWORDS if kw in url.lower()]
    return found

def check_https(url):
    return url.startswith("https://")

def calculate_risk(vt, age, ssl_info, redirects, ip_rep, typo, keywords, has_https):
    score = 0
    findings = []

    if vt['flagged'] > 0:
        pts = min(50, 30 + vt['flagged'] * 3)
        score += pts
        findings.append({"module": "VirusTotal", "severity": "critical", "detail": f"{vt['flagged']} engines flagged this URL", "points": pts})

    if age['age_days'] < 30:
        score += 25
        findings.append({"module": "Domain Age", "severity": "critical", "detail": f"Domain is only {age['age_days']} days old", "points": 25})
    elif age['age_days'] < 90:
        score += 15
        findings.append({"module": "Domain Age", "severity": "warning", "detail": f"Domain is {age['age_days']} days old", "points": 15})

    if not ssl_info['valid']:
        score += 20
        findings.append({"module": "SSL Certificate", "severity": "critical", "detail": "SSL certificate invalid", "points": 20})

    if typo:
        pts = 25
        score += pts
        findings.append({"module": "Typosquatting", "severity": "critical", "detail": f"Domain mimics {typo[0]['target']}", "points": pts})

    if not has_https:
        score += 10
        findings.append({"module": "Protocol", "severity": "warning", "detail": "HTTP connection not secure", "points": 10})

    if keywords:
        pts = min(10, len(keywords) * 3)
        score += pts
        findings.append({"module": "Keywords", "severity": "info", "detail": f"Found: {', '.join(keywords[:3])}", "points": pts})

    score = min(score, 100)

    if score >= 75:
        verdict, label = "CRITICAL", "High Risk — Do NOT visit"
    elif score >= 45:
        verdict, label = "WARNING", "Medium Risk — Proceed with caution"
    elif score >= 20:
        verdict, label = "CAUTION", "Low Risk — Verify before visiting"
    else:
        verdict, label = "SAFE", "Likely Safe"

    return {"score": score, "verdict": verdict, "label": label, "findings": findings}

@app.route('/')
def index():
    return send_file('index.html')

@app.route('/scan', methods=['POST'])
def scan():
    try:
        data = request.get_json()
        url = data.get('url', '').strip()
        
        if not url.startswith('http'):
            return jsonify({'error': 'URL must start with http:// or https://'}), 400
        
        domain = extract_domain(url)
        
        vt = check_virustotal(url)
        age = check_domain_age(domain)
        ssl_info = check_ssl(domain)
        redirects = check_redirects(url)
        ip_rep = check_ip_reputation(domain)
        typo = check_typosquatting(domain)
        keywords = check_keywords(url)
        has_https = check_https(url)
        
        risk = calculate_risk(vt, age, ssl_info, redirects, ip_rep, typo, keywords, has_https)
        
        result = {
            'url': url,
            'domain': domain,
            'scanned_at': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            'risk': risk,
            'details': {
                'virustotal': vt,
                'domain_age': age,
                'ssl': ssl_info,
                'redirects': redirects,
                'ip_reputation': ip_rep,
                'typosquatting': typo,
                'keywords': keywords,
                'https': has_https
            }
        }
        
        return jsonify(result)
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    print("\n" + "="*50)
    print("🛡️ PHISHING GUARD PRO STARTING")
    print("="*50)
    print("Open: http://localhost:5000")
    print("="*50 + "\n")
    app.run(debug=True, port=5000)