#!/usr/bin/env python3
"""
RPAL Exploration Permit Portal
RNG-EXT-01 SETU DVAAR OPERATION DEEPSTRIKE
"""
from flask import (Flask, request, jsonify, render_template_string,
                   redirect, url_for, make_response)
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding as asym_padding
from cryptography.hazmat.backends import default_backend
import sqlite3, hashlib, logging, os, json, base64, hmac, time, functools, sys

app = Flask(__name__)
app.secret_key = os.urandom(32)

DB_PATH       = os.environ.get('DB_PATH',        '/var/lib/rpal/permit-portal/permits.db')
PRIV_KEY_PATH = os.environ.get('JWT_PRIVATE_KEY', '/etc/rpal/jwt/private.pem')
PUB_KEY_PATH  = os.environ.get('JWT_PUBLIC_KEY',  '/etc/rpal/jwt/public.pem')
PORT          = int(os.environ.get('PORT', 8443))
JWT_ISSUER    = 'https://permit.rpal.in'

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s %(levelname)s %(message)s',
    stream=sys.stderr
)

with open(PRIV_KEY_PATH, 'rb') as _f:
    _priv_pem   = _f.read()
    PRIVATE_KEY = serialization.load_pem_private_key(_priv_pem, password=None, backend=default_backend())

with open(PUB_KEY_PATH, 'rb') as _f:
    PUBLIC_KEY_PEM = _f.read()
    PUBLIC_KEY     = serialization.load_pem_public_key(PUBLIC_KEY_PEM, backend=default_backend())

def _b64u_enc(data):
    if isinstance(data, str):
        data = data.encode()
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode()

def _b64u_dec(s):
    s += '=' * (4 - len(s) % 4)
    return base64.urlsafe_b64decode(s)

def _b64u_int(n):
    length = (n.bit_length() + 7) // 8
    return _b64u_enc(n.to_bytes(length, 'big'))

def issue_token(username, role):
    now = int(time.time())
    hdr = json.dumps({"alg":"RS256","typ":"JWT","kid":"rpal-permit-2024-v1"}, separators=(',',':')).encode()
    pay = json.dumps({"iss":JWT_ISSUER,"sub":username,"role":role,
                      "iat":now,"exp":now+28800,"jti":_b64u_enc(os.urandom(12))},
                     separators=(',',':')).encode()
    si  = (_b64u_enc(hdr) + '.' + _b64u_enc(pay)).encode()
    sig = PRIVATE_KEY.sign(si, asym_padding.PKCS1v15(), hashes.SHA256())
    logging.info('TOKEN_ISSUED sub=%s role=%s', username, role)
    return _b64u_enc(hdr) + '.' + _b64u_enc(pay) + '.' + _b64u_enc(sig)

def verify_token(token):
    try:
        parts = token.split('.')
        if len(parts) != 3:
            return None
        hdr_b64, pay_b64, sig_b64 = parts
        header = json.loads(_b64u_dec(hdr_b64))
        alg    = header.get('alg', '')
        if alg not in ('RS256', 'HS256'):
            return None
        si  = (hdr_b64 + '.' + pay_b64).encode()
        sig = _b64u_dec(sig_b64)
        if alg == 'RS256':
            try:
                PUBLIC_KEY.verify(sig, si, asym_padding.PKCS1v15(), hashes.SHA256())
            except Exception:
                return None
        else:  # HS256 — VULNERABLE PATH
            expected = hmac.new(PUBLIC_KEY_PEM, si, hashlib.sha256).digest()
            if not hmac.compare_digest(sig, expected):
                return None
        claims = json.loads(_b64u_dec(pay_b64))
        if claims.get('exp', 0) < int(time.time()):
            return None
        return claims
    except Exception as exc:
        logging.warning('verify_token error: %s', exc)
        return None

def require_jwt(roles=None):
    def decorator(f):
        @functools.wraps(f)
        def wrapper(*args, **kwargs):
            token = None
            auth = request.headers.get('Authorization', '')
            if auth.startswith('Bearer '):
                token = auth[7:]
            elif 'rpal_token' in request.cookies:
                token = request.cookies['rpal_token']
            if not token:
                if request.path.startswith('/api/'):
                    return jsonify({'error': 'Authentication required'}), 401
                return redirect(url_for('login'))
            claims = verify_token(token)
            if not claims:
                if request.path.startswith('/api/'):
                    return jsonify({'error': 'Invalid or expired token'}), 401
                return redirect(url_for('login'))
            if roles and claims.get('role') not in roles:
                if request.path.startswith('/api/'):
                    return jsonify({'error': 'Insufficient privileges'}), 403
                return render_template_string(ERR_HTML, msg='Insufficient privileges'), 403
            request.jwt_claims = claims
            return f(*args, **kwargs)
        return wrapper
    return decorator

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def _hp(p):
    return hashlib.sha256(p.encode()).hexdigest()

def get_jwk():
    n = PUBLIC_KEY.public_numbers()
    return {"kty":"RSA","use":"sig","kid":"rpal-permit-2024-v1","alg":"RS256",
            "n":_b64u_int(n.n),"e":_b64u_int(n.e)}

_B = "background"; _C = "#0a1628"; _N2 = "#0f1e38"; _BL = "#1a56c4"; _GD = "#c9922a"
_TX = "#e8edf5"; _T2 = "#94a3b8"; _T3 = "#64748b"; _BR = "#1e3a5f"

_BASE_CSS = """*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
:root{--navy:#0a1628;--navy2:#0f1e38;--blue:#1a56c4;--blue2:#2d7aee;--blue3:#5ba3f5;
--gold:#c9922a;--text:#e8edf5;--t2:#94a3b8;--t3:#64748b;--br:#1e3a5f;
--sans:-apple-system,BlinkMacSystemFont,"Segoe UI",Arial,sans-serif;
--mono:"SF Mono",Consolas,"Liberation Mono",monospace}
body{background:var(--navy);color:var(--text);font-family:var(--sans);min-height:100vh;-webkit-font-smoothing:antialiased}
.gov-ribbon{background:linear-gradient(90deg,#ff9933 0 33%,#fff 33% 66%,#138808 66% 100%);height:6px;border-bottom:2px solid var(--gold)}
.topbar{background:var(--navy2);border-bottom:1px solid var(--br);padding:0 32px;height:60px;display:flex;align-items:center;justify-content:space-between}
.tb-brand{display:flex;align-items:center;gap:14px}
.wheel{width:40px;height:40px;border:2px solid var(--gold);border-radius:50%;display:flex;align-items:center;justify-content:center;font-size:18px;color:var(--gold)}
.org-name{font-size:14px;font-weight:700}.org-sub{font-size:10px;color:var(--t3);font-family:var(--mono)}
.nav{display:flex;gap:6px;align-items:center}
.nav a{font-size:13px;color:var(--t2);text-decoration:none;padding:7px 14px;border-radius:6px}
.nav a:hover{background:rgba(255,255,255,.05);color:var(--text)}
.btn-nav{background:var(--blue);color:#fff;padding:9px 20px;border-radius:6px;font-size:13px;font-weight:600;text-decoration:none}"""

IDX_HTML = """<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8">
<title>RPAL Exploration Permit Portal</title><style>""" + _BASE_CSS + """
.hero{padding:72px 40px;max-width:1100px;margin:0 auto}
.tag{font-family:var(--mono);font-size:11px;color:var(--gold);text-transform:uppercase;letter-spacing:1.5px;margin-bottom:16px}
.h1{font-size:40px;font-weight:800;line-height:1.15;max-width:700px;margin-bottom:14px}
.sub{font-size:15px;color:var(--t2);line-height:1.7;max-width:620px;margin-bottom:36px}
.btns{display:flex;gap:14px}
.bp{background:var(--blue);color:#fff;padding:13px 28px;border-radius:8px;font-size:14px;font-weight:700;text-decoration:none}
.bs{background:transparent;color:var(--t2);padding:13px 28px;border-radius:8px;font-size:14px;font-weight:600;text-decoration:none;border:1.5px solid var(--br)}
.grid{max-width:1100px;margin:0 auto;padding:0 40px 56px;display:grid;grid-template-columns:repeat(3,1fr);gap:18px}
.card{background:rgba(15,30,56,.6);border:1px solid var(--br);border-radius:10px;padding:22px}
.ci{font-size:24px;margin-bottom:10px}.ct{font-size:14px;font-weight:700;margin-bottom:7px}
.cd{font-size:13px;color:var(--t2);line-height:1.6}
.notice{max-width:1100px;margin:0 auto;padding:0 40px 40px}
.nb{background:rgba(201,146,42,.07);border:1px solid rgba(201,146,42,.2);border-radius:8px;padding:14px 20px;font-size:12px;color:var(--gold);font-family:var(--mono);line-height:1.6}
.footer{border-top:1px solid var(--br);padding:16px 40px;display:flex;justify-content:space-between;font-size:11px;color:var(--t3);font-family:var(--mono)}
</style></head><body>
<div class="gov-ribbon"></div>
<div class="topbar"><div class="tb-brand"><div class="wheel">&#9955;</div>
  <div><div class="org-name">Rashtriya Petroleum Anveshan Limited</div>
  <div class="org-sub">Ministry of Petroleum &amp; Natural Gas, GoI</div></div></div>
<nav class="nav"><a href="#">About</a><a href="#">Public Notices</a><a href="#">DGH Portal</a>
  <a class="btn-nav" href="/login">Sign In &rarr;</a></nav></div>
<div class="hero">
  <div class="tag">URJA DRISHTI 2.0 &middot; Digital Exploration Platform</div>
  <div class="h1">Exploration Permit &amp; Licensing Management System</div>
  <div class="sub">Unified digital platform for petroleum exploration permit management,
    Petroleum Mining Lease tracking, and block allocation under HELP/OALP/NELP frameworks.
    Integrated with DGH regulatory systems.</div>
  <div class="btns">
    <a class="bp" href="/login">Applicant Sign In &rarr;</a>
    <a class="bs" href="https://www.dghindia.gov.in">DGH Regulatory Portal</a>
  </div>
</div>
<div class="grid">
  <div class="card"><div class="ci">&#128506;</div><div class="ct">Block GIS Viewer</div>
    <div class="cd">Interactive geospatial viewer for exploration blocks across KG Basin, Mumbai Offshore, Rajasthan and Assam-Arakan sedimentary basins.</div></div>
  <div class="card"><div class="ci">&#128203;</div><div class="ct">PML Lifecycle Management</div>
    <div class="cd">End-to-end Petroleum Mining Lease management from initial application through DGH approval, renewal, and relinquishment.</div></div>
  <div class="card"><div class="ci">&#128279;</div><div class="ct">DGH Integration</div>
    <div class="cd">Real-time integration with Directorate General of Hydrocarbons licensing database for permit status synchronisation and block allocation tracking.</div></div>
</div>
<div class="notice"><div class="nb">&#9888; This portal is for authorised RPAL personnel, DGH officials, and pre-approved exploration contractors only. Unauthorised access is a criminal offence under the IT Act 2000.</div></div>
<!-- TODO(arjun.mehta): DEVOPS-1089 - remove dev-notes.txt from docs dir before DGH go-live. Flagged in sprint review 2024-11-08. -->
<div class="footer"><span>&copy; 2024 Rashtriya Petroleum Anveshan Limited</span><span>permit.rpal.in &middot; URJA DRISHTI 2.0 &middot; v2.4.1</span></div>
</body></html>"""

LOGIN_HTML = """<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8">
<title>Sign In - RPAL Permit Portal</title><style>""" + _BASE_CSS + """
body{display:flex;flex-direction:column}
.wrap{flex:1;display:flex}
.left{flex:1;padding:72px 60px;display:flex;flex-direction:column;justify-content:center;border-right:1px solid var(--br)}
.right{width:480px;display:flex;align-items:center;justify-content:center;padding:60px 48px;background:var(--navy2)}
.srv-lbl{font-family:var(--mono);font-size:10px;font-weight:700;color:var(--gold);text-transform:uppercase;letter-spacing:1.5px;margin-bottom:18px}
.srv{display:flex;align-items:flex-start;gap:12px;margin-bottom:13px;font-size:13px;color:var(--t2);line-height:1.5}
.legal{background:rgba(201,146,42,.06);border:1px solid rgba(201,146,42,.15);border-radius:6px;padding:14px 18px;margin-top:28px;font-size:12px;color:var(--gold);line-height:1.6;font-family:var(--mono)}
.lcard{width:100%;max-width:360px}
.lt{font-size:22px;font-weight:800;margin-bottom:4px}
.ls{font-size:11px;color:var(--t3);font-family:var(--mono);margin-bottom:30px}
.field{margin-bottom:18px}
label{display:block;font-size:10px;font-weight:700;color:var(--t3);text-transform:uppercase;letter-spacing:1px;margin-bottom:7px;font-family:var(--mono)}
input{width:100%;background:var(--navy);border:1.5px solid var(--br);border-radius:6px;padding:12px 14px;font-size:14px;color:var(--text);outline:none;transition:border-color .2s}
input:focus{border-color:var(--blue2)}
.btn-si{width:100%;background:var(--blue);color:#fff;border:none;border-radius:6px;padding:13px;font-size:14px;font-weight:700;cursor:pointer}
.err{background:rgba(220,38,38,.08);border:1px solid rgba(220,38,38,.25);border-radius:6px;padding:10px 14px;font-size:12px;color:#f87171;font-family:var(--mono);margin-bottom:18px;line-height:1.5}
.help{margin-top:22px;display:flex;flex-direction:column;gap:8px;font-size:12px;color:var(--t3)}
.help a{color:var(--blue3);text-decoration:none}
</style></head><body>
<div class="gov-ribbon"></div>
<div class="topbar"><div class="tb-brand"><div class="wheel">&#9955;</div>
  <div><div class="org-name">Rashtriya Petroleum Anveshan Limited</div>
  <div class="org-sub">permit.rpal.in &middot; Exploration Licensing Division</div></div></div></div>
<div class="wrap">
  <div class="left">
    <div style="font-family:var(--mono);font-size:10px;color:var(--gold);text-transform:uppercase;letter-spacing:1.5px;margin-bottom:14px">Exploration Permit &amp; Licensing Portal</div>
    <div style="font-size:28px;font-weight:800;max-width:480px;margin-bottom:14px">Exploration Permit &amp; Licensing Portal</div>
    <div style="font-size:14px;color:var(--t2);line-height:1.7;max-width:500px;margin-bottom:26px">Unified digital platform for petroleum exploration permit management, PML tracking, and block allocation status under HELP/OALP/NELP frameworks.</div>
    <div class="srv-lbl">Portal Services</div>
    <div class="srv"><span>&#128203;</span>Exploration block application and permit tracking under NELP/OALP/HELP</div>
    <div class="srv"><span>&#127758;</span>Block GIS viewer &mdash; KG Basin, Mumbai Offshore, Rajasthan, Assam-Arakan</div>
    <div class="srv"><span>&#128196;</span>Petroleum Mining Lease (PML) status and renewal management</div>
    <div class="srv"><span>&#128279;</span>DGH integration for regulatory clearance tracking</div>
    <div class="srv"><span>&#128188;</span>Contractor qualification and pre-approval document submission</div>
    <div class="legal">&#9888; This portal is for authorised RPAL personnel, DGH officials, and pre-approved exploration contractors only. Unauthorised access is a criminal offence under the IT Act 2000.</div>
  </div>
  <div class="right"><div class="lcard">
    <div class="lt">Sign In</div>
    <div class="ls">permit.rpal.in &middot; Exploration Licensing Division</div>
    {% if error %}<div class="err">&#9888; {{ error }}</div>{% endif %}
    <form method="POST" action="/login">
      <div class="field"><label>User ID / Contractor Code</label>
        <input type="text" name="username" value="{{ username|default('') }}" placeholder="e.g. contractor.01" autocomplete="off" spellcheck="false"></div>
      <div class="field"><label>Password</label>
        <input type="password" name="password" placeholder="&bull;&bull;&bull;&bull;&bull;&bull;&bull;&bull;&bull;&bull;&bull;&bull;"></div>
      <button class="btn-si" type="submit">Sign In &rarr;</button>
    </form>
    <div class="help">
      <span>&#128273; Forgot password? <a href="#">Contact RPAL IT Helpdesk</a></span>
      <span>&#128196; New contractor registration: <a href="#">Apply online</a></span>
      <span>&#128222; Helpdesk: 011-2338-7700 (Mon&ndash;Fri, 09:00&ndash;18:00 IST)</span>
    </div>
  </div></div>
</div></body></html>"""

DASH_HTML = """<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8">
<title>Dashboard - RPAL Permit Portal</title><style>""" + _BASE_CSS + """
.tb-right{display:flex;align-items:center;gap:12px}
.up{font-family:var(--mono);font-size:11px;color:var(--t2);background:rgba(255,255,255,.04);border:1px solid var(--br);padding:3px 10px;border-radius:12px}
.rb{font-family:var(--mono);font-size:10px;padding:2px 8px;border-radius:4px;font-weight:700}
.ra{background:rgba(248,81,73,.12);color:#f85149;border:1px solid rgba(248,81,73,.25)}
.rp{background:rgba(45,122,238,.1);color:var(--blue3);border:1px solid rgba(45,122,238,.25)}
.lo{font-size:12px;color:var(--t3);text-decoration:none}
.main{max-width:1000px;margin:0 auto;padding:28px}
.pt{font-size:20px;font-weight:700;margin-bottom:4px}.ps{font-size:11px;color:var(--t3);font-family:var(--mono);margin-bottom:22px}
.card{background:var(--navy2);border:1px solid var(--br);border-radius:8px;overflow:hidden;margin-bottom:16px}
.ch{padding:12px 18px;border-bottom:1px solid var(--br);display:flex;justify-content:space-between;align-items:center;font-size:12px;font-weight:700}
table{width:100%;border-collapse:collapse}
th{font-family:var(--mono);font-size:10px;color:var(--t3);text-transform:uppercase;letter-spacing:.8px;padding:10px 16px;text-align:left;border-bottom:1px solid var(--br);background:rgba(255,255,255,.02)}
td{padding:12px 16px;font-size:12px;font-family:var(--mono);border-bottom:1px solid rgba(30,58,95,.4)}
tr:hover{background:rgba(255,255,255,.02)}
.sa{color:#3fb950}.sp{color:#f0883e}.su{color:var(--blue3)}
</style></head><body>
<div class="gov-ribbon"></div>
<div class="topbar"><div class="tb-brand"><div class="wheel">&#9955;</div>
  <div><div class="org-name">RPAL Exploration Permit Portal</div>
  <div class="org-sub">permit.rpal.in &middot; URJA DRISHTI 2.0</div></div></div>
<div class="tb-right">
  <span class="up">{{ claims.sub }}</span>
  <span class="rb {% if claims.role == 'admin' %}ra{% else %}rp{% endif %}">{{ claims.role|upper }}</span>
  <a class="lo" href="/logout">Sign Out</a>
</div></div>
<div class="main">
  <div class="pt">My Permits</div>
  <div class="ps">{{ claims.sub }} &middot; Active exploration permit applications</div>
  <div class="card">
    <div class="ch"><span>Permit Register</span><span style="font-size:10px;color:var(--t3)">{{ permits|length }} records</span></div>
    {% if permits %}
    <table><thead><tr><th>Permit No.</th><th>Block</th><th>Type</th><th>Basin</th><th>Status</th><th>Submitted</th></tr></thead>
    <tbody>{% for p in permits %}<tr>
      <td>{{ p['permit_number'] }}</td><td>{{ p['block_name'] }}</td>
      <td>{{ p['block_type'] }}</td><td>{{ p['basin'] }}</td>
      <td class="{% if p['status']=='approved' %}sa{% elif p['status']=='pending' %}sp{% else %}su{% endif %}">{{ p['status']|upper }}</td>
      <td>{{ p['submitted_at'][:10] if p['submitted_at'] else '-' }}</td>
    </tr>{% endfor %}</tbody></table>
    {% else %}
    <div style="padding:32px;text-align:center;color:var(--t3);font-size:13px">No permit applications on file.</div>
    {% endif %}
  </div>
</div></body></html>"""

ERR_HTML = """<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"><title>Error - RPAL</title>
<style>""" + _BASE_CSS + """
.ew{min-height:100vh;display:flex;align-items:center;justify-content:center}
.ec{background:var(--navy2);border:1px solid var(--br);border-radius:10px;padding:48px;max-width:440px;text-align:center}
.ei{font-size:36px;margin-bottom:14px}.et{font-size:18px;font-weight:700;margin-bottom:8px}
.em{font-size:13px;color:var(--t2);margin-bottom:24px}
.back{background:var(--blue);color:#fff;padding:10px 20px;border-radius:6px;text-decoration:none;font-size:13px;font-weight:600}
</style></head><body><div class="gov-ribbon"></div>
<div class="ew"><div class="ec"><div class="ei">&#9888;</div>
<div class="et">Error</div><div class="em">{{ msg }}</div>
<a class="back" href="/">Return to Portal</a>
</div></div></body></html>"""

@app.route('/')
def index():
    return render_template_string(IDX_HTML)

@app.route('/.well-known/jwks.json')
def jwks():
    logging.info('JWKS_FETCH ip=%s', request.remote_addr)
    return jsonify({"keys": [get_jwk()]}), 200, {'Content-Type': 'application/json'}

@app.route('/.well-known/openid-configuration')
def oidc_config():
    base = 'https://permit.rpal.in'
    return jsonify({
        "issuer": JWT_ISSUER,
        "jwks_uri": base + "/.well-known/jwks.json",
        "authorization_endpoint": base + "/oauth/authorize",
        "token_endpoint": base + "/oauth/token",
        "response_types_supported": ["code", "token"],
        "id_token_signing_alg_values_supported": ["RS256"],
    })

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'GET':
        return render_template_string(LOGIN_HTML, error=None, username='')
    username = request.form.get('username', '').strip()
    password = request.form.get('password', '')
    try:
        db  = get_db()
        row = db.execute('SELECT * FROM users WHERE username=? AND password_hash=?',
                         (username, _hp(password))).fetchone()
        db.close()
    except Exception as exc:
        logging.error('DB error during login: %s', exc)
        return render_template_string(ERR_HTML, msg='Database error. Please try again.'), 500
    if row:
        token = issue_token(row['username'], row['role'])
        logging.info('LOGIN_OK user=%s role=%s ip=%s', username, row['role'], request.remote_addr)
        resp = make_response(redirect(url_for('dashboard')))
        resp.set_cookie('rpal_token', token, httponly=True, samesite='Lax', max_age=28800)
        return resp
    logging.warning('LOGIN_FAIL user=%s ip=%s', username, request.remote_addr)
    return render_template_string(LOGIN_HTML,
        error='Invalid credentials. Contact RPAL IT Helpdesk if you need assistance.',
        username=username)

@app.route('/logout')
def logout():
    resp = make_response(redirect(url_for('index')))
    resp.delete_cookie('rpal_token')
    return resp

@app.route('/dashboard')
@require_jwt()
def dashboard():
    claims = request.jwt_claims
    db = get_db()
    if claims['role'] in ('admin', 'permit-officer', 'staff'):
        permits = db.execute('SELECT * FROM permits ORDER BY submitted_at DESC').fetchall()
    else:
        permits = db.execute(
            'SELECT * FROM permits WHERE applicant_username=? ORDER BY submitted_at DESC',
            (claims['sub'],)).fetchall()
    db.close()
    return render_template_string(DASH_HTML, permits=permits, claims=claims)

@app.route('/api/v1/status')
def api_status():
    return jsonify({'service': 'RPAL Exploration Permit Portal', 'version': '2.4.1',
                    'status': 'operational', 'issuer': JWT_ISSUER})

@app.route('/api/v1/permits')
@require_jwt()
def api_permits():
    claims = request.jwt_claims
    db = get_db()
    if claims['role'] in ('admin', 'permit-officer', 'staff'):
        rows = db.execute('SELECT * FROM permits').fetchall()
    else:
        rows = db.execute('SELECT * FROM permits WHERE applicant_username=?',
                          (claims['sub'],)).fetchall()
    db.close()
    return jsonify([dict(r) for r in rows])

@app.route('/api/v1/admin/system-config')
@require_jwt(roles=['admin'])
def api_admin_system_config():
    logging.warning('ADMIN_CONFIG_ACCESS sub=%s ip=%s', request.jwt_claims.get('sub'), request.remote_addr)
    db   = get_db()
    rows = db.execute('SELECT key, value, description FROM system_config').fetchall()
    db.close()
    return jsonify({'status': 'ok', 'config': [dict(r) for r in rows],
                    '_warn': 'This endpoint is admin-restricted — all access is audited'})

@app.route('/api/v1/admin/users')
@require_jwt(roles=['admin', 'permit-officer'])
def api_admin_users():
    db   = get_db()
    rows = db.execute('SELECT username,role,full_name,organisation,email,created_at FROM users').fetchall()
    db.close()
    return jsonify([dict(r) for r in rows])

@app.errorhandler(404)
def not_found(e):
    if request.path.startswith('/api/'):
        return jsonify({'error': 'Not found'}), 404
    return render_template_string(ERR_HTML, msg='Page not found'), 404

@app.errorhandler(500)
def server_error(e):
    logging.error('500 at %s: %s', request.path, e)
    if request.path.startswith('/api/'):
        return jsonify({'error': 'Internal server error'}), 500
    return render_template_string(ERR_HTML, msg='Internal server error'), 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=PORT, debug=False)
