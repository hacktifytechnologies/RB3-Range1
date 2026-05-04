#!/usr/bin/env bash
# M1-ext-permit-portal.sh — RPAL M1 Supporting Infrastructure
# RNG-EXT-01 · SETU DVAAR · OPERATION DEEPSTRIKE
# Run as root after setup.sh
set -euo pipefail
[[ $EUID -ne 0 ]] && { echo "Run as root: sudo bash $0"; exit 1; }

GREEN='\033[0;32m'; CYAN='\033[0;36m'; NC='\033[0m'
log()  { echo -e "${GREEN}[RPAL-EXT]${NC} $*"; }
info() { echo -e "${CYAN}[+]${NC} $*"; }

BASE="/opt/rpal/supporting-services"
mkdir -p "$BASE"
log "Deploying RPAL M1 supporting infrastructure services..."

# ── Web Portal 1: RPAL QHSE Compliance Portal — Port 7443 ────────────────────
# Vulnerability: SQL Injection in login (CWE-89)
# admin'-- bypasses auth; reveals internal HSE inspection reports
mkdir -p "${BASE}/qhse-portal"

cat > "${BASE}/qhse-portal/app.py" << 'PYEOF'
#!/usr/bin/env python3
import flask, sqlite3, os, hashlib, logging

app = flask.Flask(__name__)
app.secret_key = b'RPAL-QHSE-2024-Internal'
DB  = '/opt/rpal/supporting-services/qhse-portal/qhse.db'
logging.basicConfig(level=logging.WARNING)

def init_db():
    conn = sqlite3.connect(DB)
    conn.executescript("""
    CREATE TABLE IF NOT EXISTS users(
        id INTEGER PRIMARY KEY, username TEXT, password TEXT, role TEXT);
    CREATE TABLE IF NOT EXISTS inspections(
        id INTEGER PRIMARY KEY, site TEXT, inspector TEXT,
        findings TEXT, severity TEXT, date TEXT);
    INSERT OR IGNORE INTO users VALUES
        (1,'qhse.admin','5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8','admin'),
        (2,'kavita.rao','8d969eef6ecad3c29a3a629280e686cf0c3f5d5a86aff3ca12020c923adc6c92','inspector'),
        (3,'hse.viewer','7c4a8d09ca3762af61e59520943dc26494f8941b','viewer');
    INSERT OR IGNORE INTO inspections VALUES
        (1,'KG-DWN Platform A','kavita.rao','Gas leak at manifold P-07. Isolation valve non-responsive.','CRITICAL','2024-10-15'),
        (2,'Hazira Onshore Terminal','kavita.rao','PTW register incomplete for 3 hot-work permits.','HIGH','2024-10-22'),
        (3,'Rajahmundry Processing Plant','hse.viewer','Fire suppression system quarterly test overdue by 14 days.','MEDIUM','2024-11-01'),
        (4,'Mumbai Offshore HQ','qhse.admin','Emergency muster drill attendance: 94%. OISD-116 compliant.','LOW','2024-11-10');
    """)
    conn.commit(); conn.close()

init_db()

INDEX = """<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8">
<title>RPAL QHSE Compliance Portal</title>
<style>*{box-sizing:border-box;margin:0;padding:0}
:root{--green:#1b5e20;--green2:#2e7d32;--gold:#f9a825;--text:#212121;--bg:#f5f5f5;--card:#fff;--border:#e0e0e0;--sans:-apple-system,sans-serif}
body{background:var(--bg);font-family:var(--sans);min-height:100vh}
.header{background:var(--green);color:#fff;padding:0 28px;height:60px;display:flex;align-items:center;justify-content:space-between}
.header-brand{display:flex;align-items:center;gap:12px}
.header-icon{width:36px;height:36px;background:var(--gold);border-radius:6px;display:flex;align-items:center;justify-content:center;font-size:18px}
.header-title{font-size:15px;font-weight:700}.header-sub{font-size:10px;opacity:.7;font-family:monospace}
.hero{background:linear-gradient(135deg,var(--green),var(--green2));color:#fff;padding:48px 28px}
.hero h1{font-size:28px;font-weight:800;margin-bottom:8px}.hero p{opacity:.8;font-size:14px;max-width:600px;line-height:1.6}
.main{max-width:1000px;margin:0 auto;padding:32px 28px}
.card{background:var(--card);border:1px solid var(--border);border-radius:8px;padding:24px;margin-bottom:20px}
.card h2{font-size:14px;font-weight:700;color:var(--green);margin-bottom:16px;border-bottom:2px solid var(--gold);padding-bottom:8px}
.login-form{max-width:380px}
.field{margin-bottom:16px}
label{display:block;font-size:11px;font-weight:700;color:#555;text-transform:uppercase;letter-spacing:.7px;margin-bottom:6px}
input{width:100%;background:#fafafa;border:1.5px solid var(--border);border-radius:6px;padding:11px 13px;font-size:14px;outline:none}
input:focus{border-color:var(--green2)}
.btn{background:var(--green2);color:#fff;border:none;border-radius:6px;padding:12px 28px;font-size:14px;font-weight:700;cursor:pointer;width:100%}
.error{background:#fce4ec;border:1px solid #f48fb1;border-radius:6px;padding:10px 14px;font-size:12px;color:#c62828;margin-bottom:14px}
.info-grid{display:grid;grid-template-columns:repeat(3,1fr);gap:14px}
.info-card{background:#e8f5e9;border:1px solid #a5d6a7;border-radius:6px;padding:16px;text-align:center}
.info-val{font-size:22px;font-weight:700;color:var(--green)}.info-label{font-size:11px;color:#555;margin-top:4px}
.footer{background:var(--green);color:rgba(255,255,255,.5);padding:12px 28px;font-size:10px;font-family:monospace;display:flex;justify-content:space-between}
</style></head><body>
<div class="header">
  <div class="header-brand">
    <div class="header-icon">🦺</div>
    <div><div class="header-title">RPAL QHSE Compliance Portal</div>
    <div class="header-sub">permit.rpal.in · OISD-116 · ISO 45001 Platform</div></div>
  </div>
</div>
<div class="hero">
  <h1>Health, Safety, Environment &amp; Quality</h1>
  <p>RPAL integrated QHSE management platform for OISD-116 compliance monitoring, HSE incident reporting, and permit-to-work tracking across all operational sites.</p>
</div>
<div class="main">
  <div class="card">
    <h2>HSE Inspector Login</h2>
    <div class="login-form">
      {% if error %}<div class="error">{{ error }}</div>{% endif %}
      <form method="POST" action="/qhse/login">
        <div class="field"><label>Inspector ID</label><input name="username" placeholder="e.g. kavita.rao" autocomplete="off"></div>
        <div class="field"><label>Password</label><input type="password" name="password"></div>
        <button class="btn" type="submit">Access QHSE Portal</button>
      </form>
    </div>
  </div>
  <div class="card">
    <h2>Platform Statistics — FY 2024-25</h2>
    <div class="info-grid">
      <div class="info-card"><div class="info-val">94%</div><div class="info-label">OISD Compliance Score</div></div>
      <div class="info-card"><div class="info-val">247</div><div class="info-label">PTW Issued YTD</div></div>
      <div class="info-card"><div class="info-val">12</div><div class="info-label">Open Observations</div></div>
    </div>
  </div>
</div>
<div class="footer"><span>© 2024 Rashtriya Petroleum Anveshan Limited · QHSE Division</span><span>QHSE-Portal v3.1.2</span></div>
</body></html>"""

DASHBOARD = """<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8">
<title>QHSE Dashboard — RPAL</title>
<style>*{box-sizing:border-box;margin:0;padding:0}body{background:#f5f5f5;font-family:-apple-system,sans-serif}
.header{background:#2e7d32;color:#fff;padding:0 28px;height:52px;display:flex;align-items:center;justify-content:space-between}
.h-left{display:flex;align-items:center;gap:10px;font-size:13px;font-weight:700}
.h-right{display:flex;align-items:center;gap:12px;font-size:12px}
.user-pill{background:rgba(255,255,255,.15);padding:4px 12px;border-radius:12px}
.logout{color:rgba(255,255,255,.7);text-decoration:none}
.main{max-width:1000px;margin:0 auto;padding:28px}
.pg-title{font-size:18px;font-weight:700;margin-bottom:4px}.pg-sub{font-size:11px;color:#666;font-family:monospace;margin-bottom:24px}
.card{background:#fff;border:1px solid #e0e0e0;border-radius:8px;overflow:hidden;margin-bottom:16px}
.card-hd{padding:14px 20px;border-bottom:1px solid #e0e0e0;display:flex;justify-content:space-between;align-items:center}
.card-title{font-size:13px;font-weight:700;color:#2e7d32}
table{width:100%;border-collapse:collapse}
th{font-size:10px;color:#666;text-transform:uppercase;letter-spacing:.7px;padding:9px 16px;text-align:left;border-bottom:1px solid #e0e0e0;background:#fafafa}
td{padding:12px 16px;font-size:12px;border-bottom:1px solid #f5f5f5}
.sev-critical{color:#b71c1c;font-weight:700}.sev-high{color:#e65100;font-weight:700}
.sev-medium{color:#f57f17}.sev-low{color:#2e7d32}
</style></head><body>
<div class="header">
  <div class="h-left">🦺 RPAL QHSE Portal</div>
  <div class="h-right"><span class="user-pill">{{ username }}</span><a class="logout" href="/qhse/logout">Sign Out</a></div>
</div>
<div class="main">
  <div class="pg-title">HSE Inspection Register</div>
  <div class="pg-sub">All sites · FY 2024-25 · OISD-116 compliant</div>
  <div class="card">
    <div class="card-hd"><span class="card-title">Recent Inspections</span><span style="font-size:10px;color:#999">{{ inspections|length }} records</span></div>
    <table><thead><tr><th>Site</th><th>Inspector</th><th>Findings</th><th>Severity</th><th>Date</th></tr></thead>
    <tbody>{% for r in inspections %}<tr>
      <td>{{ r[1] }}</td><td>{{ r[2] }}</td><td>{{ r[3] }}</td>
      <td class="sev-{{ r[4]|lower }}">{{ r[4] }}</td><td>{{ r[5] }}</td>
    </tr>{% endfor %}</tbody></table>
  </div>
</div></body></html>"""

@app.route('/')
def index():
    return flask.render_template_string(INDEX, error=None)

@app.route('/qhse/login', methods=['POST'])
def login():
    username = flask.request.form.get('username', '')
    password = flask.request.form.get('password', '')
    logging.info(f"LOGIN attempt user={username} ip={flask.request.remote_addr}")
    conn = sqlite3.connect(DB)
    # VULNERABILITY: SQL injection — filter is constructed with string formatting
    query = f"SELECT * FROM users WHERE username='{username}' AND password='{hashlib.sha256(password.encode()).hexdigest()}'"
    try:
        user = conn.execute(query).fetchone()
    except Exception:
        user = None
    conn.close()
    if user:
        flask.session['user'] = user[1]
        flask.session['role'] = user[3]
        logging.warning(f"LOGIN_OK user={username} role={user[3]} ip={flask.request.remote_addr}")
        return flask.redirect('/qhse/dashboard')
    return flask.render_template_string(INDEX, error='Invalid credentials. Contact RPAL IT helpdesk.')

@app.route('/qhse/dashboard')
def dashboard():
    if 'user' not in flask.session:
        return flask.redirect('/')
    conn = sqlite3.connect(DB)
    inspections = conn.execute('SELECT * FROM inspections ORDER BY date DESC').fetchall()
    conn.close()
    return flask.render_template_string(DASHBOARD,
        username=flask.session['user'], inspections=inspections)

@app.route('/qhse/logout')
def logout():
    flask.session.clear()
    return flask.redirect('/')

@app.route('/api/status')
def status():
    return flask.jsonify({'service':'RPAL QHSE Portal','version':'3.1.2','status':'operational'})

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=7443, debug=False)
PYEOF

# ── Web Portal 2: DGH Block Licensing Registry — Port 9443 ───────────────────
# Vulnerability: Path Traversal in document download (CWE-22)
# GET /registry/download?doc=../../etc/passwd reads arbitrary files
mkdir -p "${BASE}/dgh-registry"

cat > "${BASE}/dgh-registry/app.py" << 'PYEOF'
#!/usr/bin/env python3
import flask, os, logging

app = flask.Flask(__name__)
DOC_ROOT = '/opt/rpal/supporting-services/dgh-registry/docs'
os.makedirs(DOC_ROOT, exist_ok=True)
logging.basicConfig(level=logging.WARNING)

# Plant some realistic documents
for name, content in [
    ('PML-KG-2024-001-approval.txt', 'Block: KG-DWN-98/3\nOperator: Gulf Drilling Solutions\nStatus: APPROVED\nIssued: 2024-09-01\nExpiry: 2027-09-01\nRoyalty Rate: 12.5%'),
    ('PML-MH-2024-002-review.txt', 'Block: MB-OSN-2005/2\nStatus: UNDER REVIEW\nNotes: Environmental clearance pending DGH-EC-2024-0891'),
    ('block-map-kg-basin.txt', 'KG Basin Blocks: KG-DWN-98/1, KG-DWN-98/3, KG-ONN-2004/1\nWater Depth: 300-3000m\nEstimated Reserves: 1.2 TCF'),
    ('dev-notes.txt',
     'RPAL Exploration Portal — DGH Demo Environment Setup Notes\n'
     'Author: arjun.mehta@rpal.in | Created: 2024-10-14 | Status: PENDING CLEANUP\n'
     '\n'
     'Test contractor accounts for DGH integration demonstration (DEVOPS-1089):\n'
     '  Portal URL : http://permit.rpal.in:8443/\n'
     '  Account 1  : contractor.01 / Contractor@2024!   (Gulf Drilling Solutions)\n'
     '  Account 2  : contractor.02 / Gulf@Drilling#24!  (Mahindra Energy)\n'
     '\n'
     'NOTE: Jira DEVOPS-1089 — these test credentials must be rotated before\n'
     'production go-live. Arjun to confirm with DGH team by 2024-11-30.\n'
     '\n'
     'LDAP integration: ldap://203.x.x.x:389 — bind as svc-api-gateway\n'
     'DGH SFTP for block data: sftp.dgh.gov.in (key in /etc/rpal/upstream/)\n'),
]:
    open(os.path.join(DOC_ROOT, name), 'w').write(content)

INDEX = """<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8">
<title>DGH Block Licensing Registry — RPAL Integration</title>
<style>*{box-sizing:border-box;margin:0;padding:0}body{background:#f0f4ff;font-family:-apple-system,sans-serif}
.header{background:#1a237e;color:#fff;padding:0 28px;height:62px;display:flex;align-items:center;gap:16px}
.gov-bar{background:linear-gradient(90deg,#ff9933 33%,#fff 33%,#fff 66%,#138808 66%);height:5px}
.emblem{width:40px;height:40px;border:2px solid rgba(255,255,255,.4);border-radius:50%;display:flex;align-items:center;justify-content:center;font-size:18px;font-weight:900}
.h-title{font-size:14px;font-weight:700}.h-sub{font-size:10px;opacity:.65;font-family:monospace;margin-top:2px}
.main{max-width:1000px;margin:0 auto;padding:28px}
.hero{background:#1a237e;color:#fff;padding:28px;border-radius:8px;margin-bottom:24px}
.hero h1{font-size:20px;font-weight:800;margin-bottom:6px}.hero p{font-size:13px;opacity:.8;line-height:1.6}
.card{background:#fff;border:1px solid #c5cae9;border-radius:8px;padding:20px;margin-bottom:16px}
.card h2{font-size:13px;font-weight:700;color:#1a237e;margin-bottom:14px}
.doc-list{list-style:none}
.doc-item{display:flex;align-items:center;justify-content:space-between;padding:10px 0;border-bottom:1px solid #f5f5f5}
.doc-name{font-size:13px;color:#212121;font-family:monospace}
.doc-meta{font-size:10px;color:#666}
.download-btn{font-size:11px;background:#1a237e;color:#fff;padding:4px 12px;border-radius:4px;text-decoration:none}
.search-bar{display:flex;gap:10px;margin-bottom:20px}
input{flex:1;background:#fafafa;border:1.5px solid #c5cae9;border-radius:6px;padding:10px 13px;font-size:14px;outline:none}
.btn{background:#1a237e;color:#fff;border:none;border-radius:6px;padding:10px 20px;font-size:13px;font-weight:600;cursor:pointer}
.footer{background:#1a237e;color:rgba(255,255,255,.4);padding:12px 28px;font-size:10px;font-family:monospace;display:flex;justify-content:space-between;margin-top:24px}
</style></head><body>
<div class="gov-bar"></div>
<div class="header"><div class="emblem">⊕</div><div>
  <div class="h-title">Directorate General of Hydrocarbons — Block Licensing Registry</div>
  <div class="h-sub">Ministry of Petroleum &amp; Natural Gas, GoI · RPAL Integration Interface</div>
</div></div>
<div class="main">
  <div class="hero">
    <h1>OALP / NELP Block Document Repository</h1>
    <p>Official repository for petroleum exploration block licensing documents, permit-to-map approvals, and operator notifications under the Petroleum &amp; Natural Gas Rules, 1959.</p>
  </div>
  <div class="card">
    <h2>Document Search</h2>
    <form action="/registry/search" method="GET" class="search-bar">
      <input name="q" placeholder="Search by block name, permit number or operator...">
      <button class="btn" type="submit">Search</button>
    </form>
  </div>
  <div class="card">
    <h2>Recent Documents</h2>
    <ul class="doc-list">
      <li class="doc-item">
        <div><div class="doc-name">PML-KG-2024-001-approval.txt</div><div class="doc-meta">Approval Order · KG-DWN-98/3 · 2024-09-01</div></div>
        <a class="download-btn" href="/registry/download?doc=PML-KG-2024-001-approval.txt">Download</a>
      </li>
      <li class="doc-item">
        <div><div class="doc-name">PML-MH-2024-002-review.txt</div><div class="doc-meta">Review Notice · MB-OSN-2005/2 · 2024-10-14</div></div>
        <a class="download-btn" href="/registry/download?doc=PML-MH-2024-002-review.txt">Download</a>
      </li>
      <li class="doc-item">
        <div><div class="doc-name">block-map-kg-basin.txt</div><div class="doc-meta">Technical Map · KG Basin · 2024-08-20</div></div>
        <a class="download-btn" href="/registry/download?doc=block-map-kg-basin.txt">Download</a>
      </li>
    </ul>
  </div>
</div>
<!-- TODO(arjun.mehta): DEVOPS-1089 — remove dev-notes.txt from docs dir before DGH go-live. Flagged in sprint review 2024-11-08. -->
<div class="footer"><span>© 2024 Directorate General of Hydrocarbons, GoI · RPAL Integration</span><span>DGH-Registry v2.8.1</span></div>
</body></html>"""

@app.route('/')
def index():
    return flask.render_template_string(INDEX)

@app.route('/registry/download')
def download():
    doc = flask.request.args.get('doc', '')
    logging.info(f"DOWNLOAD doc={doc} ip={flask.request.remote_addr}")
    # VULNERABILITY: Path traversal — doc parameter not sanitised
    # Attacker can request: ?doc=../../etc/passwd
    # or: ?doc=../../../etc/rpal/upstream/config.ini
    try:
        full_path = os.path.join(DOC_ROOT, doc)
        # Insecure: realpath is never checked against DOC_ROOT
        with open(full_path, 'r') as f:
            content = f.read()
        logging.warning(f"FILE_READ path={full_path} ip={flask.request.remote_addr}")
        resp = flask.Response(content, mimetype='text/plain')
        resp.headers['Content-Disposition'] = f'attachment; filename="{os.path.basename(doc)}"'
        return resp
    except FileNotFoundError:
        return flask.jsonify({'error': 'Document not found'}), 404
    except PermissionError:
        return flask.jsonify({'error': 'Access denied'}), 403
    except Exception as e:
        return flask.jsonify({'error': str(e)}), 500

@app.route('/registry/search')
def search():
    q = flask.request.args.get('q', '')
    return flask.render_template_string(INDEX)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=9443, debug=False)
PYEOF

# ── Web Portal 3: Environmental Clearance Management System — Port 8880 ───────
# Vulnerability: IDOR — change app_id parameter to access other submissions
mkdir -p "${BASE}/env-clearance"

cat > "${BASE}/env-clearance/app.py" << 'PYEOF'
#!/usr/bin/env python3
import flask, sqlite3, os, logging

app = flask.Flask(__name__)
app.secret_key = b'RPAL-ENV-CLEARANCE-2024'
DB  = '/opt/rpal/supporting-services/env-clearance/env.db'
logging.basicConfig(level=logging.WARNING)

def init_db():
    conn = sqlite3.connect(DB)
    conn.executescript("""
    CREATE TABLE IF NOT EXISTS applicants(
        id INTEGER PRIMARY KEY, username TEXT, password TEXT, company TEXT, email TEXT);
    CREATE TABLE IF NOT EXISTS applications(
        id INTEGER PRIMARY KEY, app_id TEXT, applicant_id INTEGER,
        block_name TEXT, activity TEXT, status TEXT, submitted TEXT,
        env_officer TEXT, remarks TEXT, internal_notes TEXT);
    INSERT OR IGNORE INTO applicants VALUES
        (1,'contractor.01','c01pass','Gulf Drilling Solutions','ops@gulfdrilling.ae'),
        (2,'contractor.02','c02pass','Mahindra Energy Pvt Ltd','env@mahindra-energy.in'),
        (3,'vedanta.env','venv2024','Vedanta Resources Ltd','env@vedanta.com');
    INSERT OR IGNORE INTO applications VALUES
        (1,'EC-2024-KG-0091',1,'KG-DWN-98/3','Exploratory Drilling','APPROVED','2024-08-10',
         'pradeep.iyer@moefcc.gov.in','Approved with 12 conditions. See Annexure IV.','Pending NOC from Fisheries Dept — escalate if delayed beyond Nov-30'),
        (2,'EC-2024-MB-0047',2,'MB-OSN-2005/2','Seismic Survey','UNDER_REVIEW','2024-10-01',
         'anita.sharma@moefcc.gov.in','Awaiting marine ecology assessment from NCMRWF.',
         'Applicant has political connections — fast-track per DPIIT instruction D/1829/2024'),
        (3,'EC-2024-RJ-0033',3,'RJ-ONN-2022/3','Well Workover','PENDING','2024-11-05',
         NULL,'Application received. Screening in progress.','Vedanta flagged for prior violation at Niyamgiri — additional scrutiny required');
    """)
    conn.commit(); conn.close()

init_db()

INDEX = """<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8">
<title>Environmental Clearance Management System — MoEFCC/RPAL</title>
<style>*{box-sizing:border-box;margin:0;padding:0}body{background:#e8f5e9;font-family:-apple-system,sans-serif}
.gov-bar{background:linear-gradient(90deg,#ff9933 33%,#fff 33%,#fff 66%,#138808 66%);height:6px}
.header{background:#1b5e20;color:#fff;padding:0 28px;height:60px;display:flex;align-items:center;gap:14px}
.emblem{font-size:22px}.h-main{font-size:14px;font-weight:700}.h-sub{font-size:10px;opacity:.65;font-family:monospace}
.main{max-width:960px;margin:0 auto;padding:28px}
.hero{background:linear-gradient(135deg,#1b5e20,#2e7d32);color:#fff;padding:28px;border-radius:8px;margin-bottom:24px}
.hero h1{font-size:20px;font-weight:800;margin-bottom:6px}.hero p{font-size:13px;opacity:.8;line-height:1.6}
.card{background:#fff;border:1px solid #a5d6a7;border-radius:8px;padding:20px;margin-bottom:16px}
.card h2{font-size:13px;font-weight:700;color:#1b5e20;margin-bottom:14px}
.field{margin-bottom:14px}label{display:block;font-size:10px;font-weight:700;color:#555;text-transform:uppercase;letter-spacing:.7px;margin-bottom:6px}
input{width:100%;background:#f9f9f9;border:1.5px solid #a5d6a7;border-radius:6px;padding:10px 13px;font-size:14px;outline:none}
input:focus{border-color:#2e7d32}
.btn{background:#2e7d32;color:#fff;border:none;border-radius:6px;padding:11px 24px;font-size:13px;font-weight:700;cursor:pointer;width:100%}
.error{background:#ffebee;border:1px solid #ef9a9a;border-radius:6px;padding:10px;font-size:12px;color:#b71c1c;margin-bottom:12px}
.footer{background:#1b5e20;color:rgba(255,255,255,.4);padding:12px 28px;font-size:10px;font-family:monospace;display:flex;justify-content:space-between;margin-top:24px}
</style></head><body>
<div class="gov-bar"></div>
<div class="header"><div class="emblem">🌿</div><div>
  <div class="h-main">Environmental Clearance Management System</div>
  <div class="h-sub">Ministry of Environment, Forest &amp; Climate Change · RPAL Industry Interface</div>
</div></div>
<div class="main">
  <div class="hero"><h1>Online EC Application &amp; Tracking</h1>
    <p>Digital platform for Environmental Clearance applications under EIA Notification 2006 for petroleum exploration and production activities. Operators may submit applications, track status, and download clearance orders.</p>
  </div>
  <div class="card"><h2>Operator Login</h2>
    {% if error %}<div class="error">{{ error }}</div>{% endif %}
    <form method="POST" action="/ecms/login">
      <div class="field"><label>Operator Username</label><input name="username" placeholder="e.g. contractor.01" autocomplete="off"></div>
      <div class="field"><label>Password</label><input type="password" name="password"></div>
      <button class="btn" type="submit">Access ECMS Portal</button>
    </form>
  </div>
</div>
<div class="footer"><span>© 2024 Ministry of Environment, Forest &amp; Climate Change, GoI · RPAL Interface</span><span>ECMS v4.2.1</span></div>
</body></html>"""

DASHBOARD = """<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8">
<title>My Applications — ECMS</title>
<style>*{box-sizing:border-box;margin:0;padding:0}body{background:#e8f5e9;font-family:-apple-system,sans-serif}
.header{background:#2e7d32;color:#fff;padding:0 28px;height:52px;display:flex;align-items:center;justify-content:space-between;font-size:13px;font-weight:700}
.h-right{display:flex;gap:12px;align-items:center;font-weight:400;font-size:12px}
.pill{background:rgba(255,255,255,.15);padding:3px 10px;border-radius:12px}
.logout{color:rgba(255,255,255,.7);text-decoration:none}
.main{max-width:900px;margin:0 auto;padding:28px}
.pg-title{font-size:18px;font-weight:700;margin-bottom:4px;color:#1b5e20}
.pg-sub{font-size:11px;color:#555;font-family:monospace;margin-bottom:20px}
.card{background:#fff;border:1px solid #a5d6a7;border-radius:8px;overflow:hidden;margin-bottom:16px}
.card-hd{padding:12px 18px;border-bottom:1px solid #e8f5e9;font-size:12px;font-weight:700;color:#2e7d32}
table{width:100%;border-collapse:collapse}
th{font-size:10px;color:#666;text-transform:uppercase;letter-spacing:.7px;padding:9px 14px;text-align:left;border-bottom:1px solid #e8f5e9;background:#f9fdf9}
td{padding:11px 14px;font-size:12px;font-family:monospace;border-bottom:1px solid #f5f5f5}
.view-btn{background:#2e7d32;color:#fff;padding:3px 10px;border-radius:4px;text-decoration:none;font-size:10px}
.status-approved{color:#1b5e20;font-weight:700}.status-under_review{color:#e65100}.status-pending{color:#1565c0}
</style></head><body>
<div class="header">🌿 ECMS — Environmental Clearance Management
  <div class="h-right"><span class="pill">{{ company }}</span><a class="logout" href="/ecms/logout">Sign Out</a></div>
</div>
<div class="main">
  <div class="pg-title">My EC Applications</div>
  <div class="pg-sub">{{ company }} · Showing your submitted applications</div>
  <div class="card">
    <div class="card-hd">Application Register</div>
    <table><thead><tr><th>Application ID</th><th>Block</th><th>Activity</th><th>Status</th><th>Submitted</th><th>Details</th></tr></thead>
    <tbody>{% for a in applications %}<tr>
      <td>{{ a[1] }}</td><td>{{ a[3] }}</td><td>{{ a[4] }}</td>
      <td class="status-{{ a[5]|lower }}">{{ a[5] }}</td><td>{{ a[6] }}</td>
      <td><a class="view-btn" href="/ecms/application/{{ a[0] }}">View</a></td>
    </tr>{% endfor %}</tbody></table>
  </div>
</div></body></html>"""

APP_DETAIL = """<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8">
<title>Application {{ app[1] }} — ECMS</title>
<style>*{box-sizing:border-box;margin:0;padding:0}body{background:#e8f5e9;font-family:-apple-system,sans-serif}
.header{background:#2e7d32;color:#fff;padding:0 28px;height:52px;display:flex;align-items:center;justify-content:space-between;font-size:13px;font-weight:700}
.main{max-width:800px;margin:0 auto;padding:28px}
.card{background:#fff;border:1px solid #a5d6a7;border-radius:8px;padding:20px;margin-bottom:16px}
.card h2{font-size:13px;font-weight:700;color:#2e7d32;margin-bottom:14px}
.kv{display:grid;grid-template-columns:180px 1fr;gap:8px;margin-bottom:8px;font-size:13px}
.k{color:#666;font-family:monospace;font-size:11px}.v{color:#212121}
.internal{background:#fff3e0;border:1px solid #ffcc02;border-radius:6px;padding:12px;margin-top:8px;font-size:12px;color:#e65100}
.back-btn{display:inline-block;margin-bottom:20px;font-size:12px;color:#2e7d32;text-decoration:none}
</style></head><body>
<div class="header">🌿 Application Detail — {{ app[1] }}</div>
<div class="main">
  <a class="back-btn" href="/ecms/dashboard">← Back to Dashboard</a>
  <div class="card"><h2>Application Details</h2>
    <div class="kv"><span class="k">Application ID</span><span class="v">{{ app[1] }}</span></div>
    <div class="kv"><span class="k">Block</span><span class="v">{{ app[3] }}</span></div>
    <div class="kv"><span class="k">Activity</span><span class="v">{{ app[4] }}</span></div>
    <div class="kv"><span class="k">Status</span><span class="v">{{ app[5] }}</span></div>
    <div class="kv"><span class="k">Submitted</span><span class="v">{{ app[6] }}</span></div>
    <div class="kv"><span class="k">EC Officer</span><span class="v">{{ app[7] or 'Not assigned' }}</span></div>
    <div class="kv"><span class="k">Officer Remarks</span><span class="v">{{ app[8] or 'Pending' }}</span></div>
    {% if app[9] %}
    <div class="internal">⚠ Internal Notes (MoEFCC): {{ app[9] }}</div>
    {% endif %}
  </div>
</div></body></html>"""

@app.route('/')
def index():
    return flask.render_template_string(INDEX, error=None)

@app.route('/ecms/login', methods=['POST'])
def login():
    username = flask.request.form.get('username','')
    password = flask.request.form.get('password','')
    conn = sqlite3.connect(DB)
    user = conn.execute('SELECT * FROM applicants WHERE username=? AND password=?',
                        (username, password)).fetchone()
    conn.close()
    if user:
        flask.session['uid'] = user[0]
        flask.session['company'] = user[3]
        return flask.redirect('/ecms/dashboard')
    return flask.render_template_string(INDEX, error='Invalid credentials.')

@app.route('/ecms/dashboard')
def dashboard():
    if 'uid' not in flask.session:
        return flask.redirect('/')
    conn = sqlite3.connect(DB)
    apps = conn.execute('SELECT * FROM applications WHERE applicant_id=?',
                        (flask.session['uid'],)).fetchall()
    conn.close()
    return flask.render_template_string(DASHBOARD, company=flask.session['company'], applications=apps)

@app.route('/ecms/application/<int:app_id>')
def application_detail(app_id):
    if 'uid' not in flask.session:
        return flask.redirect('/')
    # VULNERABILITY: IDOR — no check that app_id belongs to logged-in user
    # Any authenticated user can change the ID in the URL to see any application
    # including internal MoEFCC notes on competitors' submissions
    logging.warning(f"APP_DETAIL app_id={app_id} user_id={flask.session.get('uid')} ip={flask.request.remote_addr}")
    conn = sqlite3.connect(DB)
    application = conn.execute('SELECT * FROM applications WHERE id=?', (app_id,)).fetchone()
    conn.close()
    if not application:
        return flask.jsonify({'error': 'Not found'}), 404
    return flask.render_template_string(APP_DETAIL, app=application)

@app.route('/ecms/logout')
def logout():
    flask.session.clear(); return flask.redirect('/')

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8880, debug=False)
PYEOF

# ── Create systemd units ───────────────────────────────────────────────────────
for SVC_NAME in qhse-portal dgh-registry env-clearance; do
    case $SVC_NAME in
        qhse-portal) PORT=7443; TITLE="RPAL QHSE Compliance Portal";;
        dgh-registry) PORT=9443; TITLE="DGH Block Licensing Registry — RPAL Integration";;
        env-clearance) PORT=8880; TITLE="RPAL Environmental Clearance Management System";;
    esac

    chown -R nobody:nogroup "${BASE}/${SVC_NAME}" 2>/dev/null || true
    chmod 755 "${BASE}/${SVC_NAME}/app.py"

    cat > "/etc/systemd/system/rpal-${SVC_NAME}.service" << SVCEOF
[Unit]
Description=${TITLE}
After=network.target
[Service]
Type=simple
User=nobody
WorkingDirectory=${BASE}/${SVC_NAME}
ExecStart=/usr/bin/python3 ${BASE}/${SVC_NAME}/app.py
Restart=always
RestartSec=10
StandardError=append:/var/log/rpal/${SVC_NAME}.log
[Install]
WantedBy=multi-user.target
SVCEOF
    systemctl daemon-reload
    systemctl enable "rpal-${SVC_NAME}" --now 2>/dev/null || true
    info "WEB :${PORT} → ${TITLE}"
done

# ── TCP Banner Services ────────────────────────────────────────────────────────
for SVC_DEF in \
    "8009|rpal-oisd-ajp|RPAL OISD Document Management — AJP Connector" \
    "9418|rpal-internal-git|RPAL Internal Git Repository Daemon" \
    "636|rpal-corp-ldaps|RPAL LDAPS Corporate Directory — SSL LDAP" \
    "25|rpal-smtp-relay|RPAL Internal SMTP Mail Relay"; do

    IFS='|' read -r PORT SVC_NAME SVC_TITLE <<< "$SVC_DEF"

    case $PORT in
        8009) BANNER="HTTP/1.1 400 Bad Request\r\nServer: Apache-Coyote/1.1\r\nX-RPAL-Service: oisd-docmgmt\r\n\r\n<?xml version=\"1.0\"?><error>AJP connector on :8009 not accessible over HTTP. Use Tomcat AJP protocol.</error>\r\n";;
        9418) BANNER="0032ERR  \x00\x00\x00\x00\x00\x00\x00\x00\x00\x00RPAL-Internal-Git/2.43.0\r\nRepository: rpal-platform.git\r\nAccess: Authentication required. Use: git clone git://permit.rpal.in/rpal-platform.git\r\n";;
        636)  BANNER="\x30\x0c\x02\x01\x01\x61\x07\x0a\x01\x00\x04\x00\x04\x00RPAL-LDAPS/OpenLDAP-2.6.7 on :636\r\nTLS required for all LDAP operations on this port.\r\nContact: vikram.nair@rpal.in\r\n";;
        25)   BANNER="220 mail.rpal.in ESMTP Postfix (RPAL-SMTP-Relay/3.7.4)\r\n";;
    esac

    cat > "/etc/systemd/system/${SVC_NAME}.service" << SVCEOF
[Unit]
Description=${SVC_TITLE}
After=network.target
[Service]
Type=simple
User=nobody
ExecStart=/bin/bash -c "while true; do printf '${BANNER}' | nc -l -p ${PORT} -q 1 2>/dev/null || nc -l ${PORT} 2>/dev/null || true; sleep 1; done"
Restart=always
RestartSec=5
[Install]
WantedBy=multi-user.target
SVCEOF
    systemctl daemon-reload
    systemctl enable "${SVC_NAME}" --now 2>/dev/null || true
    info "TCP  :${PORT} → ${SVC_TITLE}"
done

log "M1 supporting services deployment complete."
info "Web portals : :7443 (QHSE)  :9443 (DGH Registry)  :8880 (Env Clearance)"
info "TCP services: :8009 (AJP/OISD)  :9418 (Git)  :636 (LDAPS)  :25 (SMTP)"
info "Real service: RPAL Permit Portal on :8443"
