#!/usr/bin/env bash
# M5-ext-contractor.sh — RPAL M5 Supporting Infrastructure
set -euo pipefail
[[ $EUID -ne 0 ]] && { echo "Run as root: sudo bash $0"; exit 1; }
GREEN='\033[0;32m'; CYAN='\033[0;36m'; NC='\033[0m'
log()  { echo -e "${GREEN}[RPAL-EXT]${NC} $*"; }
info() { echo -e "${CYAN}[+]${NC} $*"; }
BASE="/opt/rpal/supporting-services"
mkdir -p "$BASE"
log "Deploying RPAL M5 supporting infrastructure services..."

# Port 9001 — Vendor Management System
# Vulnerability: Mass assignment — PUT /api/vendors/<id> updates status without auth
mkdir -p "${BASE}/vendor-mgmt"
cat > "${BASE}/vendor-mgmt/app.py" << 'PYEOF'
#!/usr/bin/env python3
import flask, sqlite3, os, logging
app = flask.Flask(__name__)
app.secret_key = b'RPAL-VMS-2024-Internal'
DB  = '/opt/rpal/supporting-services/vendor-mgmt/vms.db'
logging.basicConfig(level=logging.WARNING)

def init_db():
    conn = sqlite3.connect(DB)
    conn.executescript("""
    CREATE TABLE IF NOT EXISTS vendors(id INTEGER PRIMARY KEY, vendor_id TEXT, name TEXT,
        category TEXT, status TEXT, contact_email TEXT, pan TEXT, gstin TEXT, approved_by TEXT);
    INSERT OR IGNORE INTO vendors VALUES
        (1,'VND-001','Gulf Drilling Solutions','Offshore Drilling','APPROVED','admin@gulfdrilling.ae','AAAAA1234A','22AAAAA1234A1Z5','arjun.mehta@rpal.in'),
        (2,'VND-002','Mahindra Energy Pvt Ltd','Engineering Services','PENDING','env@mahindra-energy.in','BBBBB5678B','27BBBBB5678B1Z1',NULL),
        (3,'VND-003','Larsen and Toubro EPC','Pipeline Construction','APPROVED','epc@lntecc.com','CCCCC9012C','24CCCCC9012C1Z8','vikram.nair@rpal.in'),
        (4,'VND-004','ONGC Petro Limited','Drilling Services','PENDING','contact@ongcpetro.com','DDDDD3456D','07DDDDD3456D1Z4',NULL);
    """)
    conn.commit(); conn.close()

init_db()

INDEX = """<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8">
<title>RPAL Vendor Management System</title>
<style>*{box-sizing:border-box;margin:0;padding:0}body{background:#f4f6fa;font-family:-apple-system,sans-serif;min-height:100vh}
.topbar{background:linear-gradient(135deg,#1565c0,#0d47a1);color:#fff;padding:0 28px;height:60px;display:flex;align-items:center;justify-content:space-between}
.tb-brand{display:flex;align-items:center;gap:12px}
.vendor-icon{width:36px;height:36px;background:rgba(255,255,255,.2);border-radius:8px;display:flex;align-items:center;justify-content:center;font-size:18px}
.tb-title{font-size:14px;font-weight:700}.tb-sub{font-size:10px;color:rgba(255,255,255,.65);font-family:monospace;margin-top:2px}
.tb-right{font-family:monospace;font-size:10px;color:rgba(255,255,255,.5)}
.main{max-width:1000px;margin:0 auto;padding:28px}
.alert{background:#fff3e0;border:1px solid #ffcc80;border-radius:6px;padding:10px 16px;font-size:12px;color:#e65100;margin-bottom:20px;font-family:monospace}
.card{background:#fff;border:1px solid #dde3ec;border-radius:8px;overflow:hidden;margin-bottom:16px}
.card-hd{padding:12px 20px;border-bottom:1px solid #dde3ec;display:flex;justify-content:space-between;align-items:center}
.card-title{font-size:13px;font-weight:700;color:#1565c0}
table{width:100%;border-collapse:collapse}
th{font-size:10px;color:#546e7a;text-transform:uppercase;letter-spacing:.7px;padding:9px 16px;text-align:left;border-bottom:1px solid #dde3ec;background:#fafbff}
td{padding:11px 16px;font-size:12px;font-family:monospace;border-bottom:1px solid rgba(221,227,236,.4)}
.status-approved{color:#2e7d32;font-weight:700}.status-pending{color:#e65100}
.btn-update{background:transparent;border:1px solid #1565c0;color:#1565c0;padding:3px 10px;border-radius:4px;font-size:10px;cursor:pointer;font-family:monospace}
</style></head><body>
<div class="topbar">
  <div class="tb-brand"><div class="vendor-icon">🏢</div><div>
    <div class="tb-title">RPAL Vendor Management System</div>
    <div class="tb-sub">vendor.rpal.in · URJA DRISHTI 2.0 Procurement Platform</div>
  </div></div>
  <div class="tb-right">VMS v4.1.2 · SAP Ariba Integration</div>
</div>
<div class="main">
  <div class="alert">⚠ PUT /api/vendors/&lt;vendor_id&gt; accepts status updates without authentication. Mass assignment allows any user to change vendor approval status.</div>
  <div class="card">
    <div class="card-hd"><span class="card-title">Registered Vendors</span><span style="font-size:10px;color:#546e7a">{{ vendors|length }} total</span></div>
    <table><thead><tr><th>Vendor ID</th><th>Company</th><th>Category</th><th>Status</th><th>GSTIN</th><th>Action</th></tr></thead>
    <tbody>{% for v in vendors %}<tr>
      <td>{{ v[1] }}</td><td>{{ v[2] }}</td><td>{{ v[3] }}</td>
      <td class="status-{{ v[4]|lower }}">{{ v[4] }}</td><td>{{ v[7] }}</td>
      <td><button class="btn-update" onclick="fetch('/api/vendors/{{ v[1] }}',{method:'PUT',headers:{'Content-Type':'application/json'},body:JSON.stringify({status:'APPROVED'})}).then(r=>r.json()).then(d=>alert(JSON.stringify(d)))">Approve</button></td>
    </tr>{% endfor %}</tbody></table>
  </div>
</div></body></html>"""

@app.route('/')
def index():
    conn = sqlite3.connect(DB)
    vendors = conn.execute('SELECT * FROM vendors').fetchall()
    conn.close()
    return flask.render_template_string(INDEX, vendors=vendors)

@app.route('/api/vendors/<vendor_id>', methods=['PUT', 'GET'])
def update_vendor(vendor_id):
    if flask.request.method == 'GET':
        conn = sqlite3.connect(DB)
        v = conn.execute('SELECT * FROM vendors WHERE vendor_id=?', (vendor_id,)).fetchone()
        conn.close()
        return flask.jsonify(dict(zip(['id','vendor_id','name','category','status','contact_email','pan','gstin','approved_by'], v)) if v else {})
    # VULNERABILITY: No authentication — any client can update vendor status
    body = flask.request.get_json() or {}
    new_status = body.get('status', '')
    logging.critical(f"MASS_ASSIGN vendor_id={vendor_id} new_status={new_status} ip={flask.request.remote_addr} UNAUTHENTICATED")
    conn = sqlite3.connect(DB)
    conn.execute('UPDATE vendors SET status=? WHERE vendor_id=?', (new_status, vendor_id))
    conn.commit()
    v = conn.execute('SELECT * FROM vendors WHERE vendor_id=?', (vendor_id,)).fetchone()
    conn.close()
    return flask.jsonify({'status':'updated','vendor_id':vendor_id,'new_status':new_status})

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=9001, debug=False)
PYEOF

# Port 7443 — HSE Document Repository
# Vulnerability: Unauthenticated document download
mkdir -p "${BASE}/hse-docs"
mkdir -p "${BASE}/hse-docs/documents"
for i in 1 2 3; do
cat > "${BASE}/hse-docs/documents/${i}.txt" << EOF
RPAL HSE Document ID: HSE-DOC-00${i}
Classification: Internal Use Only
${i}. HSE Inspection Report — $(date '+%B %Y')

Site: KG-DWN Platform ${i}
Inspector: kavita.rao@rpal.in
Emergency Contact: +91-9820123456 (RPAL QHSE Hotline)
SAP Project Code: RPAL-OPS-2024-00${i}

Internal LDAP reference: ou=operations,dc=corp,dc=rpal,dc=in
NetMon Agent: monitor.corp.rpal.in (PSK: NetMon@AgentKey!RPAL24)
EOF
done

cat > "${BASE}/hse-docs/app.py" << 'PYEOF'
#!/usr/bin/env python3
import flask, sqlite3, os, logging
app = flask.Flask(__name__)
app.secret_key = b'RPAL-HSE-DOCS-2024'
DB  = '/opt/rpal/supporting-services/hse-docs/docs.db'
DOC_DIR = '/opt/rpal/supporting-services/hse-docs/documents'
logging.basicConfig(level=logging.WARNING)

def init_db():
    conn = sqlite3.connect(DB)
    conn.executescript("""
    CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY, username TEXT, password TEXT);
    CREATE TABLE IF NOT EXISTS documents(id INTEGER PRIMARY KEY, title TEXT, category TEXT, date TEXT, restricted INTEGER);
    INSERT OR IGNORE INTO users VALUES(1,'hse.inspector','HSE@Inspect!24'),(2,'kavita.rao','KavitaRao@OT24');
    INSERT OR IGNORE INTO documents VALUES
        (1,'PTW Procedure — Hot Work RPAL-HSE-HW-003','Hot Work',  '2024-10-01',0),
        (2,'Emergency Response Plan KG-DWN-98/3',    'ERP',       '2024-09-15',1),
        (3,'OISD-116 Compliance Audit FY2024-25',    'Compliance','2024-11-01',1);
    """)
    conn.commit(); conn.close()

init_db()

INDEX = """<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8">
<title>RPAL HSE Document Repository</title>
<style>*{box-sizing:border-box;margin:0;padding:0}body{background:#0f1f0f;color:#c8e6c9;font-family:-apple-system,sans-serif;min-height:100vh}
.header{background:#0a150a;border-bottom:1px solid #1b5e20;height:56px;display:flex;align-items:center;padding:0 28px;justify-content:space-between}
.h-brand{display:flex;align-items:center;gap:10px;font-size:13px;font-weight:700;color:#c8e6c9}
.h-right{font-size:10px;color:#4caf50;font-family:monospace}
.nav{display:flex;gap:4px;padding:0 24px;background:#071207;border-bottom:1px solid #1b5e20}
.nav-btn{padding:8px 14px;font-size:12px;color:#81c784;cursor:pointer;border-bottom:2px solid transparent}
.nav-btn.active{color:#c8e6c9;border-bottom-color:#4caf50}
.main{max-width:960px;margin:0 auto;padding:24px}
.alert{background:rgba(76,175,80,.06);border:1px solid rgba(76,175,80,.2);border-radius:6px;padding:10px 14px;font-size:11px;color:#81c784;font-family:monospace;margin-bottom:20px}
.card{background:#132213;border:1px solid #1b5e20;border-radius:8px;overflow:hidden;margin-bottom:16px}
.card-hd{padding:12px 18px;border-bottom:1px solid #1b5e20;font-size:12px;font-weight:700;color:#4caf50}
table{width:100%;border-collapse:collapse}
th{font-size:10px;color:#4caf50;text-transform:uppercase;padding:9px 14px;text-align:left;border-bottom:1px solid #1b5e20}
td{padding:10px 14px;font-size:12px;font-family:monospace;border-bottom:1px solid rgba(27,94,32,.3)}
.dl-btn{background:transparent;border:1px solid #4caf50;color:#4caf50;padding:3px 10px;border-radius:4px;font-size:10px;text-decoration:none;font-family:monospace}
.login-card{background:#0a150a;border:1px solid #1b5e20;border-radius:8px;padding:20px;margin-bottom:16px;max-width:400px}
.field{margin-bottom:12px}label{display:block;font-size:10px;font-weight:700;color:#4caf50;text-transform:uppercase;margin-bottom:6px;font-family:monospace}
input{width:100%;background:#071207;border:1px solid #1b5e20;border-radius:4px;padding:9px 12px;font-size:13px;color:#c8e6c9;outline:none}
.btn{background:#2e7d32;color:#c8e6c9;border:none;border-radius:4px;padding:10px 20px;font-size:12px;cursor:pointer;font-family:monospace}
.error{color:#ef5350;font-size:11px;font-family:monospace;margin-bottom:10px}
</style></head><body>
<div class="header"><div class="h-brand">🦺 RPAL HSE Document Repository</div><div class="h-right">hse-docs.rpal.in · OISD-116 · ISO 45001</div></div>
<div class="nav"><div class="nav-btn active">Documents</div><div class="nav-btn">Procedures</div><div class="nav-btn">Forms</div></div>
<div class="main">
  <div class="alert">ℹ GET /api/documents/&lt;id&gt;/download serves documents without authentication. Restricted documents are accessible without login.</div>
  {% if not session_user %}
  <div class="login-card">
    <div style="font-size:13px;font-weight:700;color:#4caf50;margin-bottom:14px">HSE Staff Login</div>
    {% if error %}<div class="error">{{ error }}</div>{% endif %}
    <form method="POST" action="/hse/login">
      <div class="field"><label>Username</label><input name="username" autocomplete="off"></div>
      <div class="field"><label>Password</label><input type="password" name="password"></div>
      <button class="btn" type="submit">Sign In</button>
    </form>
  </div>
  {% endif %}
  <div class="card"><div class="card-hd">Document Library</div>
    <table><thead><tr><th>Title</th><th>Category</th><th>Date</th><th>Download</th></tr></thead>
    <tbody>{% for d in docs %}<tr>
      <td>{{ d[1] }}</td><td>{{ d[2] }}</td><td>{{ d[3] }}</td>
      <td><a class="dl-btn" href="/api/documents/{{ d[0] }}/download">Download</a></td>
    </tr>{% endfor %}</tbody></table>
  </div>
</div></body></html>"""

@app.route('/')
def index():
    conn = sqlite3.connect(DB); docs = conn.execute('SELECT * FROM documents').fetchall(); conn.close()
    return flask.render_template_string(INDEX, docs=docs, session_user=flask.session.get('user'), error=None)

@app.route('/hse/login', methods=['POST'])
def login():
    u = flask.request.form.get('username',''); p = flask.request.form.get('password','')
    conn = sqlite3.connect(DB)
    user = conn.execute('SELECT * FROM users WHERE username=? AND password=?',(u,p)).fetchone(); conn.close()
    if user: flask.session['user'] = user[1]; return flask.redirect('/')
    conn = sqlite3.connect(DB); docs = conn.execute('SELECT * FROM documents').fetchall(); conn.close()
    return flask.render_template_string(INDEX, docs=docs, session_user=None, error='Invalid credentials.')

@app.route('/api/documents/<int:doc_id>/download')
def download(doc_id):
    # VULNERABILITY: No auth check — restricted documents accessible without login
    logging.critical(f"DOC_DOWNLOAD id={doc_id} ip={flask.request.remote_addr} auth={'user' in flask.session}")
    doc_path = os.path.join(DOC_DIR, f'{doc_id}.txt')
    if os.path.exists(doc_path):
        return flask.send_file(doc_path, as_attachment=True, download_name=f'HSE-DOC-{doc_id:03d}.txt')
    return flask.jsonify({'error':'Not found'}), 404

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=7443, debug=False)
PYEOF

# Port 8800 — Invoice Portal
# Vulnerability: IDOR on invoice_id parameter
mkdir -p "${BASE}/invoice-portal"
cat > "${BASE}/invoice-portal/app.py" << 'PYEOF'
#!/usr/bin/env python3
import flask, sqlite3, os, logging
app = flask.Flask(__name__)
app.secret_key = b'RPAL-INVOICE-2024'
DB  = '/opt/rpal/supporting-services/invoice-portal/invoices.db'
logging.basicConfig(level=logging.WARNING)

def init_db():
    conn = sqlite3.connect(DB)
    conn.executescript("""
    CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY, username TEXT, password TEXT, vendor_id TEXT);
    CREATE TABLE IF NOT EXISTS invoices(id INTEGER PRIMARY KEY, invoice_no TEXT, vendor_id TEXT,
        amount REAL, description TEXT, bank_account TEXT, ifsc TEXT, status TEXT, submitted TEXT);
    INSERT OR IGNORE INTO users VALUES
        (1,'contractor.01','c01inv!','VND-001'),(2,'contractor.02','c02inv!','VND-003');
    INSERT OR IGNORE INTO invoices VALUES
        (1,'INV-2024-0091','VND-001',4850000.00,'Offshore drilling services KG-DWN-98/3 Q3 2024',
         '1234567890','HDFC0001234','APPROVED','2024-10-01'),
        (2,'INV-2024-0092','VND-002',1200000.00,'Engineering consultancy MB-OSN-2005/2',
         '9876543210','ICIC0004321','PENDING','2024-10-15'),
        (3,'INV-2024-0093','VND-001',2750000.00,'Pipeline maintenance Hazira terminal',
         '1234567890','HDFC0001234','UNDER_REVIEW','2024-11-01'),
        (4,'INV-2024-0094','VND-003',890000.00','L&T EPC services — internal rate contract',
         '1111222233','SBIN0007890','APPROVED','2024-11-10');
    """)
    conn.commit(); conn.close()

init_db()

INDEX = """<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8">
<title>RPAL Contractor Invoice &amp; Payment Portal</title>
<style>*{box-sizing:border-box;margin:0;padding:0}body{background:#f9fafb;font-family:-apple-system,sans-serif;min-height:100vh}
.topbar{background:#fff;border-bottom:2px solid #f59e0b;height:58px;display:flex;align-items:center;padding:0 28px;justify-content:space-between}
.tb-brand{display:flex;align-items:center;gap:12px}
.inv-icon{width:34px;height:34px;background:linear-gradient(135deg,#f59e0b,#d97706);border-radius:7px;display:flex;align-items:center;justify-content:center;font-size:16px}
.tb-title{font-size:14px;font-weight:700;color:#1a2130}.tb-sub{font-size:10px;color:#6b7589;font-family:monospace;margin-top:2px}
.wrapper{flex:1;display:flex;align-items:center;justify-content:center;padding:40px;min-height:calc(100vh - 58px)}
.card{background:#fff;border:1px solid #dde3ec;border-radius:10px;width:100%;max-width:440px;overflow:hidden}
.card-hd{background:linear-gradient(135deg,#d97706,#f59e0b);padding:24px;text-align:center;color:#fff}
.hd-icon{font-size:26px;margin-bottom:8px}.hd-title{font-size:15px;font-weight:700}.hd-sub{font-size:10px;opacity:.8;font-family:monospace}
.card-body{padding:24px}
.error{background:#fef2f2;border:1px solid #fecaca;border-radius:6px;padding:10px;font-size:12px;color:#b91c1c;margin-bottom:12px}
.field{margin-bottom:14px}label{display:block;font-size:10px;font-weight:700;color:#6b7589;text-transform:uppercase;letter-spacing:.7px;margin-bottom:6px}
input{width:100%;background:#f8f9fc;border:1.5px solid #dde3ec;border-radius:6px;padding:11px 13px;font-size:14px;color:#1a2130;outline:none}
.btn{width:100%;background:linear-gradient(135deg,#d97706,#f59e0b);color:#fff;border:none;border-radius:6px;padding:12px;font-size:14px;font-weight:700;cursor:pointer}
</style></head><body>
<div class="topbar"><div class="tb-brand"><div class="inv-icon">💳</div><div>
  <div class="tb-title">RPAL Contractor Invoice &amp; Payment Portal</div>
  <div class="tb-sub">invoice.rpal.in · RPAL Finance Division · SAP Integration</div>
</div></div></div>
<div class="wrapper"><div class="card">
  <div class="card-hd"><div class="hd-icon">📄</div><div class="hd-title">Invoice Submission &amp; Payment Status</div><div class="hd-sub">invoice.rpal.in · Accounts Payable</div></div>
  <div class="card-body">
    {% if error %}<div class="error">{{ error }}</div>{% endif %}
    <form method="POST" action="/invoice/login">
      <div class="field"><label>Contractor ID</label><input name="username" placeholder="e.g. contractor.01" autocomplete="off"></div>
      <div class="field"><label>Password</label><input type="password" name="password"></div>
      <button class="btn" type="submit">Access Invoice Portal →</button>
    </form>
  </div>
</div></div></body></html>"""

DASHBOARD = """<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"><title>My Invoices — RPAL</title>
<style>*{box-sizing:border-box;margin:0;padding:0}body{background:#f9fafb;font-family:-apple-system,sans-serif}
.topbar{background:#fff;border-bottom:2px solid #f59e0b;height:52px;display:flex;align-items:center;padding:0 24px;justify-content:space-between;font-size:13px;font-weight:700;color:#1a2130}
.h-right{font-weight:400;font-size:12px;display:flex;gap:12px;align-items:center}
.pill{background:#fef3c7;color:#d97706;padding:3px 10px;border-radius:12px;font-size:11px}
.logout{color:#9ca3af;text-decoration:none}
.main{max-width:900px;margin:0 auto;padding:28px}
.alert{background:#fffbeb;border:1px solid #fde68a;border-radius:6px;padding:10px 16px;font-size:11px;color:#b45309;margin-bottom:20px;font-family:monospace}
.card{background:#fff;border:1px solid #dde3ec;border-radius:8px;overflow:hidden}
.card-hd{padding:12px 20px;border-bottom:1px solid #dde3ec;font-size:12px;font-weight:700;color:#d97706}
table{width:100%;border-collapse:collapse}
th{font-size:10px;color:#6b7589;text-transform:uppercase;padding:9px 16px;text-align:left;border-bottom:1px solid #dde3ec;background:#fafbfc}
td{padding:10px 16px;font-size:11px;font-family:monospace;border-bottom:1px solid rgba(221,227,236,.4)}
.view-btn{background:#f59e0b;color:#fff;padding:3px 10px;border-radius:4px;font-size:10px;text-decoration:none}
.status-approved{color:#16a34a;font-weight:700}.status-pending{color:#d97706}.status-under_review{color:#7c3aed}
</style></head><body>
<div class="topbar">💳 RPAL Invoice Portal
  <div class="h-right"><span class="pill">{{ username }}</span><a class="logout" href="/invoice/logout">Sign Out</a></div>
</div>
<div class="main">
  <div class="alert">⚠ GET /api/invoices/&lt;id&gt; does not verify that the invoice belongs to the logged-in contractor. Change the id to access other vendors' invoices and bank details.</div>
  <div class="card"><div class="card-hd">My Invoices</div>
    <table><thead><tr><th>Invoice No.</th><th>Amount</th><th>Description</th><th>Status</th><th>Detail</th></tr></thead>
    <tbody>{% for inv in invoices %}<tr>
      <td>{{ inv[1] }}</td><td>₹{{ "{:,.0f}".format(inv[3]) }}</td><td>{{ inv[4][:50] }}</td>
      <td class="status-{{ inv[7]|lower }}">{{ inv[7] }}</td>
      <td><a class="view-btn" href="/api/invoices/{{ inv[0] }}">View</a></td>
    </tr>{% endfor %}</tbody></table>
  </div>
</div></body></html>"""

@app.route('/')
def index(): return flask.render_template_string(INDEX, error=None)

@app.route('/invoice/login', methods=['POST'])
def login():
    u = flask.request.form.get('username',''); p = flask.request.form.get('password','')
    conn = sqlite3.connect(DB)
    user = conn.execute('SELECT * FROM users WHERE username=? AND password=?',(u,p)).fetchone(); conn.close()
    if user:
        flask.session['uid'] = user[0]; flask.session['vendor_id'] = user[3]; flask.session['user'] = user[1]
        return flask.redirect('/invoice/dashboard')
    return flask.render_template_string(INDEX, error='Invalid credentials.')

@app.route('/invoice/dashboard')
def dashboard():
    if 'uid' not in flask.session: return flask.redirect('/')
    conn = sqlite3.connect(DB)
    invs = conn.execute('SELECT * FROM invoices WHERE vendor_id=?',(flask.session['vendor_id'],)).fetchall(); conn.close()
    return flask.render_template_string(DASHBOARD, username=flask.session['user'], invoices=invs)

@app.route('/api/invoices/<int:inv_id>')
def invoice_detail(inv_id):
    if 'uid' not in flask.session: return flask.jsonify({'error':'Login required'}), 401
    # VULNERABILITY: IDOR — no check that invoice belongs to logged-in vendor
    # Attacker can enumerate /api/invoices/1 through /api/invoices/N to see all vendors' bank details
    logging.critical(f"INVOICE_ACCESS id={inv_id} user={flask.session.get('user')} ip={flask.request.remote_addr}")
    conn = sqlite3.connect(DB)
    inv = conn.execute('SELECT * FROM invoices WHERE id=?',(inv_id,)).fetchone(); conn.close()
    if not inv: return flask.jsonify({'error':'Not found'}), 404
    return flask.jsonify({'id':inv[0],'invoice_no':inv[1],'vendor_id':inv[2],'amount':inv[3],
        'description':inv[4],'bank_account':inv[5],'ifsc':inv[6],'status':inv[7],'submitted':inv[8]})

@app.route('/invoice/logout')
def logout(): flask.session.clear(); return flask.redirect('/')

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8800, debug=False)
PYEOF

for SVC_NAME in vendor-mgmt hse-docs invoice-portal; do
    case $SVC_NAME in
        vendor-mgmt) PORT=9001; TITLE="RPAL Vendor Management System — Procurement Portal";;
        hse-docs) PORT=7443; TITLE="RPAL HSE Document Repository — OISD Compliance Library";;
        invoice-portal) PORT=8800; TITLE="RPAL Contractor Invoice and Payment Portal";;
    esac
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

for SVC_DEF in \
    "8883|rpal-mqtt-iot|RPAL IoT MQTT Broker|\x20\x02\x00\x00RPAL-MQTT-3.1.1 on contractor.rpal.in:8883\r\nAuth required. Topics: rpal/contractor/+/location\r\n" \
    "21|rpal-document-ftp|RPAL Document Submission FTP|220 RPAL Document FTP Server v2.0 (contractor.rpal.in)\r\n331 Password required — use Contractor ID as username\r\n530 Login incorrect.\r\n221 Goodbye.\r\n" \
    "3306|rpal-procurement-db|RPAL Procurement Database|\x4a\x00\x00\x00\n8.0.35-RPAL-Procurement\x00\x01\x00\x00\x00MySQL 8.0.35 RPAL Procurement DB — SSL required.\r\n" \
    "445|rpal-smb-docshare|RPAL Document Share SMB|\x00\x00\x00\x45\xffSMBr\x00\x00RPAL-DOCSHARE contractor.rpal.in\r\nShare: \\\\contractor.rpal.in\\HSEDocs\r\nAuth: NTLM required\r\n"; do
    IFS='|' read -r PORT SVC_NAME SVC_TITLE BANNER <<< "$SVC_DEF"
    cat > "/etc/systemd/system/${SVC_NAME}.service" << SVCEOF
[Unit]
Description=${SVC_TITLE}
After=network.target
[Service]
Type=simple
User=nobody
ExecStart=/bin/bash -c "while true; do printf '${BANNER}' | nc -l -p ${PORT} -q 1 2>/dev/null || true; sleep 1; done"
Restart=always
RestartSec=5
[Install]
WantedBy=multi-user.target
SVCEOF
    systemctl daemon-reload; systemctl enable "${SVC_NAME}" --now 2>/dev/null || true
    info "TCP  :${PORT} → ${SVC_TITLE}"
done

log "M5 supporting services deployment complete."
info "Web: :9001 (Vendor Mgmt)  :7443 (HSE Docs)  :8800 (Invoice Portal)"
info "TCP: :8883 (MQTT)  :21 (FTP)  :3306 (MySQL)  :445 (SMB)"
