#!/usr/bin/env bash
# M3-ext-soap-gateway.sh — RPAL M3 Supporting Infrastructure
set -euo pipefail
[[ $EUID -ne 0 ]] && { echo "Run as root: sudo bash $0"; exit 1; }
GREEN='\033[0;32m'; CYAN='\033[0;36m'; NC='\033[0m'
log()  { echo -e "${GREEN}[RPAL-EXT]${NC} $*"; }
info() { echo -e "${CYAN}[+]${NC} $*"; }
BASE="/opt/rpal/supporting-services"
mkdir -p "$BASE"
log "Deploying RPAL M3 supporting infrastructure services..."

# ── Web Portal 1: PNGRB Tariff Portal — Port 8081 ────────────────────────────
# Vulnerability: Default credentials (pngrb_admin / PNGRB@2024)
mkdir -p "${BASE}/pngrb-portal"
cat > "${BASE}/pngrb-portal/app.py" << 'PYEOF'
#!/usr/bin/env python3
import flask, sqlite3, os, logging
app = flask.Flask(__name__)
app.secret_key = b'PNGRB-PORTAL-2024'
DB  = '/opt/rpal/supporting-services/pngrb-portal/pngrb.db'
logging.basicConfig(level=logging.WARNING)

def init_db():
    conn = sqlite3.connect(DB)
    conn.executescript("""
    CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY, username TEXT, password TEXT, role TEXT);
    CREATE TABLE IF NOT EXISTS tariff_orders(id INTEGER PRIMARY KEY, order_no TEXT, pipeline TEXT,
        tariff_rs REAL, operator TEXT, effective TEXT, internal_notes TEXT);
    INSERT OR IGNORE INTO users VALUES
        (1,'pngrb_admin','PNGRB@2024','admin'),
        (2,'tariff.analyst','TariffAna!2024','analyst');
    INSERT OR IGNORE INTO tariff_orders VALUES
        (1,'PNGRB/T4S/HHPL/2024/01','HVJ-DVPL',37.42,'RPAL','2024-04-01',
         'Operator lobbied for rate increase. Approved 8% above CPI — internal directive D/PNGRB/2024/0091'),
        (2,'PNGRB/T4S/GREP/2023/08','GREP-I',44.67,'RPAL','2023-10-01',
         'Dispute with GAIL unresolved. Provisional order — do not publish final until Q1 2025');
    """)
    conn.commit(); conn.close()

init_db()

INDEX = """<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8">
<title>PNGRB Tariff Regulatory Portal — RPAL Interface</title>
<style>*{box-sizing:border-box;margin:0;padding:0}body{background:#f4f6fa;font-family:-apple-system,sans-serif}
.gov-bar{background:linear-gradient(90deg,#ff9933 33%,#fff 33%,#fff 66%,#138808 66%);height:6px}
.header{background:#1a237e;color:#fff;padding:0 28px;height:62px;display:flex;align-items:center;gap:16px}
.emblem{width:42px;height:42px;border:2px solid rgba(255,255,255,.35);border-radius:50%;display:flex;align-items:center;justify-content:center;font-size:18px;font-weight:900}
.h-main{font-size:14px;font-weight:700}.h-sub{font-size:10px;opacity:.65;font-family:monospace}
.main{max-width:980px;margin:0 auto;padding:28px}
.card{background:#fff;border:1px solid #c5cae9;border-radius:8px;padding:20px;margin-bottom:16px}
.card h2{font-size:13px;font-weight:700;color:#1a237e;margin-bottom:14px}
.field{margin-bottom:14px}label{display:block;font-size:10px;font-weight:700;color:#555;text-transform:uppercase;letter-spacing:.7px;margin-bottom:6px}
input{width:100%;background:#fafafa;border:1.5px solid #c5cae9;border-radius:6px;padding:10px 13px;font-size:14px;outline:none}
.btn{background:#1a237e;color:#fff;border:none;border-radius:6px;padding:11px 24px;font-size:13px;font-weight:700;cursor:pointer;width:100%}
.error{background:#fce4ec;border:1px solid #ef9a9a;border-radius:6px;padding:10px;font-size:12px;color:#b71c1c;margin-bottom:12px}
</style></head><body>
<div class="gov-bar"></div>
<div class="header"><div class="emblem">⊕</div><div>
  <div class="h-main">Petroleum &amp; Natural Gas Regulatory Board — Tariff Portal</div>
  <div class="h-sub">Third Party Access · Tariff Orders · Pipeline Regulations</div>
</div></div>
<div class="main"><div class="card"><h2>PNGRB Official Login</h2>
  {% if error %}<div class="error">{{ error }}</div>{% endif %}
  <form method="POST" action="/pngrb/login">
    <div class="field"><label>Username</label><input name="username" placeholder="Official username" autocomplete="off"></div>
    <div class="field"><label>Password</label><input type="password" name="password"></div>
    <button class="btn" type="submit">Sign In</button>
  </form>
</div></div></body></html>"""

DASHBOARD = """<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"><title>PNGRB Tariff Orders</title>
<style>*{box-sizing:border-box;margin:0;padding:0}body{background:#f4f6fa;font-family:-apple-system,sans-serif}
.header{background:#1a237e;color:#fff;padding:0 28px;height:52px;display:flex;align-items:center;justify-content:space-between;font-size:13px;font-weight:700}
.h-right{font-weight:400;font-size:12px;display:flex;gap:12px;align-items:center}
.pill{background:rgba(255,255,255,.15);padding:3px 10px;border-radius:12px}
.logout{color:rgba(255,255,255,.7);text-decoration:none}
.main{max-width:900px;margin:0 auto;padding:28px}
.card{background:#fff;border:1px solid #c5cae9;border-radius:8px;overflow:hidden}
.card-hd{padding:12px 18px;border-bottom:1px solid #e8eaf6;font-size:12px;font-weight:700;color:#1a237e}
table{width:100%;border-collapse:collapse}
th{font-size:10px;color:#546e7a;text-transform:uppercase;letter-spacing:.7px;padding:9px 14px;text-align:left;border-bottom:1px solid #e8eaf6;background:#f9f9ff}
td{padding:10px 14px;font-size:12px;font-family:monospace;border-bottom:1px solid #f0f0f8}
.note{color:#b71c1c;font-size:11px}
</style></head><body>
<div class="header">PNGRB Tariff Portal
  <div class="h-right"><span class="pill">{{ username }}</span><a class="logout" href="/pngrb/logout">Sign Out</a></div>
</div>
<div class="main">
<div class="card"><div class="card-hd">Tariff Orders Register — Confidential</div>
<table><thead><tr><th>Order No.</th><th>Pipeline</th><th>Rate (Rs/MSCMD/100km)</th><th>Effective</th><th>Internal Notes</th></tr></thead>
<tbody>{% for o in orders %}<tr>
  <td>{{ o[1] }}</td><td>{{ o[2] }}</td><td>{{ o[3] }}</td><td>{{ o[5] }}</td>
  <td class="note">{{ o[6] }}</td>
</tr>{% endfor %}</tbody></table></div></div></body></html>"""

@app.route('/')
def index(): return flask.render_template_string(INDEX, error=None)

@app.route('/pngrb/login', methods=['POST'])
def login():
    u = flask.request.form.get('username','')
    p = flask.request.form.get('password','')
    conn = sqlite3.connect(DB)
    user = conn.execute('SELECT * FROM users WHERE username=? AND password=?',(u,p)).fetchone()
    conn.close()
    if user:
        flask.session['user'] = user[1]
        return flask.redirect('/pngrb/dashboard')
    return flask.render_template_string(INDEX, error='Invalid credentials.')

@app.route('/pngrb/dashboard')
def dashboard():
    if 'user' not in flask.session: return flask.redirect('/')
    conn = sqlite3.connect(DB)
    orders = conn.execute('SELECT * FROM tariff_orders').fetchall()
    conn.close()
    return flask.render_template_string(DASHBOARD, username=flask.session['user'], orders=orders)

@app.route('/pngrb/logout')
def logout(): flask.session.clear(); return flask.redirect('/')

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8081, debug=False)
PYEOF

# ── Web Portal 2: Pipeline SCADA HMI — Port 9090 ─────────────────────────────
# Vulnerability: No authentication on control panel — alarm acknowledgment and
# valve status endpoints accessible without credentials
mkdir -p "${BASE}/pipeline-scada"
cat > "${BASE}/pipeline-scada/app.py" << 'PYEOF'
#!/usr/bin/env python3
import flask, json, logging, time
app = flask.Flask(__name__)
logging.basicConfig(level=logging.WARNING)

valve_states = {"EV-HVJ-001": "CLOSED", "EV-HVJ-002": "CLOSED", "EV-DVPL-001": "CLOSED"}
alarms = [
    {"id":"ALM-0091","tag":"PT-HVJ-003","desc":"Pressure high at Hazira compressor inlet","severity":"HIGH","acked":False},
    {"id":"ALM-0087","tag":"FT-DVPL-012","desc":"Flow anomaly detected — GREP-I segment","severity":"MEDIUM","acked":False},
]

INDEX = """<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8">
<title>RPAL Pipeline SCADA — Web HMI</title>
<style>*{box-sizing:border-box;margin:0;padding:0}:root{--bg:#0a0f1a;--surface:#0d1420;--green:#00e676;--amber:#ffb300;--red:#ef5350;--text:#c9d1d9;--mono:"SF Mono",Consolas,monospace}
body{background:var(--bg);color:var(--text);font-family:var(--mono);min-height:100vh}
.header{background:var(--surface);border-bottom:2px solid var(--green);height:52px;display:flex;align-items:center;padding:0 24px;justify-content:space-between}
.h-title{font-size:13px;font-weight:700;color:var(--green);letter-spacing:2px;text-transform:uppercase}
.h-status{display:flex;align-items:center;gap:8px;font-size:11px;color:var(--green)}
.dot{width:7px;height:7px;background:var(--green);border-radius:50%;animation:p 1.5s infinite}@keyframes p{0%,100%{opacity:1}50%{opacity:.2}}
.main{max-width:1000px;margin:0 auto;padding:24px}
.alert-box{background:rgba(239,83,80,.08);border:1px solid rgba(239,83,80,.3);border-radius:6px;padding:12px 16px;margin-bottom:20px;font-size:12px;color:#ef9a9a}
.grid{display:grid;grid-template-columns:repeat(3,1fr);gap:16px;margin-bottom:24px}
.metric{background:var(--surface);border:1px solid #1b3344;border-radius:6px;padding:16px}
.m-label{font-size:10px;color:#546e7a;text-transform:uppercase;letter-spacing:.8px;margin-bottom:8px}
.m-val{font-size:22px;font-weight:700;color:var(--green)}.m-unit{font-size:10px;color:#546e7a;margin-top:3px}
.card{background:var(--surface);border:1px solid #1b3344;border-radius:6px;padding:18px;margin-bottom:16px}
.card-title{font-size:11px;color:var(--green);text-transform:uppercase;letter-spacing:1px;margin-bottom:14px}
table{width:100%;border-collapse:collapse}
th{font-size:10px;color:#546e7a;text-transform:uppercase;padding:8px 12px;text-align:left;border-bottom:1px solid #1b3344}
td{padding:10px 12px;font-size:12px;border-bottom:1px solid rgba(27,51,68,.4)}
.btn-ack{background:transparent;border:1px solid var(--amber);color:var(--amber);padding:3px 10px;border-radius:4px;font-size:10px;font-family:var(--mono);cursor:pointer}
.btn-valve{background:transparent;border:1px solid #546e7a;color:#546e7a;padding:3px 10px;border-radius:4px;font-size:10px;font-family:var(--mono);cursor:pointer}
.no-auth{background:rgba(239,83,80,.06);border:1px solid rgba(239,83,80,.2);border-radius:4px;padding:6px 10px;font-size:10px;color:#ef9a9a;margin-bottom:12px}
</style></head><body>
<div class="header">
  <div class="h-title">RPAL Pipeline SCADA — Web HMI v4.2</div>
  <div class="h-status"><div class="dot"></div>23 STATIONS ONLINE</div>
</div>
<div class="main">
  <div class="alert-box">⚠ ALM-0091: Pressure high at Hazira compressor inlet — PT-HVJ-003 · Acknowledge required</div>
  <div class="no-auth">ℹ This HMI interface has no authentication. Control endpoints are accessible without credentials. POST /scada/ack and POST /scada/valve are open.</div>
  <div class="grid">
    <div class="metric"><div class="m-label">Line Pressure (HVJ)</div><div class="m-val">47.3</div><div class="m-unit">kg/cm² · NORMAL</div></div>
    <div class="metric"><div class="m-label">Flow Rate (GREP-I)</div><div class="m-val">18.4</div><div class="m-unit">MMSCMD · NOMINAL</div></div>
    <div class="metric"><div class="m-label">Emergency Valves</div><div class="m-val" style="color:#00e676">0</div><div class="m-unit">OPEN · All closed</div></div>
  </div>
  <div class="card">
    <div class="card-title">Active Alarms</div>
    <table><thead><tr><th>Alarm ID</th><th>Tag</th><th>Description</th><th>Severity</th><th>Action</th></tr></thead>
    <tbody id="alarms">
      <tr><td>ALM-0091</td><td>PT-HVJ-003</td><td>Pressure high at Hazira compressor inlet</td><td style="color:#ef5350">HIGH</td>
        <td><button class="btn-ack" onclick="fetch('/scada/ack',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({alarm_id:'ALM-0091'})}).then(r=>r.json()).then(d=>alert(JSON.stringify(d)))">ACK</button></td></tr>
      <tr><td>ALM-0087</td><td>FT-DVPL-012</td><td>Flow anomaly — GREP-I segment</td><td style="color:#ffb300">MEDIUM</td>
        <td><button class="btn-ack" onclick="fetch('/scada/ack',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({alarm_id:'ALM-0087'})}).then(r=>r.json()).then(d=>alert(JSON.stringify(d)))">ACK</button></td></tr>
    </tbody></table>
  </div>
  <div class="card">
    <div class="card-title">Emergency Valve Control</div>
    <table><thead><tr><th>Valve Tag</th><th>Location</th><th>Current State</th><th>Control</th></tr></thead>
    <tbody>
      <tr><td>EV-HVJ-001</td><td>Hazira Inlet</td><td>CLOSED</td><td><button class="btn-valve" onclick="fetch('/scada/valve',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({valve:'EV-HVJ-001',state:'OPEN'})}).then(r=>r.json()).then(d=>alert(JSON.stringify(d)))">OPEN</button></td></tr>
      <tr><td>EV-DVPL-001</td><td>Vijaipur Inlet</td><td>CLOSED</td><td><button class="btn-valve" onclick="fetch('/scada/valve',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({valve:'EV-DVPL-001',state:'OPEN'})}).then(r=>r.json()).then(d=>alert(JSON.stringify(d)))">OPEN</button></td></tr>
    </tbody></table>
  </div>
</div></body></html>"""

@app.route('/')
def index():
    logging.warning(f"SCADA_ACCESS ip={flask.request.remote_addr}")
    return flask.render_template_string(INDEX)

@app.route('/scada/ack', methods=['POST'])
def ack_alarm():
    alarm_id = flask.request.json.get('alarm_id','')
    logging.critical(f"ALARM_ACK alarm_id={alarm_id} ip={flask.request.remote_addr} UNAUTHENTICATED")
    return flask.jsonify({'status':'acknowledged','alarm_id':alarm_id,'operator':'UNAUTHENTICATED','timestamp':time.time()})

@app.route('/scada/valve', methods=['POST'])
def valve_control():
    valve = flask.request.json.get('valve','')
    state = flask.request.json.get('state','')
    logging.critical(f"VALVE_CONTROL valve={valve} state={state} ip={flask.request.remote_addr} UNAUTHENTICATED")
    valve_states[valve] = state
    return flask.jsonify({'status':'command_sent','valve':valve,'new_state':state,'operator':'UNAUTHENTICATED'})

@app.route('/scada/status')
def status():
    return flask.jsonify({'online':True,'stations':23,'alarms':len(alarms),'valves':valve_states})

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=9090, debug=False)
PYEOF

# ── Web Portal 3: WS-Security Certificate Portal — Port 7080 ─────────────────
# Vulnerability: Unauthenticated certificate export — GET /certs/export?cn=<name>
# returns the certificate file without any authentication
mkdir -p "${BASE}/wssec-certs"
cat > "${BASE}/wssec-certs/app.py" << 'PYEOF'
#!/usr/bin/env python3
import flask, os, logging, datetime
app = flask.Flask(__name__)
CERT_DIR = '/opt/rpal/supporting-services/wssec-certs/certs'
os.makedirs(CERT_DIR, exist_ok=True)
logging.basicConfig(level=logging.WARNING)

# Plant realistic certificate files
for cn, content in [
    ('rpal-tariff-gw-2024',
     '-----BEGIN CERTIFICATE-----\nMIICxDCCAaygAwIBAgIUZmFrZUNlcnRGb3JSUFBBTFR5cGUwDQYJKoZIhvcNAQEL\nCN=rpal-tariff-gw-2024,O=Rashtriya Petroleum Anveshan Limited,C=IN\nIssuer: CN=RPAL-RootCA-2022\nExpires: 2025-11-30\n[Certificate content for SOAP gateway TLS]\nPrivateKey_Hint: key stored at /etc/rpal/tls/tariff-gw.key\nSOAP_SVC_PASSWORD: TariffGW@Soap!2024#RPAL\n-----END CERTIFICATE-----'),
    ('rpal-pngrb-intf-2024',
     '-----BEGIN CERTIFICATE-----\nCN=rpal-pngrb-intf-2024,O=RPAL,C=IN\nIssuer: PNGRB-RootCA-2022\nExpires: 2025-06-15\n[PNGRB Interface Certificate]\n-----END CERTIFICATE-----'),
]:
    open(os.path.join(CERT_DIR, f'{cn}.crt'), 'w').write(content)

INDEX = """<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8">
<title>RPAL WS-Security Certificate Management</title>
<style>*{box-sizing:border-box;margin:0;padding:0}body{background:#f0f2f5;font-family:-apple-system,sans-serif}
.header{background:#263238;color:#fff;padding:0 28px;height:56px;display:flex;align-items:center;gap:12px}
.cert-icon{font-size:22px}.h-main{font-size:14px;font-weight:700}.h-sub{font-size:10px;opacity:.6;font-family:monospace}
.main{max-width:900px;margin:0 auto;padding:28px}
.card{background:#fff;border:1px solid #dde3ec;border-radius:8px;padding:20px;margin-bottom:16px}
.card h2{font-size:13px;font-weight:700;color:#263238;margin-bottom:14px;text-transform:uppercase;letter-spacing:.5px;font-family:monospace}
.cert-row{display:flex;justify-content:space-between;align-items:center;padding:10px 0;border-bottom:1px solid #f0f2f5}
.cert-name{font-size:12px;font-family:monospace;color:#37474f}
.cert-expiry{font-size:10px;color:#546e7a;font-family:monospace}
.cert-status{font-size:10px;padding:2px 8px;border-radius:4px;font-weight:700}
.valid{background:#e8f5e9;color:#2e7d32}.expiring{background:#fff3e0;color:#e65100}
.dl-btn{background:#263238;color:#fff;padding:4px 12px;border-radius:4px;text-decoration:none;font-size:11px;font-family:monospace}
</style></head><body>
<div class="header"><div class="cert-icon">🔐</div><div>
  <div class="h-main">RPAL WS-Security X.509 Certificate Management</div>
  <div class="h-sub">tariff-gw.rpal.in · SOAP Security Certificate Authority</div>
</div></div>
<div class="main"><div class="card"><h2>Active Service Certificates</h2>
  <div class="cert-row">
    <div><div class="cert-name">rpal-tariff-gw-2024</div><div class="cert-expiry">Expires: 2025-11-30</div></div>
    <div style="display:flex;align-items:center;gap:10px">
      <span class="cert-status valid">VALID</span>
      <a class="dl-btn" href="/certs/export?cn=rpal-tariff-gw-2024">Export</a>
    </div>
  </div>
  <div class="cert-row">
    <div><div class="cert-name">rpal-pngrb-intf-2024</div><div class="cert-expiry">Expires: 2025-06-15</div></div>
    <div style="display:flex;align-items:center;gap:10px">
      <span class="cert-status expiring">EXPIRING SOON</span>
      <a class="dl-btn" href="/certs/export?cn=rpal-pngrb-intf-2024">Export</a>
    </div>
  </div>
</div></div></body></html>"""

@app.route('/')
def index(): return flask.render_template_string(INDEX)

@app.route('/certs/export')
def export_cert():
    cn = flask.request.args.get('cn', '')
    # VULNERABILITY: No authentication check before serving certificate files
    # The certificate for rpal-tariff-gw-2024 contains the SOAP service password
    logging.critical(f"CERT_EXPORT cn={cn} ip={flask.request.remote_addr} NO_AUTH")
    cert_path = os.path.join(CERT_DIR, f'{cn}.crt')
    if os.path.exists(cert_path):
        content = open(cert_path).read()
        return flask.Response(content, mimetype='application/x-pem-file',
            headers={'Content-Disposition': f'attachment; filename="{cn}.crt"'})
    return flask.jsonify({'error': 'Certificate not found'}), 404

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=7080, debug=False)
PYEOF

for SVC_NAME in pngrb-portal pipeline-scada wssec-certs; do
    case $SVC_NAME in
        pngrb-portal) PORT=8081; TITLE="RPAL PNGRB Tariff Regulatory Portal";;
        pipeline-scada) PORT=9090; TITLE="RPAL Pipeline SCADA Web HMI Interface";;
        wssec-certs) PORT=7080; TITLE="RPAL WS-Security Certificate Management Portal";;
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
    "443|rpal-soap-tls|RPAL SOAP Gateway TLS Endpoint|HTTP/1.1 400 Bad Request\r\nServer: RPAL-TariffGW/2.3.0\r\n\r\n<error>TLS required. Plain HTTP received on :443.</error>\r\n" \
    "502|rpal-modbus-gw|RPAL Modbus TCP Gateway|\x00\x01\x00\x00\x00\x06\x01\x83\x02RPAL-Modbus-GW/1.0 on tariff-gw.rpal.in:502\r\n" \
    "102|rpal-s7-gateway|RPAL Siemens S7 PLC Gateway|\x03\x00\x00\x16\x11\xd0\x00\x01\x00\x0aRPAL-S7-GW pipeline sensor interface\r\n" \
    "10514|rpal-syslog-collector|RPAL Centralised Syslog Collector|<134>Nov 15 03:22:00 tariff-gw rpal-tariff-gateway[1234]: SOAP_REQUEST endpoint=CalculateTariff status=OK\r\n"; do
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

log "M3 supporting services deployment complete."
info "Web: :8081 (PNGRB Portal)  :9090 (Pipeline SCADA)  :7080 (WS-Sec Certs)"
info "TCP: :443 (SOAP-TLS)  :502 (Modbus)  :102 (S7 PLC)  :10514 (Syslog)"
