#!/usr/bin/env bash
# M4-ext-haproxy.sh — RPAL M4 Supporting Infrastructure
set -euo pipefail
[[ $EUID -ne 0 ]] && { echo "Run as root: sudo bash $0"; exit 1; }
GREEN='\033[0;32m'; CYAN='\033[0;36m'; NC='\033[0m'
log()  { echo -e "${GREEN}[RPAL-EXT]${NC} $*"; }
info() { echo -e "${CYAN}[+]${NC} $*"; }
BASE="/opt/rpal/supporting-services"
mkdir -p "$BASE"
log "Deploying RPAL M4 supporting infrastructure services..."

# Port 8404 — Kong Gateway Manager
# Vulnerability: /api/v2/services returns all service configs including upstream credentials
mkdir -p "${BASE}/kong-manager"
cat > "${BASE}/kong-manager/app.py" << 'PYEOF'
#!/usr/bin/env python3
import flask, logging
app = flask.Flask(__name__)
logging.basicConfig(level=logging.WARNING)

SERVICES = [
    {"id":"svc-001","name":"rpal-permit-portal","protocol":"http","host":"203.x.x.10","port":8443,
     "path":"/","tags":["permit","ext"],"plugins":[{"name":"basic-auth","config":{"hide_credentials":False}}]},
    {"id":"svc-002","name":"rpal-tariff-gateway","protocol":"http","host":"203.x.x.30","port":8080,
     "path":"/TariffGateway","tags":["soap","pngrb"],
     "upstream_auth":"user=rpal-tariff-svc&pass=TariffGW@Soap!2024#RPAL"},
    {"id":"svc-003","name":"rpal-exploration-api","protocol":"http","host":"203.x.x.20","port":4000,
     "path":"/graphql","tags":["graphql","api"],
     "upstream_api_key":"RPAL-API-2024-XK9mP3nT8qRs"},
]

INDEX = """<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8">
<title>Kong Gateway Manager — RPAL API Platform</title>
<style>*{box-sizing:border-box;margin:0;padding:0}:root{--bg:#1a2738;--surface:#1e2f42;--teal:#00c4b4;--text:#e2e8f0;--text2:#7a8fa6;--border:#1e3a52;--mono:"SF Mono",Consolas,monospace}
body{background:var(--bg);color:var(--text);font-family:-apple-system,sans-serif;min-height:100vh}
.topbar{background:#151f2e;border-bottom:2px solid var(--teal);height:54px;display:flex;align-items:center;padding:0 24px;justify-content:space-between}
.logo{display:flex;align-items:center;gap:10px}
.k-badge{background:var(--teal);width:30px;height:30px;border-radius:6px;display:flex;align-items:center;justify-content:center;font-size:14px;font-weight:900;color:#151f2e}
.logo-name{font-size:13px;font-weight:700}.logo-sub{font-family:var(--mono);font-size:10px;color:var(--text2)}
.topbar-right{font-family:var(--mono);font-size:10px;color:var(--text2)}
.content{display:flex;min-height:calc(100vh-54px)}
.sidebar{width:200px;background:#151f2e;border-right:1px solid var(--border);padding:14px 0}
.sb-sec{font-size:9px;font-weight:700;color:var(--text2);text-transform:uppercase;letter-spacing:1px;padding:0 14px 6px;font-family:var(--mono);margin-top:12px}
.sb-item{padding:8px 14px;font-size:12px;color:var(--text2);cursor:pointer;border-left:3px solid transparent}
.sb-item:hover,.sb-item.active{color:var(--teal);background:rgba(0,196,180,.06);border-left-color:var(--teal)}
.main{flex:1;padding:24px}
.pg-title{font-size:18px;font-weight:700;margin-bottom:4px}.pg-sub{font-size:11px;color:var(--text2);font-family:var(--mono);margin-bottom:20px}
.card{background:var(--surface);border:1px solid var(--border);border-radius:8px;overflow:hidden;margin-bottom:16px}
.card-hd{padding:12px 18px;border-bottom:1px solid var(--border);font-size:12px;font-weight:700;color:var(--teal)}
table{width:100%;border-collapse:collapse}
th{font-family:var(--mono);font-size:10px;color:var(--text2);text-transform:uppercase;padding:9px 14px;text-align:left;border-bottom:1px solid var(--border)}
td{padding:10px 14px;font-size:11px;font-family:var(--mono);border-bottom:1px solid rgba(30,58,82,.4)}
.sensitive{color:#f0883e;font-weight:600}
.api-note{background:rgba(240,136,62,.06);border:1px solid rgba(240,136,62,.2);border-radius:4px;padding:8px 12px;font-size:11px;color:#f0883e;font-family:var(--mono);margin-bottom:12px}
</style></head><body>
<div class="topbar">
  <div class="logo"><div class="k-badge">K</div><div><div class="logo-name">Kong Gateway Manager</div><div class="logo-sub">api-gw.rpal.in · Enterprise 3.6.1</div></div></div>
  <div class="topbar-right">Logged in: admin</div>
</div>
<div class="content">
  <nav class="sidebar">
    <div class="sb-sec">Overview</div>
    <div class="sb-item active">📊 Dashboard</div>
    <div class="sb-item">🔌 Services</div>
    <div class="sb-item">🛣 Routes</div>
    <div class="sb-sec">Security</div>
    <div class="sb-item">🔑 API Keys</div>
    <div class="sb-item">🔒 ACL Plugins</div>
  </nav>
  <div class="main">
    <div class="pg-title">Services</div>
    <div class="pg-sub">api-gw.rpal.in · All registered upstream services</div>
    <div class="api-note">⚠ GET /api/v2/services returns full service config including upstream_auth and upstream_api_key fields in plaintext.</div>
    <div class="card">
      <div class="card-hd">Registered Services ({{ services|length }})</div>
      <table><thead><tr><th>Name</th><th>Host</th><th>Port</th><th>Upstream Auth</th></tr></thead>
      <tbody>
      {% for s in services %}
      <tr>
        <td>{{ s.name }}</td><td>{{ s.host }}</td><td>{{ s.port }}</td>
        <td class="sensitive">{{ s.get('upstream_auth') or s.get('upstream_api_key') or '—' }}</td>
      </tr>
      {% endfor %}
      </tbody></table>
    </div>
  </div>
</div></body></html>"""

@app.route('/')
def index():
    logging.warning(f"KONG_CONSOLE_ACCESS ip={flask.request.remote_addr}")
    return flask.render_template_string(INDEX, services=SERVICES)

@app.route('/api/v2/services')
def api_services():
    # VULNERABILITY: Returns upstream credentials in plaintext — no auth check
    logging.critical(f"API_SERVICES_ACCESS ip={flask.request.remote_addr}")
    return flask.jsonify({"data": SERVICES, "total": len(SERVICES)})

@app.route('/api/v2/routes')
def api_routes():
    return flask.jsonify({"data":[],"total":0})

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8404, debug=False)
PYEOF

# Port 8500 — Consul Service Mesh
# Vulnerability: No ACL token required — /v1/kv/?recurse returns all KV including secrets
mkdir -p "${BASE}/consul-mesh"
cat > "${BASE}/consul-mesh/app.py" << 'PYEOF'
#!/usr/bin/env python3
import flask, json, base64, logging
app = flask.Flask(__name__)
logging.basicConfig(level=logging.WARNING)

def b64(s): return base64.b64encode(s.encode()).decode()

KV_STORE = {
    "rpal/services/permit-portal/config": b64('{"port":8443,"auth":"jwt","jwt_secret":"RPAL-JWT-SECRET-2024"}'),
    "rpal/services/tariff-gateway/credentials": b64('{"username":"rpal-tariff-svc","password":"TariffGW@Soap!2024#RPAL"}'),
    "rpal/services/exploration-api/api-key": b64('RPAL-API-2024-XK9mP3nT8qRs'),
    "rpal/infra/ldap/bind-password": b64('Ldap@GW!Bind2024#RPAL'),
    "rpal/infra/haproxy/stats-password": b64('HAProxy@Stats!2024'),
}

INDEX = """<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8">
<title>HashiCorp Consul — RPAL Service Mesh</title>
<style>*{box-sizing:border-box;margin:0;padding:0}body{background:#f8f9fc;font-family:-apple-system,sans-serif;min-height:100vh}
.nav{background:#fff;border-bottom:1px solid #dde3ec;height:52px;display:flex;align-items:center;padding:0 24px;justify-content:space-between}
.nav-brand{display:flex;align-items:center;gap:10px}
.consul-badge{background:linear-gradient(135deg,#e42f74,#c0235c);width:30px;height:30px;border-radius:6px;display:flex;align-items:center;justify-content:center;font-size:14px;font-weight:900;color:#fff}
.nav-title{font-size:13px;font-weight:700;color:#1a2130}.nav-sub{font-size:10px;color:#546e7a;font-family:monospace}
.nav-right{font-size:11px;color:#546e7a;font-family:monospace}
.main{max-width:1000px;margin:0 auto;padding:24px}
.alert{background:#fff3e0;border:1px solid #ffcc02;border-radius:6px;padding:10px 16px;font-size:12px;color:#e65100;margin-bottom:20px;font-family:monospace}
.card{background:#fff;border:1px solid #dde3ec;border-radius:8px;overflow:hidden;margin-bottom:16px}
.card-hd{padding:12px 18px;border-bottom:1px solid #dde3ec;font-size:12px;font-weight:700;color:#1a2130}
table{width:100%;border-collapse:collapse}
th{font-size:10px;color:#546e7a;text-transform:uppercase;padding:9px 14px;text-align:left;border-bottom:1px solid #dde3ec;background:#fafbfc}
td{padding:10px 14px;font-size:11px;font-family:monospace;border-bottom:1px solid #f0f2f7}
.kv-key{color:#1565c0}.kv-val{color:#b71c1c;font-weight:600}
</style></head><body>
<div class="nav">
  <div class="nav-brand"><div class="consul-badge">C</div><div><div class="nav-title">HashiCorp Consul</div><div class="nav-sub">api-gw.rpal.in · Service Mesh &amp; Discovery</div></div></div>
  <div class="nav-right">dc: rpal-prod-mumbai · No ACL enforced</div>
</div>
<div class="main">
  <div class="alert">⚠ ACL system is not enabled. GET /v1/kv/?recurse returns all key-value pairs without authentication. This includes service credentials stored in the KV store.</div>
  <div class="card">
    <div class="card-hd">KV Store — rpal/* (all keys, values base64-decoded for display)</div>
    <table><thead><tr><th>Key</th><th>Decoded Value</th></tr></thead>
    <tbody>
    {% for k, v in kv_items %}
    <tr><td class="kv-key">{{ k }}</td><td class="kv-val">{{ v }}</td></tr>
    {% endfor %}
    </tbody></table>
  </div>
</div></body></html>"""

@app.route('/')
def index():
    import base64
    decoded = [(k, base64.b64decode(v).decode()) for k, v in KV_STORE.items()]
    logging.warning(f"CONSUL_UI_ACCESS ip={flask.request.remote_addr}")
    return flask.render_template_string(INDEX, kv_items=decoded)

@app.route('/v1/kv/')
def kv_recurse():
    # VULNERABILITY: No ACL token check — returns all KV including secrets
    logging.critical(f"KV_RECURSE_ACCESS ip={flask.request.remote_addr}")
    result = [{"Key":k,"Value":v,"Flags":0,"Session":""} for k,v in KV_STORE.items()]
    return flask.jsonify(result)

@app.route('/v1/catalog/services')
def catalog():
    return flask.jsonify({"rpal-permit-portal":[],"rpal-tariff-gateway":["soap","pngrb"],"rpal-exploration-api":["graphql"]})

@app.route('/v1/health/service/<svc>')
def health(svc):
    return flask.jsonify([{"Node":{"Node":"rpal-api-gw","Address":"203.x.x.40"},"Service":{"ID":svc,"Service":svc,"Status":"passing"}}])

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8500, debug=False)
PYEOF

# Port 9411 — Zipkin Tracing
# Vulnerability: No auth — trace data reveals internal IPs and service names
mkdir -p "${BASE}/zipkin-tracing"
cat > "${BASE}/zipkin-tracing/app.py" << 'PYEOF'
#!/usr/bin/env python3
import flask, json, logging
app = flask.Flask(__name__)
logging.basicConfig(level=logging.WARNING)

SERVICES = ["rpal-permit-portal","rpal-tariff-gateway","rpal-exploration-api","rpal-api-backend","rpal-contractor-portal"]
TRACES = [
    {"traceId":"3f2a1b8c9d4e5f6a","duration":4200,"timestamp":1731634800000000,
     "spans":[{"name":"POST /api/v1/admin/system-config","remoteEndpoint":{"serviceName":"rpal-permit-portal","ipv4":"203.x.x.10"},"tags":{"http.status_code":"200","user":"admin","jwt.alg":"HS256"}},
              {"name":"DB query","remoteEndpoint":{"ipv4":"127.0.0.1","port":5432},"tags":{"db.type":"sqlite","db.statement":"SELECT * FROM system_config"}}]},
    {"traceId":"7d8e9f0a1b2c3d4e","duration":88400,"timestamp":1731634700000000,
     "spans":[{"name":"POST /TariffGateway","remoteEndpoint":{"serviceName":"rpal-tariff-gateway","ipv4":"203.x.x.30"},"tags":{"http.status_code":"200","soap.action":"CalculateTariff","upstream.user":"rpal-tariff-svc","upstream.host":"203.x.x.30:8080"}}]}
]

INDEX = """<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8">
<title>Zipkin — RPAL API Distributed Tracing</title>
<style>*{box-sizing:border-box;margin:0;padding:0}body{background:#fff;font-family:-apple-system,sans-serif;min-height:100vh}
.header{background:#f8f8f8;border-bottom:1px solid #e0e0e0;height:48px;display:flex;align-items:center;padding:0 20px;gap:12px}
.zlogo{font-size:20px;font-weight:900;color:#e05c23;letter-spacing:-1px;font-family:monospace}
.header-sub{font-size:12px;color:#757575}
.main{padding:24px;max-width:1000px;margin:0 auto}
.alert{background:#fff3e0;border:1px solid #ffcc80;border-radius:6px;padding:10px 16px;font-size:12px;color:#e65100;margin-bottom:20px;font-family:monospace}
.search-bar{display:flex;gap:10px;margin-bottom:24px;background:#f8f8f8;border:1px solid #e0e0e0;border-radius:8px;padding:16px}
.field{flex:1}label{display:block;font-size:10px;font-weight:700;color:#757575;text-transform:uppercase;margin-bottom:6px;font-family:monospace}
select,input{width:100%;background:#fff;border:1px solid #e0e0e0;border-radius:4px;padding:7px 10px;font-size:12px;font-family:monospace}
.run-btn{background:#e05c23;color:#fff;border:none;border-radius:4px;padding:8px 20px;font-size:12px;font-weight:700;cursor:pointer;white-space:nowrap;align-self:flex-end}
.trace-row{display:flex;align-items:center;padding:12px 16px;border:1px solid #e0e0e0;border-radius:6px;margin-bottom:8px;cursor:pointer}
.trace-row:hover{background:#fafafa}
.t-service{font-family:monospace;font-size:12px;color:#1565c0;width:220px}
.t-id{font-family:monospace;font-size:11px;color:#757575;flex:1}
.t-tags{font-family:monospace;font-size:10px;color:#b71c1c}
.t-dur{font-family:monospace;font-size:11px;color:#333;width:80px}
</style></head><body>
<div class="header"><div class="zlogo">zipkin</div><div class="header-sub">RPAL API Gateway — Distributed Tracing (No Auth)</div></div>
<div class="main">
  <div class="alert">⚠ Authentication is not configured. GET /api/v2/services and /api/v2/traces return all trace data including internal IPs, service credentials in tags, and upstream endpoint details.</div>
  <div class="search-bar">
    <div class="field"><label>Service Name</label>
      <select>{% for s in services %}<option>{{ s }}</option>{% endfor %}</select>
    </div>
    <div class="field"><label>Lookback</label><select><option>1 hour</option><option>6 hours</option></select></div>
    <button class="run-btn">Search Traces</button>
  </div>
  {% for t in traces %}
  <div class="trace-row">
    <span class="t-service">{{ t.spans[0].remoteEndpoint.serviceName }}</span>
    <span class="t-id">{{ t.traceId }}</span>
    <span class="t-tags">{{ t.spans[0].tags | string | truncate(60) }}</span>
    <span class="t-dur">{{ (t.duration / 1000)|int }} ms</span>
  </div>
  {% endfor %}
</div></body></html>"""

@app.route('/')
def index():
    logging.warning(f"ZIPKIN_ACCESS ip={flask.request.remote_addr}")
    return flask.render_template_string(INDEX, services=SERVICES, traces=TRACES)

@app.route('/api/v2/services')
def api_services():
    logging.info(f"API_SERVICES ip={flask.request.remote_addr}")
    return flask.jsonify(SERVICES)

@app.route('/api/v2/traces')
def api_traces():
    logging.critical(f"API_TRACES_ACCESS ip={flask.request.remote_addr}")
    return flask.jsonify(TRACES)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=9411, debug=False)
PYEOF

for SVC_NAME in kong-manager consul-mesh zipkin-tracing; do
    case $SVC_NAME in
        kong-manager) PORT=8404; TITLE="RPAL Kong API Gateway Manager";;
        consul-mesh) PORT=8500; TITLE="RPAL Consul Service Mesh Dashboard";;
        zipkin-tracing) PORT=9411; TITLE="RPAL API Distributed Tracing — Zipkin";;
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
    "8443|rpal-api-gw-tls|RPAL API Gateway HTTPS Endpoint|HTTP/1.1 400 Bad Request\r\nServer: HAProxy/2.6.14\r\n\r\n{\"error\":\"Client sent HTTP request to HTTPS port\"}\r\n" \
    "9999|rpal-haproxy-runtime|RPAL HAProxy Runtime API|HAProxy Runtime API v2.6.14 on api-gw.rpal.in\r\nAvailable: show info, show stat, show servers state\r\nAuth required for write operations.\r\n> " \
    "514|rpal-apigw-syslog|RPAL API Gateway Syslog Relay|<14>Nov 15 03:44:01 api-gw haproxy[891]: 203.x.x.x:44322 [15/Nov/2024] rpal-api-gateway rpal-api-backend 2/0/1/47/50 200 842 \"GET /api/v1/status\"\r\n" \
    "2003|rpal-carbon-metrics|RPAL Carbon/Graphite Metrics Collector|RPAL-Carbon/1.1.10 on api-gw.rpal.in:2003\r\nGraphite plaintext: <metric> <value> <timestamp>\r\n"; do
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

log "M4 supporting services deployment complete."
info "Web: :8404 (Kong Manager)  :8500 (Consul Mesh)  :9411 (Zipkin)"
info "TCP: :8443 (HTTPS)  :9999 (HAProxy Runtime)  :514 (Syslog)  :2003 (Carbon)"
