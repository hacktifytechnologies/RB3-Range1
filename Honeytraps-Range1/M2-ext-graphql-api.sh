#!/usr/bin/env bash
# M2-ext-graphql-api.sh — RPAL M2 Supporting Infrastructure
# RNG-EXT-01 · SETU DVAAR · OPERATION DEEPSTRIKE
set -euo pipefail
[[ $EUID -ne 0 ]] && { echo "Run as root: sudo bash $0"; exit 1; }
GREEN='\033[0;32m'; CYAN='\033[0;36m'; NC='\033[0m'
log()  { echo -e "${GREEN}[RPAL-EXT]${NC} $*"; }
info() { echo -e "${CYAN}[+]${NC} $*"; }
BASE="/opt/rpal/supporting-services"
mkdir -p "$BASE"
log "Deploying RPAL M2 supporting infrastructure services..."

# ── Web Portal 1: Apollo Studio — Port 4001 ───────────────────────────────────
# Vulnerability: GraphQL introspection enabled — reveals schema including
# a hidden mutation updateServiceCredentials. Ironic: M2 real service disables
# introspection; this one leaves it on ("internal tool, not internet-facing")
mkdir -p "${BASE}/apollo-studio"
cat > "${BASE}/apollo-studio/app.py" << 'PYEOF'
#!/usr/bin/env python3
import flask, json, logging
app = flask.Flask(__name__)
logging.basicConfig(level=logging.WARNING)

SCHEMA_TYPES = [
    {"name":"Query"},{"name":"Mutation"},{"name":"WellLog"},{"name":"ExplorationBlock"},
    {"name":"Employee"},{"name":"ServiceCredential"},{"name":"String"},
    {"name":"Boolean"},{"name":"Int"},{"name":"Float"},{"name":"ID"},
    {"name":"__Schema"},{"name":"__Type"},{"name":"__Field"},{"name":"__InputValue"},
    {"name":"__EnumValue"},{"name":"__Directive"},{"name":"__TypeKind"},{"name":"__DirectiveLocation"}
]
SCHEMA_RESPONSE = {
    "data": {
        "__schema": {
            "queryType": {"name": "Query"},
            "mutationType": {"name": "Mutation"},
            "types": SCHEMA_TYPES,
            "directives": []
        }
    }
}
INTROSPECTION_FIELDS = {
    "data": {
        "__type": {
            "name": "Query",
            "fields": [
                {"name":"wellLogs","description":"Fetch well log data","args":[],"type":{"name":"WellLog","kind":"OBJECT"}},
                {"name":"explorationBlocks","description":"Fetch block data","args":[],"type":{"name":"ExplorationBlock","kind":"OBJECT"}},
                {"name":"employees","description":"Employee directory","args":[],"type":{"name":"Employee","kind":"OBJECT"}},
                {"name":"serviceCredentials","description":"Internal service credentials — admin only","args":[{"name":"service","type":{"name":"String"}}],"type":{"name":"ServiceCredential","kind":"OBJECT"}},
            ]
        }
    }
}
CREDS_RESPONSE = {
    "data": {
        "serviceCredentials": [
            {"service":"rpal-tariff-svc","endpoint":"http://203.x.x.x:8080/TariffGateway","password":"TariffGW@Soap!2024#RPAL"},
            {"service":"rpal-explore-svc","endpoint":"http://203.x.x.x:4000/graphql","apiKey":"RPAL-API-2024-XK9mP3nT8qRs"},
        ]
    }
}

INDEX = """<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8">
<title>Apollo Studio — RPAL Exploration API</title>
<style>*{box-sizing:border-box;margin:0;padding:0}:root{--bg:#1a1a2e;--surface:#16213e;--blue:#4a9eff;--text:#e0e6f0;--text2:#8a9ab0;--border:#2a3a52;--sans:-apple-system,sans-serif;--mono:"SF Mono",Consolas,monospace}
body{background:var(--bg);color:var(--text);font-family:var(--sans);min-height:100vh;display:flex;flex-direction:column}
.topbar{background:var(--surface);border-bottom:1px solid var(--border);height:50px;display:flex;align-items:center;padding:0 20px;justify-content:space-between}
.logo{display:flex;align-items:center;gap:10px}
.logo-mark{width:28px;height:28px;background:linear-gradient(135deg,#e535ab,#7b2dd2);border-radius:6px;display:flex;align-items:center;justify-content:center;font-size:13px;font-weight:900;color:#fff}
.logo-name{font-size:13px;font-weight:700}.logo-sub{font-family:var(--mono);font-size:10px;color:var(--text2)}
.topbar-right{font-family:var(--mono);font-size:10px;color:var(--text2)}
.layout{display:flex;flex:1}
.sidebar{width:200px;background:var(--surface);border-right:1px solid var(--border);padding:14px 0}
.sb-sec{font-size:9px;font-weight:700;color:var(--text2);text-transform:uppercase;letter-spacing:1px;padding:0 14px 6px;font-family:var(--mono);margin-top:12px}
.sb-item{padding:8px 14px;font-size:12px;color:var(--text2);cursor:pointer;border-left:3px solid transparent}
.sb-item:hover,.sb-item.active{color:var(--blue);background:rgba(74,158,255,.06);border-left-color:var(--blue)}
.main{flex:1;display:flex;gap:0}
.editor{flex:1;background:#1e1e1e;padding:20px;font-family:var(--mono);font-size:13px}
.result{flex:1;border-left:1px solid var(--border);background:#1a1d23;padding:20px;font-family:var(--mono);font-size:12px;color:var(--text2)}
.toolbar{background:var(--surface);border-bottom:1px solid var(--border);padding:8px 16px;display:flex;align-items:center;gap:8px}
.run-btn{background:#e535ab;color:#fff;border:none;border-radius:4px;padding:6px 16px;font-size:12px;font-weight:700;cursor:pointer}
.endpoint{font-family:var(--mono);font-size:11px;color:var(--text2);background:rgba(255,255,255,.04);padding:5px 10px;border-radius:4px}
.comment{color:#6a9955}.keyword{color:#c792ea}.field-name{color:#82aaff}.string-val{color:#c3e88d}
pre{white-space:pre-wrap;word-break:break-all;color:var(--text2)}
</style></head><body>
<div class="topbar">
  <div class="logo"><div class="logo-mark">A</div><div><div class="logo-name">Apollo Studio</div><div class="logo-sub">explore-api.rpal.in · Internal</div></div></div>
  <div class="topbar-right">RPAL Exploration Data API · Introspection Enabled</div>
</div>
<div class="layout">
  <nav class="sidebar">
    <div class="sb-sec">Explorer</div>
    <div class="sb-item active">📝 Query Editor</div>
    <div class="sb-item">📊 Schema</div>
    <div class="sb-item">📈 Response</div>
    <div class="sb-sec">Tools</div>
    <div class="sb-item">🔍 Introspection</div>
    <div class="sb-item">📋 History</div>
  </nav>
  <div style="flex:1;display:flex;flex-direction:column">
    <div class="toolbar">
      <button class="run-btn">▶ Run</button>
      <span class="endpoint">POST http://explore-api.rpal.in:4001/graphql</span>
    </div>
    <div class="main">
      <div class="editor">
        <span class="comment"># RPAL Exploration Data API — Apollo Studio</span><br>
        <span class="comment"># Note: Introspection is ENABLED on this internal instance</span><br><br>
        <span class="keyword">query</span> {<br>
        &nbsp;&nbsp;<span class="field-name">wellLogs</span> {<br>
        &nbsp;&nbsp;&nbsp;&nbsp;<span class="field-name">well_id</span><br>
        &nbsp;&nbsp;&nbsp;&nbsp;<span class="field-name">block_name</span><br>
        &nbsp;&nbsp;&nbsp;&nbsp;<span class="field-name">status</span><br>
        &nbsp;&nbsp;}<br>
        }
      </div>
      <div class="result"><pre>Run a query to see results here</pre></div>
    </div>
  </div>
</div></body></html>"""

@app.route('/')
@app.route('/graphql')
def index():
    if flask.request.method == 'POST':
        body = flask.request.get_json(silent=True) or {}
        query = body.get('query','')
        logging.info(f"GRAPHQL query_len={len(query)} ip={flask.request.remote_addr}")
        if '__schema' in query or '__type' in query:
            logging.warning(f"INTROSPECTION_QUERY ip={flask.request.remote_addr}")
            if '__schema' in query:
                return flask.jsonify(SCHEMA_RESPONSE)
            return flask.jsonify(INTROSPECTION_FIELDS)
        if 'serviceCredentials' in query:
            logging.critical(f"SERVICE_CREDS_QUERY ip={flask.request.remote_addr}")
            return flask.jsonify(CREDS_RESPONSE)
        return flask.jsonify({"data":{},"errors":[{"message":"Resolver not implemented in Studio mode"}]})
    return flask.render_template_string(INDEX)

app.add_url_rule('/graphql', 'graphql_post', index, methods=['POST'])

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=4001, debug=False)
PYEOF

# ── Web Portal 2: Hasura Console — Port 3100 ─────────────────────────────────
# Vulnerability: Admin console accessible without X-Hasura-Admin-Secret header.
# The header check is done only on the /api/v1/graphql endpoint, not the console UI.
# Attacker can browse schema, run SQL via "Data" tab, and enumerate tables.
mkdir -p "${BASE}/hasura-console"
cat > "${BASE}/hasura-console/app.py" << 'PYEOF'
#!/usr/bin/env python3
import flask, json, logging
app = flask.Flask(__name__)
logging.basicConfig(level=logging.WARNING)

TABLE_DATA = {
    "well_logs": [
        {"well_id":"WL-KG-2024-001","block_name":"KG-DWN-98/3","operator":"RPAL","status":"Suspended","depth_tvdss":4820.5},
        {"well_id":"WL-MB-2024-001","block_name":"MB-OSN-2005/2","operator":"RPAL","status":"Completed","depth_tvdss":2340.0},
    ],
    "service_accounts": [
        {"username":"rpal-tariff-svc","service":"SOAP Gateway","password":"TariffGW@Soap!2024#RPAL","endpoint":"http://203.x.x.x:8080"},
        {"username":"rpal-explore-svc","service":"GraphQL API","api_key":"RPAL-API-2024-XK9mP3nT8qRs","endpoint":"http://203.x.x.x:4000"},
    ]
}

INDEX = """<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8">
<title>Hasura Console — RPAL Data Platform</title>
<style>*{box-sizing:border-box;margin:0;padding:0}:root{--bg:#f8f9fc;--surface:#fff;--pink:#e42f74;--text:#1a2130;--text2:#546e7a;--text3:#90a4ae;--border:#dde3ec;--sans:-apple-system,sans-serif;--mono:"SF Mono",Consolas,monospace}
body{background:var(--bg);font-family:var(--sans);min-height:100vh}
.nav{background:#1c1c1c;height:52px;display:flex;align-items:center;padding:0 20px;justify-content:space-between}
.nav-brand{display:flex;align-items:center;gap:10px}
.h-badge{background:var(--pink);width:30px;height:30px;border-radius:6px;display:flex;align-items:center;justify-content:center;font-size:14px;font-weight:900;color:#fff}
.nav-title{font-size:13px;font-weight:700;color:#fff}.nav-sub{font-size:10px;color:#777;font-family:var(--mono)}
.nav-tabs{display:flex;gap:4px}
.nav-tab{padding:6px 14px;font-size:12px;color:#aaa;cursor:pointer;border-radius:4px;border-bottom:2px solid transparent}
.nav-tab.active{color:#fff;border-bottom-color:var(--pink)}
.content{max-width:1100px;margin:0 auto;padding:24px}
.alert{background:#fff3e0;border:1px solid #ffcc02;border-radius:6px;padding:10px 16px;font-size:12px;color:#e65100;margin-bottom:20px;font-family:var(--mono)}
.tables-grid{display:grid;grid-template-columns:220px 1fr;gap:20px}
.table-list{background:var(--surface);border:1px solid var(--border);border-radius:8px;overflow:hidden}
.tl-hd{padding:12px 16px;border-bottom:1px solid var(--border);font-size:11px;font-weight:700;color:var(--text2);text-transform:uppercase;letter-spacing:.8px}
.tl-item{padding:10px 16px;font-family:var(--mono);font-size:12px;cursor:pointer;border-bottom:1px solid rgba(221,227,236,.4)}
.tl-item:hover,.tl-item.active{background:rgba(228,47,116,.04);color:var(--pink)}
.data-panel{background:var(--surface);border:1px solid var(--border);border-radius:8px;overflow:hidden}
.dp-hd{padding:12px 18px;border-bottom:1px solid var(--border);display:flex;justify-content:space-between;align-items:center}
.dp-title{font-size:13px;font-weight:700}
.run-sql-btn{background:var(--pink);color:#fff;border:none;border-radius:4px;padding:6px 16px;font-size:12px;font-weight:700;cursor:pointer}
table{width:100%;border-collapse:collapse}
th{font-size:10px;color:var(--text2);text-transform:uppercase;letter-spacing:.7px;padding:9px 14px;text-align:left;border-bottom:1px solid var(--border);background:var(--bg)}
td{padding:10px 14px;font-family:var(--mono);font-size:11px;border-bottom:1px solid rgba(221,227,236,.4)}
.sensitive{color:var(--pink);font-weight:600}
</style></head><body>
<div class="nav">
  <div class="nav-brand"><div class="h-badge">H</div><div><div class="nav-title">Hasura GraphQL Engine</div><div class="nav-sub">rpal-data-platform.rpal.in · v2.35.0</div></div></div>
  <div class="nav-tabs"><div class="nav-tab active">API Explorer</div><div class="nav-tab">Data</div><div class="nav-tab">Events</div><div class="nav-tab">Settings</div></div>
</div>
<div class="content">
  <div class="alert">⚠ Admin console is accessible. X-Hasura-Admin-Secret header is not enforced on the console UI. Run SQL via the Data tab to query all tables directly.</div>
  <div class="tables-grid">
    <div class="table-list">
      <div class="tl-hd">Tables</div>
      <div class="tl-item active">service_accounts</div>
      <div class="tl-item">well_logs</div>
      <div class="tl-item">exploration_blocks</div>
      <div class="tl-item">employees</div>
      <div class="tl-item">system_config</div>
    </div>
    <div class="data-panel">
      <div class="dp-hd"><span class="dp-title">service_accounts — All rows</span><button class="run-sql-btn">Run SQL</button></div>
      <table><thead><tr><th>username</th><th>service</th><th>password / api_key</th><th>endpoint</th></tr></thead>
      <tbody>
        <tr><td>rpal-tariff-svc</td><td>SOAP Gateway</td><td class="sensitive">TariffGW@Soap!2024#RPAL</td><td>http://203.x.x.x:8080</td></tr>
        <tr><td>rpal-explore-svc</td><td>GraphQL API</td><td class="sensitive">RPAL-API-2024-XK9mP3nT8qRs</td><td>http://203.x.x.x:4000</td></tr>
      </tbody></table>
    </div>
  </div>
</div></body></html>"""

@app.route('/')
def index():
    logging.warning(f"HASURA_CONSOLE_ACCESS ip={flask.request.remote_addr} admin_secret_present={'X-Hasura-Admin-Secret' in flask.request.headers}")
    return flask.render_template_string(INDEX)

@app.route('/v1/graphql', methods=['POST'])
def graphql():
    secret = flask.request.headers.get('X-Hasura-Admin-Secret','')
    if not secret:
        logging.critical(f"NO_ADMIN_SECRET ip={flask.request.remote_addr}")
    body = flask.request.get_json(silent=True) or {}
    return flask.jsonify({"data":{"service_accounts":TABLE_DATA["service_accounts"]}})

@app.route('/v2/query', methods=['POST'])
def run_sql():
    # Unauthenticated SQL execution endpoint
    body = flask.request.get_json(silent=True) or {}
    logging.critical(f"SQL_EXEC sql={body.get('args',{}).get('sql','')[:80]} ip={flask.request.remote_addr}")
    table = body.get('args',{}).get('sql','').lower()
    for tbl, data in TABLE_DATA.items():
        if tbl in table:
            return flask.jsonify({"result_type":"TuplesOk","result":data})
    return flask.jsonify({"result_type":"TuplesOk","result":[]})

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=3100, debug=False)
PYEOF

# ── Web Portal 3: Swagger UI — Port 5000 ──────────────────────────────────────
# Vulnerability: Hidden undocumented endpoint /api/v1/internal/tokens
# returns service API keys — not shown in Swagger docs but accessible
mkdir -p "${BASE}/swagger-ui"
cat > "${BASE}/swagger-ui/app.py" << 'PYEOF'
#!/usr/bin/env python3
import flask, logging
app = flask.Flask(__name__)
logging.basicConfig(level=logging.WARNING)

INDEX = """<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8">
<title>RPAL Upstream Data API — Swagger UI</title>
<style>*{box-sizing:border-box;margin:0;padding:0}body{background:#f4f6f9;font-family:-apple-system,sans-serif;min-height:100vh}
.topbar{background:#1b1b1b;height:50px;display:flex;align-items:center;padding:0 24px;gap:12px}
.sw-logo{color:#85ea2d;font-size:20px;font-weight:900;font-family:monospace}
.sw-title{color:#fff;font-size:14px;font-weight:600}
.main{max-width:1000px;margin:0 auto;padding:24px}
.info-block{background:#fff;border:1px solid #dde3ec;border-radius:8px;padding:20px 24px;margin-bottom:20px;border-left:4px solid #85ea2d}
.info-title{font-size:18px;font-weight:800;color:#1b1b1b;margin-bottom:4px}
.info-sub{font-size:13px;color:#546e7a;font-family:monospace}.info-desc{font-size:13px;color:#37474f;margin-top:10px;line-height:1.6}
.servers{display:flex;align-items:center;gap:10px;margin-top:10px}
.server-label{font-size:11px;font-weight:700;color:#546e7a}
.server-url{font-family:monospace;font-size:12px;background:#f8f9fc;border:1px solid #dde3ec;border-radius:4px;padding:5px 12px;color:#1565c0}
.auth-btn{background:#1565c0;color:#fff;border:none;border-radius:4px;padding:6px 16px;font-size:12px;font-weight:700;cursor:pointer;margin-left:auto}
.section-title{font-size:13px;font-weight:700;color:#37474f;text-transform:uppercase;letter-spacing:.7px;margin:20px 0 10px;font-family:monospace}
.endpoint{background:#fff;border:1px solid #dde3ec;border-radius:6px;margin-bottom:8px;overflow:hidden}
.ep-hd{display:flex;align-items:center;gap:12px;padding:12px 16px;cursor:pointer}
.method{font-family:monospace;font-size:11px;font-weight:800;padding:3px 10px;border-radius:4px;min-width:52px;text-align:center}
.get{background:#d1ecf1;color:#0c5460}.post{background:#d4edda;color:#155724}.put{background:#fff3cd;color:#856404}
.path{font-family:monospace;font-size:13px;color:#1b1b1b}
.ep-desc{font-size:12px;color:#6c757d;margin-left:auto}
.badge-locked{background:#fce4ec;color:#c62828;font-size:10px;padding:2px 6px;border-radius:4px;font-weight:700}
</style></head><body>
<div class="topbar"><div class="sw-logo">swagger</div><div class="sw-title">RPAL Upstream Data REST API</div></div>
<div class="main">
  <div class="info-block">
    <div class="info-title">RPAL Exploration Data API <span style="font-size:12px;background:#85ea2d;color:#000;padding:2px 8px;border-radius:4px;margin-left:8px">v3.2.1</span></div>
    <div class="info-sub">OAS3 · explore-api.rpal.in:4001</div>
    <div class="info-desc">REST API for RPAL exploration data — well logs, block allocations, GIS data. Requires X-API-Key header for protected endpoints.</div>
    <div class="servers"><div class="server-label">Server:</div><div class="server-url">http://explore-api.rpal.in:5000</div><button class="auth-btn">🔑 Authorize</button></div>
  </div>
  <div class="section-title">Exploration Data</div>
  <div class="endpoint"><div class="ep-hd"><span class="method get">GET</span><span class="path">/api/v1/wells</span><span class="ep-desc">List well logs</span><span class="badge-locked">🔑 Auth</span></div></div>
  <div class="endpoint"><div class="ep-hd"><span class="method get">GET</span><span class="path">/api/v1/blocks</span><span class="ep-desc">List exploration blocks</span><span class="badge-locked">🔑 Auth</span></div></div>
  <div class="endpoint"><div class="ep-hd"><span class="method post">POST</span><span class="path">/api/v1/blocks/search</span><span class="ep-desc">Search blocks by basin</span><span class="badge-locked">🔑 Auth</span></div></div>
  <div class="section-title">Status</div>
  <div class="endpoint"><div class="ep-hd"><span class="method get">GET</span><span class="path">/api/v1/status</span><span class="ep-desc">Service health check</span></div></div>
  <div class="endpoint"><div class="ep-hd"><span class="method get">GET</span><span class="path">/api/v1/version</span><span class="ep-desc">Version info</span></div></div>
</div></body></html>"""

@app.route('/')
def index():
    return flask.render_template_string(INDEX)

@app.route('/api/v1/status')
def status():
    return flask.jsonify({'status':'ok','service':'RPAL Exploration Data API','version':'3.2.1'})

@app.route('/api/v1/version')
def version():
    return flask.jsonify({'version':'3.2.1','build':'a3f2c8e','env':'production'})

@app.route('/api/v1/wells')
@app.route('/api/v1/blocks')
def protected():
    if not flask.request.headers.get('X-API-Key'):
        return flask.jsonify({'error':'X-API-Key header required'}), 401
    return flask.jsonify({'data':[]})

# VULNERABILITY: Undocumented endpoint not in Swagger docs
# Returns internal service tokens — no auth required
# Discoverable via directory brute-force (ffuf, gobuster)
@app.route('/api/v1/internal/tokens')
def internal_tokens():
    logging.critical(f"INTERNAL_TOKENS_ACCESS ip={flask.request.remote_addr}")
    return flask.jsonify({
        'warning': 'Internal endpoint — do not expose externally',
        'tokens': [
            {'service':'rpal-explore-svc','api_key':'RPAL-API-2024-XK9mP3nT8qRs','scope':'read:wells read:blocks'},
            {'service':'rpal-tariff-svc','soap_password':'TariffGW@Soap!2024#RPAL','scope':'tariff:calculate'},
        ]
    })

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=False)
PYEOF

for SVC_NAME in apollo-studio hasura-console swagger-ui; do
    case $SVC_NAME in
        apollo-studio) PORT=4001; TITLE="RPAL Apollo Studio — GraphQL Schema Registry";;
        hasura-console) PORT=3100; TITLE="RPAL Hasura GraphQL Engine Console";;
        swagger-ui) PORT=5000; TITLE="RPAL Upstream Data API — Swagger Documentation";;
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
    "6379|rpal-redis-cache|RPAL Session Cache — Redis|+PONG\r\n-ERR Authentication required. Use AUTH <password>.\r\n" \
    "5672|rpal-amqp-broker|RPAL Message Broker — AMQP|AMQP\x00\x00\x09\x01RPAL-AMQP/RabbitMQ-3.12.7 auth=PLAIN required\r\n" \
    "8883|rpal-mqtt-telemetry|RPAL MQTT Telemetry Broker|\x20\x02\x00\x00RPAL-MQTT-3.1.1 auth required on :8883\r\n" \
    "9200|rpal-elasticsearch|RPAL Elasticsearch Data Index|HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{\"name\":\"rpal-explore-node-01\",\"cluster_name\":\"rpal-exploration\",\"version\":{\"number\":\"8.12.1\"}}\r\n"; do
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

log "M2 supporting services deployment complete."
info "Web: :4001 (Apollo Studio)  :3100 (Hasura Console)  :5000 (Swagger UI)"
info "TCP: :6379 (Redis)  :5672 (AMQP)  :8883 (MQTT)  :9200 (Elasticsearch)"
