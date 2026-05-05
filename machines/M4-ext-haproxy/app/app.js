/*
 * RPAL Geological Survey Analytics Portal
 * M4 · ext-survey-portal · RNG-EXT-01 · SETU DVAAR · OPERATION DEEPSTRIKE
 */

'use strict';

const express      = require('express');
const ejs          = require('ejs');
const cookieSession = require('cookie-session');
const crypto       = require('crypto');
const path         = require('path');
const fs           = require('fs');

const app  = express();
const PORT = process.env.PORT || 3000;

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieSession({ name: 'rpal_sess', secret: 'RPAL-Survey-Portal-2024', maxAge: 8 * 60 * 60 * 1000 }));

function todayStr() {
    return new Date().toISOString().slice(0, 10); // YYYY-MM-DD
}
function prevDayStr() {
    const d = new Date(); d.setDate(d.getDate() - 1);
    return d.toISOString().slice(0, 10);
}
function computeCreds(dateStr) {
    const seed      = `RPAL-IMDS-CREDS-${dateStr}`;
    const keyIdRaw  = crypto.createHash('sha256').update(`${seed}:keyid`).digest('hex').slice(0, 20).toUpperCase();
    const tokenRaw  = crypto.createHash('sha256').update(`${seed}:token`).digest('hex');
    return { accessKeyId: `ASIA${keyIdRaw}`, token: tokenRaw.repeat(2) };
}

function validateImds(accessKeyId, token) {
    for (const d of [todayStr(), prevDayStr()]) {
        const c = computeCreds(d);
        const half = c.token.slice(0, 64);
        if (accessKeyId === c.accessKeyId &&
            (token === c.token || token === half)) return true;
    }
    return false;
}

function requireAuth(req, res, next) {
    if (req.session && req.session.authenticated) return next();
    if (req.path.startsWith('/api/')) return res.status(401).json({ error: 'Authentication required' });
    res.redirect('/login');
}

const WELL_LOGS = [
    { well_id: 'WL-KG-2024-001', block: 'KG-DWN-98/3',    depth: '4,820m', formation: 'Godavari-IV', status: 'Suspended', operator: 'RPAL' },
    { well_id: 'WL-MB-2024-002', block: 'MB-OSN-2005/2',  depth: '2,340m', formation: 'Mumbai-II',   status: 'Completed', operator: 'RPAL' },
    { well_id: 'WL-RJ-2024-003', block: 'RJ-ONN-2022/3',  depth: '1,890m', formation: 'Barmer',      status: 'Drilling',  operator: 'RPAL' },
    { well_id: 'WL-CB-2024-004', block: 'CB-ONN-2010/7',  depth: '2,140m', formation: 'Ankleshwar',  status: 'Completed', operator: 'RPAL' },
];

const SURVEY_SITES = [
    { id: 'S001', name: 'KG Basin Offshore', lat: '15.8°N', lon: '82.1°E', type: '3D Seismic',    status: 'Active' },
    { id: 'S002', name: 'Mumbai High North',  lat: '19.1°N', lon: '72.3°E', type: 'Marine Survey', status: 'Complete' },
    { id: 'S003', name: 'Rajasthan Block',    lat: '27.4°N', lon: '71.8°E', type: 'Gravity/Mag',   status: 'Active' },
];

const CSS_BASE = `
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
:root{
  --bg:#060d1a;--nav:#0a1628;--surface:#0f1e38;--surface2:#162444;
  --amber:#f59e0b;--amber2:#d97706;--amber3:#fbbf24;
  --text:#e8edf5;--t2:#94a3b8;--t3:#475569;--br:#1e3a5f;
  --green:#10b981;--red:#ef4444;--blue:#3b82f6;
  --sans:-apple-system,BlinkMacSystemFont,"Segoe UI",Arial,sans-serif;
  --mono:"SF Mono",Consolas,"Liberation Mono",monospace;
}
body{background:var(--bg);color:var(--text);font-family:var(--sans);min-height:100vh;-webkit-font-smoothing:antialiased}
.topbar{background:var(--nav);border-bottom:2px solid var(--amber);height:58px;display:flex;align-items:center;justify-content:space-between;padding:0 28px;position:sticky;top:0;z-index:100}
.tb-brand{display:flex;align-items:center;gap:14px}
.tb-icon{width:36px;height:36px;background:linear-gradient(135deg,var(--amber),var(--amber2));border-radius:8px;display:flex;align-items:center;justify-content:center;font-size:16px}
.tb-name{font-size:14px;font-weight:700}.tb-sub{font-size:10px;color:var(--t3);font-family:var(--mono)}
.tb-right{display:flex;align-items:center;gap:12px;font-size:12px;color:var(--t2)}
.user-chip{background:rgba(245,158,11,.1);border:1px solid rgba(245,158,11,.25);color:var(--amber3);padding:4px 12px;border-radius:12px;font-family:var(--mono);font-size:11px}
.btn-lo{color:var(--t3);text-decoration:none;font-size:12px}
.btn-lo:hover{color:var(--amber)}
.main{max-width:1100px;margin:0 auto;padding:28px}
.pg-hd{margin-bottom:24px}
.pg-title{font-size:20px;font-weight:700;margin-bottom:4px}
.pg-sub{font-size:11px;color:var(--t3);font-family:var(--mono)}
.grid-4{display:grid;grid-template-columns:repeat(4,1fr);gap:14px;margin-bottom:24px}
.stat{background:var(--surface);border:1px solid var(--br);border-radius:8px;padding:16px}
.stat-val{font-size:22px;font-weight:700;color:var(--amber)}
.stat-label{font-size:10px;color:var(--t3);font-family:var(--mono);text-transform:uppercase;letter-spacing:.8px;margin-top:4px}
.card{background:var(--surface);border:1px solid var(--br);border-radius:8px;overflow:hidden;margin-bottom:20px}
.card-hd{padding:12px 18px;border-bottom:1px solid var(--br);display:flex;justify-content:space-between;align-items:center}
.card-title{font-size:12px;font-weight:700;color:var(--amber)}
table{width:100%;border-collapse:collapse}
th{font-family:var(--mono);font-size:10px;color:var(--t3);text-transform:uppercase;letter-spacing:.8px;padding:10px 14px;text-align:left;border-bottom:1px solid var(--br);background:rgba(255,255,255,.02)}
td{padding:11px 14px;font-size:12px;font-family:var(--mono);border-bottom:1px solid rgba(30,58,95,.4);color:var(--t2)}
tr:hover{background:rgba(255,255,255,.02)}
.badge{display:inline-block;font-size:10px;padding:2px 8px;border-radius:4px;font-family:var(--mono);font-weight:700}
.badge-green{background:rgba(16,185,129,.1);color:var(--green);border:1px solid rgba(16,185,129,.2)}
.badge-amber{background:rgba(245,158,11,.1);color:var(--amber3);border:1px solid rgba(245,158,11,.2)}
.badge-red{background:rgba(239,68,68,.1);color:var(--red);border:1px solid rgba(239,68,68,.2)}
.btn{background:var(--amber);color:#000;border:none;border-radius:6px;padding:9px 20px;font-size:13px;font-weight:700;cursor:pointer}
.btn:hover{background:var(--amber3)}
.btn-sec{background:transparent;color:var(--amber);border:1px solid var(--amber);border-radius:6px;padding:8px 18px;font-size:12px;font-weight:600;cursor:pointer}
`;

const PAGE_LOGIN = `<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8">
<title>Sign In — RPAL Geological Survey Portal</title>
<style>
${CSS_BASE}
.gov-bar{background:linear-gradient(90deg,#ff9933 0 33%,#fff 33% 66%,#138808 66% 100%);height:6px}
.wrap{min-height:100vh;display:flex;flex-direction:column}
.content{flex:1;display:flex}
.left{flex:1;padding:72px 60px;display:flex;flex-direction:column;justify-content:center;border-right:1px solid var(--br)}
.left-tag{font-family:var(--mono);font-size:10px;color:var(--amber);text-transform:uppercase;letter-spacing:1.5px;margin-bottom:16px}
.left-h1{font-size:32px;font-weight:800;line-height:1.2;max-width:480px;margin-bottom:14px}
.left-p{font-size:14px;color:var(--t2);line-height:1.7;max-width:460px;margin-bottom:28px}
.feature{display:flex;gap:12px;margin-bottom:12px;font-size:13px;color:var(--t2)}
.feature-icon{color:var(--amber);flex-shrink:0}
.right{width:480px;display:flex;align-items:center;justify-content:center;padding:60px 48px;background:var(--nav)}
.lcard{width:100%}
.lcard-title{font-size:20px;font-weight:800;margin-bottom:4px}
.lcard-sub{font-size:11px;color:var(--t3);font-family:var(--mono);margin-bottom:28px}
.field{margin-bottom:18px}
label{display:block;font-size:10px;font-weight:700;color:var(--t3);text-transform:uppercase;letter-spacing:1px;margin-bottom:7px;font-family:var(--mono)}
input{width:100%;background:var(--bg);border:1.5px solid var(--br);border-radius:6px;padding:11px 14px;font-size:13px;color:var(--text);outline:none;font-family:var(--mono);transition:border-color .2s}
input:focus{border-color:var(--amber)}
.btn-submit{width:100%;background:var(--amber);color:#000;border:none;border-radius:6px;padding:13px;font-size:14px;font-weight:700;cursor:pointer;margin-top:4px}
.err{background:rgba(239,68,68,.08);border:1px solid rgba(239,68,68,.25);border-radius:6px;padding:10px 14px;font-size:12px;color:#fca5a5;font-family:var(--mono);margin-bottom:18px}
.note{margin-top:20px;font-size:11px;color:var(--t3);font-family:var(--mono);line-height:1.6;background:rgba(245,158,11,.04);border:1px solid rgba(245,158,11,.1);border-radius:6px;padding:10px 14px}
</style></head><body>
<div class="gov-bar"></div>
<div class="wrap">
  <div class="content">
    <div class="left">
      <div class="left-tag">URJA DRISHTI 2.0 &middot; Geological Data Platform</div>
      <div class="left-h1">RPAL Geological Survey Analytics Portal</div>
      <div class="left-p">Integrated platform for well log analysis, seismic survey data management, and geological report generation. Access restricted to authorised RPAL technical personnel.</div>
      <div class="feature"><span class="feature-icon">&#9670;</span>Well log data visualisation &amp; export across all RPAL basins</div>
      <div class="feature"><span class="feature-icon">&#9670;</span>Seismic survey site management &mdash; KG Basin, Mumbai Offshore, Rajasthan</div>
      <div class="feature"><span class="feature-icon">&#9670;</span>Custom geological report generation with template support</div>
      <div class="feature"><span class="feature-icon">&#9670;</span>Integration with RPAL cloud IAM for secure access</div>
    </div>
    <div class="right">
      <div class="lcard">
        <div class="lcard-title">Sign In</div>
        <div class="lcard-sub">survey.rpal.in &middot; IAM Authentication</div>
        <%- error ? '<div class="err">&#9888; ' + error + '</div>' : '' %>
        <form method="POST" action="/login">
          <div class="field"><label>AWS Access Key ID</label>
            <input name="accessKeyId" placeholder="ASIAxxxxxxxxxxxxxxxx" autocomplete="off" spellcheck="false" value="<%= accessKeyId || '' %>"></div>
          <div class="field"><label>Session Token</label>
            <input name="token" type="password" placeholder="Paste token from IMDS response"></div>
          <button class="btn-submit" type="submit">Authenticate &rarr;</button>
        </form>
        <div class="note">&#9432; Use the AccessKeyId and Token fields from the IMDS IAM role credentials response (rpal-upstream-api-role).</div>
      </div>
    </div>
  </div>
</div></body></html>`;

const PAGE_DASHBOARD = `<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8">
<title>Dashboard &mdash; RPAL Survey Portal</title>
<style>${CSS_BASE}</style></head><body>
<div class="topbar">
  <div class="tb-brand">
    <div class="tb-icon">&#9728;</div>
    <div><div class="tb-name">RPAL Geological Survey Portal</div>
    <div class="tb-sub">survey.rpal.in &middot; URJA DRISHTI 2.0</div></div>
  </div>
  <div class="tb-right">
    <span class="user-chip"><%= accessKeyId.slice(0,12) %>...</span>
    <a class="btn-lo" href="/logout">Sign Out</a>
  </div>
</div>
<div class="main">
  <div class="pg-hd"><div class="pg-title">Geological Data Dashboard</div>
    <div class="pg-sub">rpal-upstream-api-role &middot; KG Basin, Mumbai Offshore, Rajasthan</div></div>
  <div class="grid-4">
    <div class="stat"><div class="stat-val">4</div><div class="stat-label">Active Wells</div></div>
    <div class="stat"><div class="stat-val">3</div><div class="stat-label">Survey Sites</div></div>
    <div class="stat"><div class="stat-val">247</div><div class="stat-label">Seismic Traces</div></div>
    <div class="stat"><div class="stat-val">94%</div><div class="stat-label">Data Coverage</div></div>
  </div>
  <div class="card">
    <div class="card-hd"><span class="card-title">Well Log Register</span>
      <span style="font-size:10px;color:var(--t3)"><%= wells.length %> wells</span></div>
    <table><thead><tr><th>Well ID</th><th>Block</th><th>Depth</th><th>Formation</th><th>Status</th><th>Operator</th></tr></thead>
    <tbody><% wells.forEach(function(w){ %><tr>
      <td><%=w.well_id%></td><td><%=w.block%></td><td><%=w.depth%></td>
      <td><%=w.formation%></td>
      <td><span class="badge <%=w.status==='Completed'?'badge-green':w.status==='Drilling'?'badge-amber':'badge-red'%>"><%=w.status%></span></td>
      <td><%=w.operator%></td>
    </tr><% }) %></tbody></table>
  </div>
  <div class="card">
    <div class="card-hd"><span class="card-title">Survey Sites</span></div>
    <table><thead><tr><th>Site ID</th><th>Name</th><th>Coordinates</th><th>Type</th><th>Status</th></tr></thead>
    <tbody><% sites.forEach(function(s){ %><tr>
      <td><%=s.id%></td><td><%=s.name%></td><td><%=s.lat%>, <%=s.lon%></td>
      <td><%=s.type%></td>
      <td><span class="badge <%=s.status==='Active'?'badge-amber':'badge-green'%>"><%=s.status%></span></td>
    </tr><% }) %></tbody></table>
  </div>
  <div class="card">
    <div class="card-hd"><span class="card-title">&#127381; Report Generator</span>
      <span style="font-size:10px;color:var(--amber);font-family:var(--mono)">Custom Template Support</span></div>
    <div style="padding:20px">
      <p style="font-size:13px;color:var(--t2);margin-bottom:16px">Generate formatted geological reports using custom temp. Temp support dynamic data binding with well log fields.</p>
      <div id="report-ui">
        <div style="display:grid;grid-template-columns:1fr 1fr;gap:14px;margin-bottom:14px">
          <div><label style="display:block;font-size:10px;font-weight:700;color:var(--t3);text-transform:uppercase;letter-spacing:1px;margin-bottom:6px;font-family:var(--mono)">Site Name</label>
            <input id="site-input" style="width:100%;background:var(--bg);border:1.5px solid var(--br);border-radius:6px;padding:9px 12px;font-size:13px;color:var(--text);outline:none;font-family:var(--mono)" placeholder="e.g. KG-DWN-98/3" value="KG-DWN-98/3"></div>
          <div><label style="display:block;font-size:10px;font-weight:700;color:var(--t3);text-transform:uppercase;letter-spacing:1px;margin-bottom:6px;font-family:var(--mono)">Report Type</label>
            <select id="type-input" style="width:100%;background:var(--bg);border:1.5px solid var(--br);border-radius:6px;padding:9px 12px;font-size:13px;color:var(--text);outline:none">
              <option>Well Log Summary</option><option>Seismic Analysis</option><option>Formation Evaluation</option><option>Custom</option>
            </select></div>
        </div>
        <div style="margin-bottom:14px"><label style="display:block;font-size:10px;font-weight:700;color:var(--t3);text-transform:uppercase;letter-spacing:1px;margin-bottom:6px;font-family:var(--mono)">Report Template (custom syntax supported)</label>
          <textarea id="tmpl-input" rows="6" style="width:100%;background:var(--bg);border:1.5px solid var(--br);border-radius:6px;padding:10px 13px;font-size:12px;color:var(--text);outline:none;resize:vertical;font-family:var(--mono);line-height:1.6">RPAL Geological Survey Report
Site: <site>
Date: <date>
Status: Well data analysis complete.
Prepared by: RPAL Exploration Division</textarea></div>
        <button class="btn" onclick="generateReport()">Generate Report</button>
      </div>
      <div id="report-output" style="display:none;margin-top:16px">
        <div style="font-size:10px;font-weight:700;color:var(--t3);font-family:var(--mono);text-transform:uppercase;letter-spacing:.8px;margin-bottom:8px">Output</div>
        <pre id="report-content" style="background:var(--bg);border:1px solid var(--br);border-radius:6px;padding:14px;font-size:12px;font-family:var(--mono);white-space:pre-wrap;color:var(--amber3);max-height:300px;overflow:auto"></pre>
      </div>
    </div>
  </div>
</div>
<script>
async function generateReport() {
  const site = document.getElementById('site-input').value;
  const template = document.getElementById('tmpl-input').value;
  const r = await fetch('/api/reports/generate', {
    method:'POST', headers:{'Content-Type':'application/json'},
    body: JSON.stringify({ site, template })
  });
  const data = await r.json();
  document.getElementById('report-output').style.display = 'block';
  document.getElementById('report-content').textContent =
    data.output || data.error || JSON.stringify(data, null, 2);
}
</script>
</body></html>`;

app.get('/', (req, res) => {
    if (req.session && req.session.authenticated) return res.redirect('/dashboard');
    res.redirect('/login');
});

app.get('/login', (req, res) => {
    res.send(ejs.render(PAGE_LOGIN, { error: null, accessKeyId: '' }));
});

app.post('/login', (req, res) => {
    const { accessKeyId, token } = req.body;
    if (!accessKeyId || !token) {
        return res.send(ejs.render(PAGE_LOGIN, { error: 'Both fields are required.', accessKeyId }));
    }
    if (!validateImds(accessKeyId.trim(), token.trim())) {
        console.log(`LOGIN_FAIL key=${accessKeyId.slice(0,12)}... ip=${req.ip}`);
        return res.send(ejs.render(PAGE_LOGIN, {
            error: 'Invalid credentials. Use AccessKeyId and Token from the IMDS rpal-upstream-api-role response.',
            accessKeyId
        }));
    }
    req.session.authenticated = true;
    req.session.accessKeyId   = accessKeyId.trim();
    console.log(`LOGIN_OK key=${accessKeyId.slice(0,12)}... ip=${req.ip}`);
    res.redirect('/dashboard');
});

app.get('/dashboard', requireAuth, (req, res) => {
    res.send(ejs.render(PAGE_DASHBOARD, {
        accessKeyId: req.session.accessKeyId,
        wells:       WELL_LOGS,
        sites:       SURVEY_SITES,
    }));
});

app.post('/api/reports/generate', requireAuth, (req, res) => {
    const { site = 'Unknown Site', template } = req.body;
    if (!template) return res.status(400).json({ error: 'template field required' });

    console.log(`REPORT_GEN site=${site} tmpl_len=${template.length} ip=${req.ip}`);

    try {
        const output = ejs.render(template, {
            site,
            date:    new Date().toLocaleDateString('en-IN', { day:'2-digit', month:'short', year:'numeric' }),
            company: 'Rashtriya Petroleum Anveshan Limited',
        });
        res.json({ success: true, output });
    } catch (err) {
        res.status(400).json({ error: err.message });
    }
});

app.get('/logout', (req, res) => { req.session = null; res.redirect('/login'); });

app.get('/api/status', (req, res) => res.json({
    service: 'RPAL Geological Survey Analytics Portal',
    version: '2.1.0',
    status:  'operational',
    auth:    'IMDS IAM role credentials (rpal-upstream-api-role)',
}));

app.use((req, res) => res.status(404).json({ error: 'Not found' }));

app.listen(PORT, '0.0.0.0', () => {
    console.log(`RPAL Survey Portal running on :${PORT}`);
});
