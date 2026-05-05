/*
 * RPAL Contractor Registration System
 * M5 · ext-contractor-portal · RNG-EXT-01 · SETU DVAAR · OPERATION DEEPSTRIKE
 */

'use strict';

const express = require('express');
const path    = require('path');
const crypto  = require('crypto');
const ejs     = require('ejs');

const app      = express();
const PORT     = process.env.PORT || 4000;
const APP_ROOT = __dirname;

const ADMIN_TOKEN = process.env.ADMIN_TOKEN;
const API_KEY = 'RPAL-CONTRACTOR-API-2024-xK9mP3nT8qRs7vL2';

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(APP_ROOT, { dotfiles: 'allow' }));

// ── Auth middleware ────────────────────────────────────────────────────────────
function requireApiKey(req, res, next) {
    const key = req.headers['x-api-key'] || req.query.api_key;
    if (key === API_KEY) return next();
    res.status(401).json({ error: 'Invalid API key. Use X-Api-Key header.' });
}

function requireAdmin(req, res, next) {
    const auth = req.headers['authorization'] || '';
    const token = auth.startsWith('Bearer ') ? auth.slice(7) : req.query.token;
    if (token === ADMIN_TOKEN) return next();
    res.status(403).json({ error: 'Admin token required.' });
}

const CSS = `
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
:root{--bg:#f0f4fa;--white:#fff;--navy:#1e3a5f;--navy2:#162444;--blue:#2563eb;--blue2:#1d4ed8;
--text:#1e293b;--t2:#475569;--t3:#94a3b8;--br:#dde6f0;--green:#059669;--red:#dc2626;
--sans:-apple-system,BlinkMacSystemFont,"Segoe UI",Arial,sans-serif;
--mono:"SF Mono",Consolas,"Liberation Mono",monospace}
body{background:var(--bg);color:var(--text);font-family:var(--sans);min-height:100vh}
.gov-bar{background:linear-gradient(90deg,#ff9933 0 33%,#fff 33% 66%,#138808 66% 100%);height:6px}
.header{background:var(--navy);color:#fff;padding:0 32px;height:64px;display:flex;align-items:center;justify-content:space-between}
.hb{display:flex;align-items:center;gap:14px}
.emblem{width:42px;height:42px;border:2px solid rgba(255,255,255,.4);border-radius:50%;display:flex;align-items:center;justify-content:center;font-size:18px;font-weight:900}
.h-title{font-size:14px;font-weight:700}.h-sub{font-size:10px;opacity:.6;font-family:var(--mono)}
.h-right{font-size:11px;opacity:.6;font-family:var(--mono)}
.hero{background:linear-gradient(135deg,var(--navy2),var(--navy));color:#fff;padding:52px 40px}
.hero h1{font-size:28px;font-weight:800;margin-bottom:10px}
.hero p{font-size:14px;opacity:.8;line-height:1.7;max-width:640px}
.main{max-width:1060px;margin:0 auto;padding:28px}
.card{background:var(--white);border:1px solid var(--br);border-radius:8px;overflow:hidden;margin-bottom:20px;box-shadow:0 1px 3px rgba(0,0,0,.06)}
.card-hd{padding:14px 20px;border-bottom:1px solid var(--br);display:flex;justify-content:space-between;align-items:center;background:#fafbff}
.card-title{font-size:13px;font-weight:700;color:var(--navy)}
.card-body{padding:20px}
.grid2{display:grid;grid-template-columns:1fr 1fr;gap:16px}
.field{margin-bottom:16px}
label{display:block;font-size:11px;font-weight:700;color:var(--t2);text-transform:uppercase;letter-spacing:.7px;margin-bottom:6px}
input,select,textarea{width:100%;background:#f8fafc;border:1.5px solid var(--br);border-radius:6px;padding:10px 13px;font-size:13px;color:var(--text);outline:none;transition:border-color .2s}
input:focus,select:focus,textarea:focus{border-color:var(--blue)}
.btn{background:var(--blue);color:#fff;border:none;border-radius:6px;padding:10px 24px;font-size:13px;font-weight:700;cursor:pointer}
.btn:hover{background:var(--blue2)}
.badge{display:inline-block;font-size:10px;padding:2px 8px;border-radius:4px;font-weight:700;font-family:var(--mono)}
.badge-green{background:#d1fae5;color:var(--green)}
.badge-blue{background:#dbeafe;color:var(--blue)}
.footer{background:var(--navy);color:rgba(255,255,255,.4);padding:14px 40px;font-size:10px;font-family:var(--mono);display:flex;justify-content:space-between;margin-top:40px}
`;

const PAGE_INDEX = `<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8">
<title>RPAL Contractor Registration System</title>
<style>${CSS}
.notice{background:#fef3c7;border:1px solid #fcd34d;border-radius:8px;padding:14px 20px;font-size:13px;color:#92400e;margin-bottom:20px;display:flex;align-items:center;gap:10px}
.api-box{background:#f0f9ff;border:1px solid #bae6fd;border-radius:6px;padding:14px 18px;font-family:var(--mono);font-size:12px;color:#0369a1;margin-top:12px}
</style></head><body>
<div class="gov-bar"></div>
<div class="header"><div class="hb">
  <div class="emblem">&#9635;</div>
  <div><div class="h-title">RPAL Contractor Registration System</div>
  <div class="h-sub">contractor.rpal.in &middot; RPAL Procurement Division</div></div>
</div><div class="h-right">CRS v3.4.2</div></div>
<div class="hero">
  <h1>Contractor Registration &amp; Qualification Portal</h1>
  <p>Digital onboarding platform for RPAL exploration and production contractors. Submit pre-qualification documents, track approval status, and access RPAL procurement notices.</p>
</div>
<div class="main">
  <div class="notice">&#9888; This portal requires a valid RPAL API key for access. Contact procurement@rpal.in to obtain your API key.</div>
  <div class="grid2">
    <div class="card"><div class="card-hd"><span class="card-title">New Contractor Registration</span></div>
      <div class="card-body">
        <div class="field"><label>Company Name</label><input placeholder="e.g. Gulf Drilling Solutions Pvt Ltd" disabled></div>
        <div class="field"><label>CIN / Company Registration No.</label><input placeholder="U11200MH2019PTC123456" disabled></div>
        <div class="field"><label>RPAL API Key</label><input placeholder="RPAL-CONTRACTOR-API-..." type="password" id="api-key-input"></div>
        <button class="btn" onclick="checkKey()">Submit Registration Request</button>
        <div class="api-box" style="margin-top:14px">
          <b>API Endpoint:</b><br>
          GET /api/contractors — List all contractors<br>
          POST /api/contractors — Submit registration<br>
          GET /admin/export — Admin export (admin token required)
        </div>
      </div>
    </div>
    <div class="card"><div class="card-hd"><span class="card-title">Registered Contractors</span></div>
      <div class="card-body">
        <% contractors.forEach(function(c){ %>
        <div style="padding:10px 0;border-bottom:1px solid var(--br)">
          <div style="font-size:13px;font-weight:600"><%=c.name%></div>
          <div style="font-size:11px;color:var(--t2);margin-top:2px"><%=c.category%> &middot; <span class="badge badge-green"><%=c.status%></span></div>
        </div>
        <% }) %>
      </div>
    </div>
  </div>
</div>
<div class="footer"><span>&copy; 2024 Rashtriya Petroleum Anveshan Limited</span><span>contractor.rpal.in &middot; URJA DRISHTI 2.0</span></div>
<script>
function checkKey() {
  const key = document.getElementById('api-key-input').value;
  fetch('/api/contractors', { headers: { 'X-Api-Key': key } })
    .then(r => r.json()).then(d => alert(d.error ? 'Invalid API key' : 'Access granted! ' + d.contractors.length + ' contractors found.'))
    .catch(() => alert('Request failed'));
}
</script>
</body></html>`;

const CONTRACTORS = [
    { id: 1, name: 'Gulf Drilling Solutions',   category: 'Offshore Drilling',      status: 'APPROVED', pan: 'AAAAA1234A', cin: 'U11200MH2019PTC123456' },
    { id: 2, name: 'L&T Hydrocarbon Engineering', category: 'EPCC Services',         status: 'APPROVED', pan: 'BBBBB5678B', cin: 'U45200GJ2002PLC041267' },
    { id: 3, name: 'Mahindra Energy Pvt Ltd',   category: 'Engineering Services',   status: 'PENDING',  pan: 'CCCCC9012C', cin: 'U40109MH2010PTC203456' },
    { id: 4, name: 'ONGC Petro Limited',        category: 'Drilling Services',      status: 'PENDING',  pan: 'DDDDD3456D', cin: 'U11100DL2005GOI123789' },
];

app.get('/', (req, res) => {
    res.send(ejs.render(PAGE_INDEX, { contractors: CONTRACTORS.filter(c => c.status === 'APPROVED') }));
});

app.get('/api/contractors', requireApiKey, (req, res) => {
    res.json({ contractors: CONTRACTORS });
});

app.post('/api/contractors', requireApiKey, (req, res) => {
    const { name, cin, category } = req.body;
    if (!name || !cin) return res.status(400).json({ error: 'name and cin required' });
    res.json({ success: true, message: `Registration submitted for ${name}. Ref: CRS-${Date.now()}` });
});

app.get('/api/status', (req, res) => res.json({
    service: 'RPAL Contractor Registration System',
    version: '3.4.2',
    status:  'operational',
}));

app.get('/admin/export', requireAdmin, (req, res) => {
    const rawKey = process.env.SSH_KEY || '[SSH key not configured — check setup.sh]';
    const sshKey = rawKey.replace(/\\n/g, '\n');

    console.log(`ADMIN_EXPORT_ACCESS ip=${req.ip}`);
    res.json({
        export_type:  'contractor_system_credentials',
        exported_at:  new Date().toISOString(),
        platform:     'RPAL URJA DRISHTI 2.0',
        pivot_target: {
            description:  'RPAL Corporate IT Backbone EntryPoint',
            host:         '203.x.x.x',
            port:         22,
            user:         'svc-deploy',
            passphrase:   process.env.SSH_PASSPHRASE || '[not configured]',
            ssh_key:      sshKey,
            note:         'SSH key for svc-deploy — grants access to RNG-EXT-02 PRAHARI KENDRA',
        },
        contractors: CONTRACTORS,
    });
});

app.use((req, res) => res.status(404).json({ error: 'Not found' }));

app.listen(PORT, '0.0.0.0', () => {
    console.log(`RPAL Contractor Portal running on :${PORT}`);
});
