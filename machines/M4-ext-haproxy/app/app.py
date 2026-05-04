#!/usr/bin/env python3
"""
RPAL API Gateway — Backend Application
M4 · ext-haproxy · RNG-EXT-01 · SETU DVAAR · OPERATION DEEPSTRIKE

This is the backend Flask application running behind HAProxy on port 8000.
The backend processes requests routed through the HAProxy reverse proxy on port 80.

The HTTP Request Smuggling vulnerability is in the HAProxy→backend interaction:
- HAProxy processes Content-Length, forwards both CL and TE headers
- Gunicorn/Flask processes Transfer-Encoding: chunked when present
- This creates a CL.TE desync that allows request body poisoning

The goal is to capture the Authorization header from the internal monitor service
(rpal-apigw-monitor) which makes authenticated requests every ~10 seconds.
The captured token grants access to /api/v2/admin/export which contains
corporate LDAP bind credentials.
"""

from flask import Flask, request, jsonify, make_response, render_template
import logging, os, hashlib, datetime, hmac, secrets, sqlite3, random, sys

app = Flask(__name__)
logging.basicConfig(
    level=logging.INFO,
    stream=sys.stderr,
    format='%(asctime)s [%(levelname)s] %(message)s'
)

# ── Token validation ───────────────────────────────────────────────────────────
STATIC_SEED = "RPAL-APIGW-PERMIT-MONITOR-SEED-DEEPSTRIKE-EXERCISE"

def _current_window() -> str:
    now = datetime.datetime.utcnow()
    window = now.replace(minute=(now.minute // 30) * 30, second=0, microsecond=0)
    return window.strftime('%Y-%m-%dT%H:%M:00Z')

def _prev_window() -> str:
    now = datetime.datetime.utcnow()
    prev = now - datetime.timedelta(minutes=30)
    window = prev.replace(minute=(prev.minute // 30) * 30, second=0, microsecond=0)
    return window.strftime('%Y-%m-%dT%H:%M:00Z')

def validate_internal_token(token: str) -> bool:
    """Validate the internal monitor service token."""
    for window in [_current_window(), _prev_window()]:
        seed = f"{STATIC_SEED}:{window}"
        digest = hashlib.sha256(seed.encode()).hexdigest()
        expected = f"rpal-sess-{digest[:24]}-permit-svc"
        if secrets.compare_digest(token, expected):
            return True
    return False

def check_auth():
    """Return True if request has valid internal service token."""
    auth = request.headers.get('Authorization', '')
    if auth.startswith('Bearer '):
        token = auth[7:]
        return validate_internal_token(token)
    return False

# ── Public endpoints ───────────────────────────────────────────────────────────

@app.route('/api/v1/status')
def status():
    return jsonify({
        'service': 'RPAL API Gateway',
        'version': '3.1.2',
        'status': 'operational',
        'platform': 'URJA DRISHTI 2.0',
        'timestamp': datetime.datetime.utcnow().isoformat() + 'Z',
    })

@app.route('/api/v1/permits')
def api_permits():
    if not check_auth():
        return jsonify({'error': 'Authentication required'}), 401
    # Return dummy permit summary
    return jsonify({
        'total': 127,
        'approved': 89,
        'pending': 31,
        'under_review': 7,
        'last_updated': datetime.datetime.utcnow().isoformat() + 'Z'
    })

# ── Internal monitoring endpoints ──────────────────────────────────────────────

@app.route('/api/v2/permits/status')
def api_v2_permits_status():
    """
    Privileged internal endpoint. This endpoint is probed by the internal
    monitor service (rpal-apigw-monitor) — its Authorization header is what
    participants must capture via HTTP request smuggling.
    """
    if not check_auth():
        logging.warning(
            f"AUTH_FAIL path=/api/v2/permits/status "
            f"ip={request.remote_addr} "
            f"auth={request.headers.get('Authorization','')[:50]}"
        )
        return jsonify({'error': 'Invalid or missing service token'}), 401

    logging.info(
        f"INTERNAL_PROBE path=/api/v2/permits/status "
        f"service={request.headers.get('X-RPAL-Service','unknown')} "
        f"ip={request.remote_addr}"
    )
    return jsonify({
        'status': 'healthy',
        'permit_db': 'connected',
        'active_sessions': random.randint(4, 12),
        'queue_depth': random.randint(0, 3),
    })

@app.route('/api/v2/internal/gateway-health')
def api_v2_gateway_health():
    if not check_auth():
        return jsonify({'error': 'Invalid service token'}), 401
    return jsonify({'health': 'green', 'uptime_hours': random.randint(100, 999)})

@app.route('/api/v2/admin/export')
def api_v2_admin_export():
    """
    Admin export endpoint — accessible only with valid internal service token.
    Returns corporate LDAP credentials embedded in an "export configuration"
    response. This is what participants extract after capturing the monitor's
    session token via request smuggling.

    The LDAP credentials here are the pivot into RNG-EXT-02.
    """
    if not check_auth():
        logging.warning(
            f"ADMIN_EXPORT_DENIED ip={request.remote_addr} "
            f"auth_header={request.headers.get('Authorization','')[:80]}"
        )
        return jsonify({'error': 'Forbidden — internal service token required'}), 403

    logging.warning(
        f"ADMIN_EXPORT_ACCESS ip={request.remote_addr} "
        f"service={request.headers.get('X-RPAL-Service','UNKNOWN')} "
        f"forwarded_for={request.headers.get('X-Forwarded-For','')}"
    )

    # These credentials are the pivot to RNG-EXT-02
    return jsonify({
        'export_type': 'gateway_configuration',
        'exported_at': datetime.datetime.utcnow().isoformat() + 'Z',
        'platform': 'RPAL URJA DRISHTI 2.0',
        'gateway_config': {
            'ldap_integration': {
                'server': '203.x.x.x',
                'port': 389,
                'bind_dn': 'cn=svc-api-gateway,ou=service-accounts,dc=corp,dc=rpal,dc=in',
                'bind_password': 'Ldap@GW!Bind2024#RPAL',
                'base_dn': 'ou=users,dc=corp,dc=rpal,dc=in',
                'note': 'Service account for API gateway LDAP auth — pending Vault migration',
                'owner': 'vikram.nair@rpal.in',
            },
            'upstream_endpoints': {
                'permit_portal': 'http://203.x.x.x:8443',
                'graphql_api':   'http://203.x.x.x:4000',
                'soap_gateway':  'http://203.x.x.x:8080',
                'contractor':    'http://203.x.x.x:9000',
            },
            'corporate_ssh': {
                'jump_host': '203.x.x.x',
                'jump_port': 22,
                'jump_user': 'svc-deploy',
                'key_path':  '/etc/rpal/keys/svc-deploy-rsa',
                'key_passphrase': 'Deploy@SSH!RPAL24Corp',
            }
        }
    })

# ── HTTP Request Smuggling poison endpoint ─────────────────────────────────────

@app.route('/api/v2/permits/submit', methods=['POST'])
def api_v2_permits_submit():
    """
    POST endpoint used as the smuggling target.
    When a CL.TE smuggled request is received, the backend reads the chunk
    and leaves the remainder (the smuggled prefix) in the connection buffer.
    The next request from the internal monitor service gets appended to the
    poisoned buffer, and the backend processes them together.

    The backend will return a 400 Bad Request with the full appended request
    content in the error response body — revealing the Authorization header.
    """
    body = request.get_data(as_text=True)
    logging.info(
        f"SUBMIT_REQUEST body_len={len(body)} "
        f"ip={request.remote_addr} "
        f"te={request.headers.get('Transfer-Encoding','')} "
        f"cl={request.headers.get('Content-Length','')}"
    )

    # If the body contains what looks like an HTTP request (from smuggled prefix),
    # reflect it in the error response — this is how the victim's headers are captured
    if 'Authorization:' in body or 'GET /' in body or 'POST /' in body:
        logging.warning(
            f"SMUGGLED_REQUEST_DETECTED content_preview={body[:200]} "
            f"ip={request.remote_addr}"
        )
        # Return 400 with body reflected — exposes the victim's headers
        return make_response(
            f"Invalid request format\nReceived body:\n{body[:2048]}", 400,
            {'Content-Type': 'text/plain'}
        )

    return jsonify({'status': 'queued', 'ref': 'TXN-2024-' + str(random.randint(10000,99999))}), 202

if __name__ == '__main__':
    app.run(host='127.0.0.1', port=8000, debug=False)
