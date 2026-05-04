#!/usr/bin/env python3
"""
RPAL Internal API Gateway Health Monitor
rpal-apigw-monitor — systemd service

This script is the internal health-checking daemon for the RPAL API Gateway.
It periodically probes internal backend endpoints to verify availability and
response integrity. This is a standard SRE practice for the URJA DRISHTI 2.0
platform's API gateway cluster.

In the exercise context: this daemon simulates a legitimate privileged internal
service making authenticated requests through the HAProxy frontend. Its session
token is what participants must capture via HTTP request smuggling (CL.TE).

The token rotates every 30 minutes using a deterministic seeded PRNG (seeded from
datetime truncated to 30-minute window) — predictable for scoring, appears live.
"""

import requests, time, logging, os, hashlib, random, datetime, signal, sys

# ── Configuration ──────────────────────────────────────────────────────────────
GATEWAY_URL    = os.environ.get('RPAL_GATEWAY_URL',  'http://127.0.0.1:80')
BACKEND_URL    = os.environ.get('RPAL_BACKEND_URL',  'http://127.0.0.1:8000')
PROBE_INTERVAL = int(os.environ.get('PROBE_INTERVAL', '10'))   # seconds

logging.basicConfig(
    level=logging.INFO,
    stream=sys.stderr,
    format='%(asctime)s [%(levelname)s] %(name)s: %(message)s'
)
log = logging.getLogger('rpal-apigw-monitor')

# ── Token generation ───────────────────────────────────────────────────────────
# Token rotates every 30 minutes, seeded deterministically from datetime.
# This simulates a rotating service token without requiring a real auth server.

STATIC_SEED = "RPAL-APIGW-PERMIT-MONITOR-SEED-DEEPSTRIKE-EXERCISE"

def _current_window() -> str:
    """Return a string representing the current 30-minute window."""
    now = datetime.datetime.utcnow()
    window = now.replace(minute=(now.minute // 30) * 30, second=0, microsecond=0)
    return window.strftime('%Y-%m-%dT%H:%M:00Z')

def generate_session_token() -> str:
    """
    Generate a deterministic session token for the current 30-minute window.

    TOKEN STRUCTURE:
      rpal-sess-<base32(sha256(seed + window)[:12])>-<user_fragment>

    This token is what participants must capture via HTTP request smuggling.
    The actual value they need to extract is the full Authorization header:
      Authorization: Bearer <token>
    """
    window = _current_window()
    seed = f"{STATIC_SEED}:{window}"
    digest = hashlib.sha256(seed.encode()).hexdigest()
    # Take first 24 hex chars = 96 bits of token entropy
    token_body = digest[:24]
    return f"rpal-sess-{token_body}-permit-svc"

def get_auth_header() -> dict:
    token = generate_session_token()
    return {
        "Authorization": f"Bearer {token}",
        "X-RPAL-Service": "apigw-permit-monitor",
        "X-RPAL-Client-ID": "internal-health-probe",
        "User-Agent": "RPAL-APIGateway-HealthMonitor/1.0",
        "Host": "api-gw.rpal.in",
    }

# ── Probe targets ──────────────────────────────────────────────────────────────
# The monitor checks multiple internal endpoints on a rotating basis.
# The critical one (from the exercise perspective) is /api/v2/permits/status
# which requires the privileged permit-officer session token.

PROBE_ENDPOINTS = [
    ("/api/v1/status",                       False),   # public health check
    ("/api/v1/permits",                       True),    # requires auth
    ("/api/v2/permits/status",                True),    # privileged — token captured here
    ("/api/v2/internal/gateway-health",       True),    # internal endpoint
]

probe_idx = 0

def run_probe():
    global probe_idx
    endpoint, requires_auth = PROBE_ENDPOINTS[probe_idx % len(PROBE_ENDPOINTS)]
    probe_idx += 1

    url = f"{GATEWAY_URL}{endpoint}"
    headers = get_auth_header() if requires_auth else {
        "User-Agent": "RPAL-APIGateway-HealthMonitor/1.0",
        "Host": "api-gw.rpal.in",
    }

    try:
        resp = requests.get(url, headers=headers, timeout=5, allow_redirects=False)
        log.info(
            f"PROBE endpoint={endpoint} status={resp.status_code} "
            f"auth={requires_auth} latency={resp.elapsed.total_seconds():.3f}s"
        )
        if resp.status_code not in (200, 204, 301, 302):
            log.warning(
                f"PROBE_DEGRADED endpoint={endpoint} status={resp.status_code}"
            )
    except requests.exceptions.ConnectionError:
        log.error(f"PROBE_UNREACHABLE endpoint={endpoint} url={url}")
    except requests.exceptions.Timeout:
        log.error(f"PROBE_TIMEOUT endpoint={endpoint}")
    except Exception as e:
        log.error(f"PROBE_ERROR endpoint={endpoint} error={e}")

# ── Signal handling ────────────────────────────────────────────────────────────

def handle_sigterm(signum, frame):
    log.info("Monitor received SIGTERM — shutting down gracefully")
    sys.exit(0)

signal.signal(signal.SIGTERM, handle_sigterm)
signal.signal(signal.SIGINT, handle_sigterm)

# ── Main loop ──────────────────────────────────────────────────────────────────

if __name__ == '__main__':
    log.info("RPAL API Gateway Health Monitor starting")
    log.info(f"Gateway URL: {GATEWAY_URL}")
    log.info(f"Probe interval: {PROBE_INTERVAL}s")
    log.info(f"Monitor endpoints: {len(PROBE_ENDPOINTS)}")

    # Stagger initial start to avoid thundering herd
    initial_delay = random.uniform(2, 8)
    log.info(f"Initial delay: {initial_delay:.1f}s")
    time.sleep(initial_delay)

    while True:
        run_probe()
        time.sleep(PROBE_INTERVAL)
