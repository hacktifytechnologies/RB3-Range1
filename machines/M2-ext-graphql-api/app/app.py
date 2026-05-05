#!/usr/bin/env python3
"""
RPAL Exploration Data API — GraphQL Service
M2 · ext-graphql-api · RNG-EXT-01 · SETU DVAAR · OPERATION DEEPSTRIKE

"""

from flask import Flask, request, jsonify, render_template, make_response
import strawberry
from strawberry.flask.views import GraphQLView
from strawberry.extensions import AddValidationRules
from graphql import NoSchemaIntrospectionCustomRule
from strawberry.types import Info
from typing import Optional, List
import sqlite3, hashlib, logging, sys, os, json, functools, datetime, typing

app = Flask(__name__)
DB_PATH  = os.environ.get('DB_PATH', '/var/lib/rpal/graphql-api/explore.db')
PORT     = int(os.environ.get('PORT', 4000))
API_KEY  = os.environ.get('RPAL_API_KEY', 'RPAL-API-2024-XK9mP3nT8qRs')
SVC_PASS = os.environ.get('RPAL_SVC_PASS', 'T@riff@Expl0re!24')

logging.basicConfig(level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    stream=sys.stderr)

def get_auth_context(req) -> dict:
    auth = req.headers.get('Authorization', '')
    api_key = req.headers.get('X-API-Key', '')
    ctx = {'authenticated': False, 'role': 'anonymous', 'user': None}
    if api_key == API_KEY:
        ctx.update({'authenticated': True, 'role': 'service', 'user': 'rpal-explore-svc'})
    elif auth.startswith('Bearer '):
        token = auth[7:]
        if token == hashlib.sha256(f"{SVC_PASS}:rpal-explore-svc".encode()).hexdigest():
            ctx.update({'authenticated': True, 'role': 'service', 'user': 'rpal-explore-svc'})
    return ctx

def require_auth(fn):
    @functools.wraps(fn)
    def wrapper(root, info: Info, **kwargs):
        ctx = info.context.get('auth', {})
        if not ctx.get('authenticated'):
            raise Exception("Authentication required — provide X-API-Key header")
        return fn(root, info, **kwargs)
    return wrapper

def db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

@strawberry.type
class WellLog:
    well_id: str
    block_name: str
    well_type: str
    depth_tvdss: float
    formation: str
    operator: str
    spud_date: str
    status: str

@strawberry.type
class ExplorationBlock:
    block_id: str
    block_name: str
    basin: str
    block_type: str
    area_sqkm: float
    operator: str
    round_name: str
    award_date: str
    status: str

@strawberry.type
class Employee:
    employee_id: str
    full_name: str
    designation: str
    department: str
    email: str
    phone: Optional[str]
    location: str

@strawberry.type
class SystemAccount:
    account_id: str
    username: str
    service_name: str
    endpoint: str
    api_key: Optional[str]
    password_hash: Optional[str]
    plaintext_password: Optional[str]   
    owner: str
    notes: str

@strawberry.type
class InternalService:
    service_id: str
    service_name: str
    endpoint: str
    auth_type: str
    credentials: Optional[str]
    description: str

@strawberry.type
class BatchResult:
    key: str
    data: strawberry.scalars.JSON

@strawberry.type
class Query:

    @strawberry.field
    @require_auth
    def well_logs(self, info: Info, block_name: Optional[str] = None) -> List[WellLog]:
        logging.info(f"QUERY well_logs block={block_name} user={info.context['auth']['user']}")
        conn = db()
        if block_name:
            rows = conn.execute("SELECT * FROM well_logs WHERE block_name=?", (block_name,)).fetchall()
        else:
            rows = conn.execute("SELECT * FROM well_logs LIMIT 20").fetchall()
        conn.close()
        return [WellLog(**dict(r)) for r in rows]

    @strawberry.field
    @require_auth
    def exploration_blocks(self, info: Info, basin: Optional[str] = None) -> List[ExplorationBlock]:
        logging.info(f"QUERY exploration_blocks basin={basin} user={info.context['auth']['user']}")
        conn = db()
        if basin:
            rows = conn.execute("SELECT * FROM exploration_blocks WHERE basin=?", (basin,)).fetchall()
        else:
            rows = conn.execute("SELECT * FROM exploration_blocks LIMIT 20").fetchall()
        conn.close()
        return [ExplorationBlock(**dict(r)) for r in rows]

    @strawberry.field
    @require_auth
    def employees(self, info: Info, department: Optional[str] = None) -> List[Employee]:
        """Requires authentication — normal employees accessible with service key."""
        ctx = info.context['auth']
        if ctx['role'] not in ('service', 'admin'):
            raise Exception("Insufficient privileges to access employee records")
        logging.info(f"QUERY employees dept={department} user={ctx['user']}")
        conn = db()
        rows = conn.execute("SELECT * FROM employees").fetchall()
        conn.close()
        return [Employee(**dict(r)) for r in rows]

    @strawberry.field
    @require_auth
    def system_accounts(self, info: Info) -> List[SystemAccount]:
        """Admin-only resolver — should not be accessible to service accounts."""
        ctx = info.context['auth']
        if ctx['role'] != 'admin':
            raise Exception("Admin role required to access system accounts")
        logging.warning(f"QUERY system_accounts user={ctx['user']}")
        conn = db()
        rows = conn.execute("SELECT * FROM system_accounts").fetchall()
        conn.close()
        return [SystemAccount(**dict(r)) for r in rows]

    @strawberry.field
    def batch_query(self, info: Info, queries: List[str]) -> List[BatchResult]:
        
        logging.warning(
            f"BATCH_QUERY_ACCESSED queries={queries} "
            f"ip={request.remote_addr} "
            f"auth={info.context.get('auth',{}).get('authenticated',False)}"
        )
        results = []
        conn = db()
        for q in queries:
            q_lower = q.strip().lower()
            if 'systemaccounts' in q_lower or 'system_accounts' in q_lower:
                rows = conn.execute("SELECT * FROM system_accounts").fetchall()
                results.append(BatchResult(
                    key=q,
                    data=[dict(r) for r in rows]
                ))
            elif 'internalservices' in q_lower or 'internal_services' in q_lower:
                rows = conn.execute("SELECT * FROM internal_services").fetchall()
                results.append(BatchResult(
                    key=q,
                    data=[dict(r) for r in rows]
                ))
            elif 'employees' in q_lower:
                rows = conn.execute("SELECT * FROM employees").fetchall()
                results.append(BatchResult(
                    key=q,
                    data=[dict(r) for r in rows]
                ))
            elif 'exploration_blocks' in q_lower or 'explorationblocks' in q_lower:
                rows = conn.execute("SELECT * FROM exploration_blocks").fetchall()
                results.append(BatchResult(
                    key=q,
                    data=[dict(r) for r in rows]
                ))
            else:
                results.append(BatchResult(key=q, data={'error': f'Unknown query: {q}'}))
        conn.close()
        return results

schema = strawberry.Schema(
    query=Query,
    extensions=[AddValidationRules([NoSchemaIntrospectionCustomRule])],  
)

class AuthGraphQLView(GraphQLView):
    def get_context(self, request, response) -> dict:
        return {
            'request': request,
            'response': response,
            'auth': get_auth_context(request),
        }

app.add_url_rule(
    '/graphql',
    view_func=AuthGraphQLView.as_view('graphql_view', schema=schema)
)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/status')
def api_status():
    return jsonify({
        'service': 'RPAL Exploration Data GraphQL API',
        'version': '3.2.1',
        'status': 'operational',
        'graphql_endpoint': '/graphql',
        'introspection': 'disabled',
        'documentation': 'https://intranet.rpal.in/docs/graphql-api',
    })

@app.route('/graphiql')
def graphiql():
    """GraphiQL IDE — accessible for authenticated users."""
    return render_template('graphiql.html')

@app.errorhandler(404)
def not_found(e):
    return jsonify({'error': 'Not found'}), 404

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=PORT, debug=False)
