#!/usr/bin/env python3
"""
RPAL Contractor Onboarding Portal — app.py
M5 · ext-contractor · RNG-EXT-01 · SETU DVAAR · OPERATION DEEPSTRIKE

VULNERABILITY: wkhtmltopdf 0.12.5 Server-Side Request Forgery via file:// URI

wkhtmltopdf 0.12.5 fetches URLs embedded in HTML when generating PDFs.
The contractor onboarding portal allows applicants to provide a "Company Profile URL"
that is fetched and embedded in the generated PDF summary.

The URL is passed directly to wkhtmltopdf without validation. wkhtmltopdf 0.12.5
supports the file:// protocol — allowing attackers to read arbitrary local files.

The /etc/rpal/upstream/config.ini file contains:
  - SSH private key (for svc-deploy jump host access → RNG-EXT-02 entry)
  - LDAP bind credentials for corporate directory

Attack: Submit company profile URL as file:///etc/rpal/upstream/config.ini
→ wkhtmltopdf reads the file
→ Content appears in the generated PDF
→ Download the PDF and extract the credentials
"""

from flask import (Flask, request, render_template, redirect, url_for,
                   session, send_file, jsonify, make_response)
import subprocess, os, tempfile, hashlib, logging, sqlite3, datetime, re, uuid

app = Flask(__name__)
app.secret_key = os.urandom(32)

LOG_DIR = '/var/log/rpal/contractor-portal'
DB_PATH = os.environ.get('DB_PATH', '/var/lib/rpal/contractor-portal/onboarding.db')
WKHTMLTOPDF = os.environ.get('WKHTMLTOPDF', '/usr/local/bin/wkhtmltopdf')
PORT = int(os.environ.get('PORT', 9000))

os.makedirs(LOG_DIR, exist_ok=True)
logging.basicConfig(filename=f'{LOG_DIR}/portal.log', level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s')

USERS = {
    'contractor.01': {'password': hashlib.sha256('Contractor@2024!'.encode()).hexdigest(),
                      'company': 'Gulf Drilling Solutions', 'role': 'contractor'},
    'contractor.02': {'password': hashlib.sha256('Gulf@Drilling#24!'.encode()).hexdigest(),
                      'company': 'Mahindra Energy Pvt Ltd', 'role': 'contractor'},
    'rpal-hseinspector': {'password': hashlib.sha256('RPAL@HSE!Inspect24'.encode()).hexdigest(),
                           'company': 'RPAL Internal', 'role': 'inspector'},
}

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def logged_in():
    return 'user' in session

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        user = USERS.get(username)
        if user and user['password'] == hashlib.sha256(password.encode()).hexdigest():
            session['user'] = {'username': username,
                                'company': user['company'],
                                'role': user['role']}
            logging.info(f"LOGIN_OK user={username} ip={request.remote_addr}")
            return redirect(url_for('dashboard'))
        logging.warning(f"LOGIN_FAIL user={username} ip={request.remote_addr}")
        error = 'Invalid credentials. Contact RPAL procurement at contractor@rpal.in'
    return render_template('login.html', error=error)

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('index'))

@app.route('/dashboard')
def dashboard():
    if not logged_in():
        return redirect(url_for('login'))
    db = get_db()
    applications = db.execute(
        'SELECT * FROM applications WHERE contractor_username=? ORDER BY submitted_at DESC',
        (session['user']['username'],)
    ).fetchall()
    db.close()
    return render_template('dashboard.html', user=session['user'], applications=applications)

@app.route('/apply', methods=['GET', 'POST'])
def apply():
    if not logged_in():
        return redirect(url_for('login'))

    if request.method == 'POST':
        application_id = str(uuid.uuid4())[:8].upper()
        company_name     = request.form.get('company_name', '').strip()
        contact_name     = request.form.get('contact_name', '').strip()
        contact_email    = request.form.get('contact_email', '').strip()
        work_category    = request.form.get('work_category', '').strip()
        company_profile_url = request.form.get('company_profile_url', '').strip()
        pan_number       = request.form.get('pan_number', '').strip()

        logging.info(
            f"APPLICATION user={session['user']['username']} "
            f"company={company_name} profile_url={company_profile_url} "
            f"ip={request.remote_addr}"
        )

        db = get_db()
        db.execute("""INSERT INTO applications
            (application_id, contractor_username, company_name, contact_name,
             contact_email, work_category, company_profile_url, pan_number,
             status, submitted_at)
            VALUES (?,?,?,?,?,?,?,?,'pending',datetime('now'))""",
            (application_id, session['user']['username'], company_name, contact_name,
             contact_email, work_category, company_profile_url, pan_number))
        db.commit()
        db.close()

        # Generate PDF summary
        # VULNERABILITY: company_profile_url is passed to wkhtmltopdf without validation
        # wkhtmltopdf 0.12.5 supports file:// protocol — reads local files
        pdf_path = generate_application_pdf(
            application_id=application_id,
            company_name=company_name,
            contact_name=contact_name,
            work_category=work_category,
            company_profile_url=company_profile_url,
            username=session['user']['username']
        )

        return render_template('apply_success.html',
                               user=session['user'],
                               application_id=application_id,
                               pdf_path=pdf_path)

    return render_template('apply.html', user=session['user'])

def generate_application_pdf(application_id, company_name, contact_name,
                              work_category, company_profile_url, username):
    """
    Generate PDF application summary using wkhtmltopdf 0.12.5.

    VULNERABILITY: company_profile_url is passed to wkhtmltopdf as a URL to fetch.
    wkhtmltopdf 0.12.5 supports:
      - http:// and https:// (fetch remote URLs)
      - file:// (read local filesystem files) << VULNERABILITY
      - data:// (inline data)

    An attacker can pass file:///etc/rpal/upstream/config.ini to read the
    SSH key and LDAP credentials for the RNG-EXT-02 pivot.

    In legitimate use, this would fetch the company's public website profile page
    and embed it as an additional page in the PDF. No validation is performed.
    """
    # HTML template for the PDF
    html_content = f"""<!DOCTYPE html>
<html><head><meta charset="UTF-8">
<style>
body {{ font-family: Arial, sans-serif; color: #333; margin: 40px; }}
.header {{ background: #1a237e; color: white; padding: 20px; border-radius: 8px; margin-bottom: 24px; }}
.header h1 {{ margin: 0; font-size: 20px; }}
.header p {{ margin: 4px 0 0; font-size: 12px; opacity: 0.8; }}
.section {{ margin-bottom: 20px; border: 1px solid #ddd; border-radius: 6px; padding: 16px; }}
.section h2 {{ margin: 0 0 12px; font-size: 14px; color: #1a237e; border-bottom: 1px solid #eee; padding-bottom: 8px; }}
.field {{ display: flex; margin-bottom: 8px; }}
.label {{ font-weight: bold; width: 180px; font-size: 12px; color: #555; }}
.value {{ font-size: 12px; color: #333; }}
.footer {{ margin-top: 32px; font-size: 10px; color: #999; text-align: center; border-top: 1px solid #eee; padding-top: 12px; }}
</style></head><body>
<div class="header">
  <h1>RPAL Contractor Onboarding Application</h1>
  <p>Rashtriya Petroleum Anveshan Limited | URJA DRISHTI 2.0 | Application #{application_id}</p>
</div>
<div class="section">
  <h2>Application Details</h2>
  <div class="field"><span class="label">Application ID:</span><span class="value">{application_id}</span></div>
  <div class="field"><span class="label">Submitted By:</span><span class="value">{username}</span></div>
  <div class="field"><span class="label">Submission Date:</span><span class="value">{datetime.datetime.now().strftime('%d %B %Y %H:%M IST')}</span></div>
  <div class="field"><span class="label">Status:</span><span class="value">Under Review</span></div>
</div>
<div class="section">
  <h2>Company Information</h2>
  <div class="field"><span class="label">Company Name:</span><span class="value">{company_name}</span></div>
  <div class="field"><span class="label">Contact Person:</span><span class="value">{contact_name}</span></div>
  <div class="field"><span class="label">Work Category:</span><span class="value">{work_category}</span></div>
  <div class="field"><span class="label">Company Profile URL:</span><span class="value">{company_profile_url}</span></div>
</div>
<div class="footer">
  Generated by RPAL Contractor Portal | contractor.rpal.in | URJA DRISHTI 2.0<br>
  This document is system-generated. For queries: contractor@rpal.in | +91-22-2495-6000
</div>
</body></html>"""

    tmpdir = tempfile.mkdtemp(prefix='rpal-pdf-')
    html_file = os.path.join(tmpdir, 'application.html')
    pdf_file  = os.path.join(tmpdir, f'RPAL-CTR-{application_id}.pdf')

    with open(html_file, 'w') as f:
        f.write(html_content)

    # VULNERABILITY: --allow "" permits all file:// access
    # company_profile_url is appended as an additional page source
    # The PDF will contain: page 1 = application form, page 2 = contents of company_profile_url
    cmd = [
        WKHTMLTOPDF,
        '--quiet',
        '--enable-local-file-access',    # << VULNERABILITY: enables file:// protocol
        '--allow', '',                    # << VULNERABILITY: allows all paths
        '--javascript-delay', '0',
        html_file,                        # Page 1: application form
    ]

    # Add company profile as additional page if URL provided
    if company_profile_url:
        cmd.append(company_profile_url)  # << VULNERABILITY: unvalidated URL to wkhtmltopdf
        logging.info(f"PDF_GENERATE app={application_id} profile_url={company_profile_url}")

    cmd.append(pdf_file)

    try:
        result = subprocess.run(cmd, capture_output=True, timeout=30)
        if result.returncode == 0 and os.path.exists(pdf_file):
            logging.info(f"PDF_SUCCESS app={application_id} size={os.path.getsize(pdf_file)}")
            return pdf_file
        else:
            logging.error(f"PDF_FAIL app={application_id} stderr={result.stderr[:200]}")
            return None
    except subprocess.TimeoutExpired:
        logging.error(f"PDF_TIMEOUT app={application_id}")
        return None
    except Exception as e:
        logging.error(f"PDF_ERROR app={application_id} error={e}")
        return None

@app.route('/download-pdf')
def download_pdf():
    if not logged_in():
        return redirect(url_for('login'))
    pdf_path = request.args.get('path', '')
    if not pdf_path or not os.path.exists(pdf_path):
        return "PDF not found or expired", 404
    # Basic path validation — only serve from tmpdir
    if not pdf_path.startswith('/tmp/rpal-pdf-'):
        return "Invalid path", 403
    return send_file(pdf_path, as_attachment=True,
                     download_name=os.path.basename(pdf_path))

@app.route('/api/status')
def api_status():
    return jsonify({
        'service': 'RPAL Contractor Onboarding Portal',
        'version': '1.8.3',
        'status': 'operational',
    })

@app.errorhandler(404)
def not_found(e):
    return render_template('error.html', message='Page not found'), 404

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=PORT, debug=False)
