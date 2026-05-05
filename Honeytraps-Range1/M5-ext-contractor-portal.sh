#!/usr/bin/env bash
# M5-ext-contractor-portal.sh — Supporting services for M5 RNG-EXT-01
# Theme: contractor management / procurement / government systems
set -euo pipefail
[[ $EUID -ne 0 ]] && { echo "Run as root: sudo bash $0"; exit 1; }
GREEN='\033[0;32m'; CYAN='\033[0;36m'; NC='\033[0m'
log()  { echo -e "${GREEN}[RPAL-EXT]${NC} $*"; }
info() { echo -e "${CYAN}[+]${NC} $*"; }

log "Deploying M5 supporting infrastructure services..."

deploy_tcp() {
    local PORT="$1" SVC="$2" DESC="$3" BANNER="$4"
    cat > "/etc/systemd/system/${SVC}.service" << SVCEOF
[Unit]
Description=${DESC}
After=network.target
[Service]
Type=simple
User=nobody
ExecStart=/bin/bash -c "while true; do printf '${BANNER}' | nc -l -p ${PORT} -q 1 2>/dev/null || true; sleep 1; done"
Restart=always
RestartSec=5
StandardOutput=journal
StandardError=journal
[Install]
WantedBy=multi-user.target
SVCEOF
    systemctl daemon-reload
    systemctl enable "${SVC}" --now 2>/dev/null || true
    info "TCP :${PORT} → ${DESC}"
}

# :8080 — Apache Tomcat (SAP Ariba integration middleware)
deploy_tcp 8080 "rpal-tomcat-procurement" \
    "RPAL Procurement Integration — Apache Tomcat" \
    "HTTP/1.1 200 OK\r\nServer: Apache-Coyote/1.1\r\nX-Powered-By: Servlet/4.0\r\n\r\n<!DOCTYPE html><html><head><title>RPAL Procurement Gateway — Apache Tomcat 9.0.83</title></head><body><h2>RPAL Procurement Middleware</h2><p>SAP Ariba integration endpoint. Authentication required.</p></body></html>\r\n"

# :21 — FTP (contractor document submission)
deploy_tcp 21 "rpal-ftp-contractor" \
    "RPAL Contractor Document Submission FTP" \
    "220 contractor.rpal.in RPAL Contractor FTP Server v2.4\r\n331 Password required for contractor submission.\r\n530 Login incorrect.\r\n221 Goodbye.\r\n"

# :3306 — MySQL (contractor database)
deploy_tcp 3306 "rpal-mysql-contractor" \
    "RPAL Contractor Registration Database — MySQL" \
    "\x4a\x00\x00\x00\n8.0.35-RPAL-ContractorDB\x00\x01\x00\x00\x00\x52\x50\x41\x4c MySQL 8.0.35 RPAL Contractor DB\r\nSSL required.\r\n"

# :445 — SMB (contractor document share)
deploy_tcp 445 "rpal-smb-contractor" \
    "RPAL Contractor Document Share — SMB" \
    "\x00\x00\x00\x45\xffSMBr\x00\x00\x00\x00RPAL-CONTRACTOR-SHARE contractor.rpal.in\r\nShare: \\\\contractor.rpal.in\\ProcurementDocs\r\nAuth: NTLM required.\r\n"

# :25 — SMTP (procurement notifications)
deploy_tcp 25 "rpal-smtp-procurement" \
    "RPAL Procurement Notification SMTP Relay" \
    "220 mail.rpal.in ESMTP RPAL-Procurement-SMTP/3.7\r\n"

# :8443 — HTTPS (SAP SRM portal)
deploy_tcp 8443 "rpal-sap-srm" \
    "RPAL SAP SRM Supplier Portal" \
    "HTTP/1.1 302 Found\r\nServer: SAP NetWeaver\r\nLocation: https://contractor.rpal.in:8443/sap/bc/webdynpro/sap/srm\r\nX-SAP-System-ID: PRD\r\n\r\n"

# :2222 — SSH (developer access — different port to avoid confusion with real SSH)
deploy_tcp 2222 "rpal-ssh-contractor-dev" \
    "RPAL Contractor Portal Developer SSH" \
    "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6\r\nRPAL Contractor Portal Developer Access — contractor.rpal.in\r\nUnauthorised access is strictly prohibited.\r\n"

log "M5 supporting services deployed."
info "Ports: :8080 (Tomcat)  :21 (FTP)  :3306 (MySQL)  :445 (SMB)"
info "       :25 (SMTP)  :8443 (SAP SRM)  :2222 (Dev SSH)"
info "Real service: RPAL Contractor Registration System on :4000"
