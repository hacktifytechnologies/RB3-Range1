#!/usr/bin/env bash
# M4-ext-survey-portal.sh — Supporting services for M4 RNG-EXT-01
# Theme: geological data / data science / analytics stack
# All services are TCP banner services — no Python, no Flask
set -euo pipefail
[[ $EUID -ne 0 ]] && { echo "Run as root: sudo bash $0"; exit 1; }
GREEN='\033[0;32m'; CYAN='\033[0;36m'; NC='\033[0m'
log()  { echo -e "${GREEN}[RPAL-EXT]${NC} $*"; }
info() { echo -e "${CYAN}[+]${NC} $*"; }

log "Deploying M4 supporting infrastructure services..."

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

# :8888 — Jupyter Notebook (data scientists use this for well log analysis)
deploy_tcp 8888 "rpal-jupyter-survey" \
    "RPAL Geological Survey — Jupyter Notebook Server" \
    "HTTP/1.1 200 OK\r\nServer: Jupyter/6.5.4\r\nContent-Type: text/html\r\n\r\n<html><head><title>RPAL Survey Analytics — Jupyter</title></head><body><h3>Jupyter Notebook — RPAL Geological Survey</h3><p>Authentication required. Token: <a href='/login?next=%2Ftree'>Sign in</a></p></body></html>\r\n"

# :6006 — TensorBoard (ML model training for seismic interpretation)
deploy_tcp 6006 "rpal-tensorboard-survey" \
    "RPAL Seismic Interpretation TensorBoard" \
    "HTTP/1.1 200 OK\r\nServer: TensorBoard/2.14.0\r\nContent-Type: application/json\r\n\r\n{\"version\":\"2.14.0\",\"data_location\":\"logdir=/opt/rpal/survey/tb-logs\",\"plugin\":\"scalars\"}\r\n"

# :9200 — Elasticsearch (geological data indexing)
deploy_tcp 9200 "rpal-elasticsearch-survey" \
    "RPAL Geological Data Search Index — Elasticsearch" \
    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{\"name\":\"rpal-survey-node-01\",\"cluster_name\":\"rpal-geological-data\",\"version\":{\"number\":\"8.12.1\",\"build_flavor\":\"default\"},\"tagline\":\"You Know, for Search\"}\r\n"

# :5432 — PostgreSQL (geological database — connection string in M4 source)
deploy_tcp 5432 "rpal-postgres-geosurvey" \
    "RPAL Geological Survey PostgreSQL Database" \
    "\x4e\x00\x00\x00\x08\x04\xd2\x16\x2fRPAL-GeoSurvey-DB/PostgreSQL-14.9\r\nDatabase: rpal_geosurvey\r\nSSL required.\r\n"

# :27017 — MongoDB (unstructured well log documents)
deploy_tcp 27017 "rpal-mongodb-wellogs" \
    "RPAL Well Log Document Store — MongoDB" \
    "\x3f\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xd4\x07\x00\x00\x00\x00\x00\x00RPAL-WellLog-MongoDB/7.0.4 on survey.rpal.in\r\nAuth required: SCRAM-SHA-256\r\n"

# :4040 — Apache Spark UI (seismic data processing)
deploy_tcp 4040 "rpal-spark-survey" \
    "RPAL Seismic Data Processing — Spark Master UI" \
    "HTTP/1.1 200 OK\r\nServer: Spark/3.5.0\r\nContent-Type: text/html\r\n\r\n<html><title>Spark Master at spark://survey.rpal.in:7077</title><body>Spark 3.5.0 Master — RPAL Seismic Processing Cluster<br>Workers: 3 | Cores: 24 | Memory: 96GB</body></html>\r\n"

# :11434 — Ollama (local LLM for geological report drafting — modern)
deploy_tcp 11434 "rpal-ollama-survey" \
    "RPAL Geological Report AI Assistant — Ollama" \
    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{\"status\":\"Ollama is running\",\"models\":[{\"name\":\"llama3.1:8b\",\"modified_at\":\"2024-10-01T00:00:00Z\"}]}\r\n"

log "M4 supporting services deployed."
info "Ports: :8888 (Jupyter)  :6006 (TensorBoard)  :9200 (Elasticsearch)"
info "       :5432 (PostgreSQL)  :27017 (MongoDB)  :4040 (Spark)  :11434 (Ollama)"
info "Real service: RPAL Geological Survey Portal on :3000"
