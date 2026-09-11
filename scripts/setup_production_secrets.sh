#!/usr/bin/env bash
# ==============================================================================
# Security Operations Platform (SOP) — Production Secrets Setup Script
# Generates cryptographically secure credentials and writes a hardened .env.production
# for the Contabo VPS deployment.
#
# Usage:
#   chmod +x scripts/setup_production_secrets.sh
#   ./scripts/setup_production_secrets.sh
# ==============================================================================

set -euo pipefail

ENV_FILE=".env.production"
BACKUP_DIR="./backups/secrets"

echo "=========================================================="
echo "  SOC Platform — Production Secrets Generator & Hardener  "
echo "=========================================================="

# Check for openssl or python3 for random generation
generate_secret() {
    local length="${1:-32}"
    if command -v openssl >/dev/null 2>&1; then
        openssl rand -hex "$length"
    elif command -v python3 >/dev/null 2>&1; then
        python3 -c "import secrets; print(secrets.token_hex($length))"
    else
        # Fallback to /dev/urandom
        tr -dc 'a-zA-Z0-9' < /dev/urandom | head -c "$((length * 2))"
    fi
}

# Generate a strong alphanumeric password with special chars for strict policies
generate_password() {
    if command -v python3 >/dev/null 2>&1; then
        python3 -c '
import secrets, string
chars = string.ascii_letters + string.digits + "!@#$%^&*"
while True:
    pwd = "".join(secrets.choice(chars) for _ in range(32))
    if (any(c.islower() for c in pwd) and any(c.isupper() for c in pwd) 
        and any(c.isdigit() for c in pwd) and any(c in "!@#$%^&*" for c in pwd)):
        print(pwd)
        break
'
    else
        echo "$(generate_secret 16)A1!"
    fi
}

if [ -f "$ENV_FILE" ]; then
    echo "[!] Existing $ENV_FILE found."
    mkdir -p "$BACKUP_DIR"
    TIMESTAMP=$(date +%Y%m%d_%H%M%S)
    cp "$ENV_FILE" "${BACKUP_DIR}/env_production_${TIMESTAMP}.bak"
    echo "[+] Backup saved to ${BACKUP_DIR}/env_production_${TIMESTAMP}.bak"
    read -p "Do you want to re-generate random passwords and update $ENV_FILE? (y/N): " CONFIRM
    if [[ ! "$CONFIRM" =~ ^[Yy]$ ]]; then
        echo "Exiting without making changes."
        exit 0
    fi
fi

# Load existing values if present to preserve API keys
EXISTING_VT=""
EXISTING_ABUSE=""
EXISTING_OTX=""
EXISTING_URLSCAN=""
EXISTING_SHODAN=""
EXISTING_THEHIVE=""
EXISTING_MAIL_USER=""
EXISTING_MAIL_PASS=""

if [ -f "$ENV_FILE" ]; then
    # shellcheck disable=SC1090
    set +e
    EXISTING_VT=$(grep "^VIRUSTOTAL_API_KEY=" "$ENV_FILE" | cut -d '=' -f2- || true)
    EXISTING_ABUSE=$(grep "^ABUSEIPDB_API_KEY=" "$ENV_FILE" | cut -d '=' -f2- || true)
    EXISTING_OTX=$(grep "^OTX_API_KEY=" "$ENV_FILE" | cut -d '=' -f2- || true)
    EXISTING_URLSCAN=$(grep "^URLSCAN_API_KEY=" "$ENV_FILE" | cut -d '=' -f2- || true)
    EXISTING_SHODAN=$(grep "^SHODAN_API_KEY=" "$ENV_FILE" | cut -d '=' -f2- || true)
    EXISTING_THEHIVE=$(grep "^THEHIVE_API_KEY=" "$ENV_FILE" | cut -d '=' -f2- || true)
    EXISTING_MAIL_USER=$(grep "^MAILER_USER=" "$ENV_FILE" | cut -d '=' -f2- || true)
    EXISTING_MAIL_PASS=$(grep "^MAILER_PASSWORD=" "$ENV_FILE" | cut -d '=' -f2- || true)
    set -e
elif [ -f "backend/.env" ]; then
    set +e
    EXISTING_VT=$(grep "^VIRUSTOTAL_API_KEY" "backend/.env" | cut -d '=' -f2- | tr -d ' ' || true)
    EXISTING_ABUSE=$(grep "^ABUSEIPDB_API_KEY" "backend/.env" | cut -d '=' -f2- | tr -d ' ' || true)
    EXISTING_OTX=$(grep "^OTX_API_KEY" "backend/.env" | cut -d '=' -f2- | tr -d ' ' || true)
    EXISTING_URLSCAN=$(grep "^URLSCAN_API_KEY" "backend/.env" | cut -d '=' -f2- | tr -d ' ' || true)
    EXISTING_SHODAN=$(grep "^SHODAN_API_KEY" "backend/.env" | cut -d '=' -f2- | tr -d ' ' || true)
    EXISTING_THEHIVE=$(grep "^THEHIVE_API_KEY" "backend/.env" | cut -d '=' -f2- | tr -d ' ' || true)
    set -e
fi

echo "[*] Generating cryptographically secure random credentials..."

POSTGRES_PASS=$(generate_password)
MINIO_PASS=$(generate_password)
KEYCLOAK_PASS=$(generate_password)
KEYCLOAK_SECRET=$(generate_secret 32)
AUTH_KC_SECRET=$(generate_secret 32)
NEXTAUTH_SECRET=$(generate_secret 32)
WAZUH_INDEXER_PASS=$(generate_password)
WAZUH_API_PASS=$(generate_password)
GRAFANA_PASS=$(generate_password)
N8N_PASS=$(generate_password)
N8N_ENC_KEY=$(generate_secret 32)
INTERNAL_API_KEY=$(generate_secret 24)

cat <<EOF > "$ENV_FILE"
# ==============================================================================
# Security Operations Platform (SOP) — Production Environment Secrets
# Auto-generated: $(date -u +"%Y-%m-%dT%H:%M:%SZ")
# Permissions: 0600 (Restricted to owner)
# ==============================================================================

# Host & Routing
HOST_IP=169.58.221.49
DOMAIN_SUFFIX=169-58-221-49.nip.io
LETSENCRYPT_EMAIL=inshalikram06@gmail.com

# PostgreSQL
POSTGRES_USER=sop_admin
POSTGRES_PASSWORD=${POSTGRES_PASS}
POSTGRES_DB=sop_db
DATABASE_URL=postgresql://sop_admin:${POSTGRES_PASS}@postgres:5432/sop_db

# Redis
REDIS_HOST=redis
REDIS_PORT=6379

# MinIO
MINIO_ROOT_USER=sop_admin
MINIO_ROOT_PASSWORD=${MINIO_PASS}
MINIO_ENDPOINT=minio:9000

# Keycloak
KEYCLOAK_ADMIN=admin
KEYCLOAK_ADMIN_PASSWORD=${KEYCLOAK_PASS}
KC_DB=postgres
KC_DB_URL=jdbc:postgresql://postgres:5432/sop_db
KC_DB_USERNAME=sop_admin
KC_DB_PASSWORD=${POSTGRES_PASS}
KEYCLOAK_URL=http://169.58.221.49:8080
KEYCLOAK_INTERNAL_URL=http://keycloak:8080
KEYCLOAK_REALM=soc-platform
KEYCLOAK_CLIENT_ID=soc-platform-backend
KEYCLOAK_CLIENT_SECRET=${KEYCLOAK_SECRET}

# Frontend NextAuth / Keycloak
AUTH_KEYCLOAK_ID=soc-platform-frontend
AUTH_KEYCLOAK_SECRET=${AUTH_KC_SECRET}
AUTH_KEYCLOAK_ISSUER=http://169.58.221.49:8080/realms/soc-platform
AUTH_KEYCLOAK_INTERNAL_ISSUER=http://keycloak:8080/realms/soc-platform
AUTH_URL=http://169.58.221.49:3000
AUTH_SECRET=${NEXTAUTH_SECRET}
NEXT_PUBLIC_API_URL=https://api.169-58-221-49.nip.io

# Wazuh Indexer & Manager
INDEXER_URL=https://wazuh-indexer:9200
INDEXER_USERNAME=admin
INDEXER_PASSWORD=${WAZUH_INDEXER_PASS}
WAZUH_INDEXER_URL=https://wazuh.indexer:9200
WAZUH_INDEXER_USER=admin
WAZUH_INDEXER_PASSWORD=${WAZUH_INDEXER_PASS}

API_USERNAME=wazuh
API_PASSWORD=${WAZUH_API_PASS}
WAZUH_API_URL=https://wazuh-manager:55000
WAZUH_API_USER=wazuh
WAZUH_API_PASSWORD=${WAZUH_API_PASS}

# Observability
GF_SECURITY_ADMIN_USER=admin
GF_SECURITY_ADMIN_PASSWORD=${GRAFANA_PASS}
OTEL_EXPORTER_OTLP_ENDPOINT=http://tempo:4317
ENABLE_OTEL=true

# n8n Automation
N8N_BASIC_AUTH_ACTIVE=true
N8N_BASIC_AUTH_USER=admin
N8N_BASIC_AUTH_PASSWORD=${N8N_PASS}
N8N_ENCRYPTION_KEY=${N8N_ENC_KEY}

# TheHive & Mailer
THEHIVE_URL=http://thehive:9000
THEHIVE_API_KEY=${EXISTING_THEHIVE:-change_in_thehive_ui}
MAILER_USER=${EXISTING_MAIL_USER:-notifications@example.com}
MAILER_PASSWORD=${EXISTING_MAIL_PASS:-change_smtp_password}
MAILER_FROM=soc-alerts@169-58-221-49.nip.io

# Threat Intelligence APIs
VIRUSTOTAL_API_KEY=${EXISTING_VT}
ABUSEIPDB_API_KEY=${EXISTING_ABUSE}
OTX_API_KEY=${EXISTING_OTX}
URLSCAN_API_KEY=${EXISTING_URLSCAN}
SHODAN_API_KEY=${EXISTING_SHODAN}

# AI Gateway
AI_PROVIDER=ollama
OLLAMA_URL=http://host.docker.internal:11434

# Service-to-Service Internal Auth
API_KEYS=${INTERNAL_API_KEY}
EOF

# Lock down file permissions
chmod 600 "$ENV_FILE"

echo "[+] Successfully generated $ENV_FILE with permissions 0600 (rw-------)."
echo "[*] Validating compose configuration syntax..."
docker compose --env-file "$ENV_FILE" config --quiet
echo "[✓] Docker Compose syntax validated successfully."
echo ""
echo "Next step: Review $ENV_FILE and run:"
echo "  docker compose --env-file .env.production up -d"
