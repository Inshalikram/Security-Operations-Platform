# Operational Runbook: Credential Rotation Guide (`rotate_secrets.md`)

This runbook outlines the step-by-step procedures for rotating all credentials in the AI-Powered Security Operations Platform (SOP). All commands are intended to be executed from the root directory on the Contabo VPS (`/home/ubuntu/SOC` or equivalent).

---

## Table of Contents
1. [General Rotation Principles](#general-rotation-principles)
2. [PostgreSQL Database Password](#1-postgresql-database-password)
3. [Keycloak Admin Password](#2-keycloak-admin-password)
4. [Keycloak Client Secrets (Backend & Frontend)](#3-keycloak-client-secrets-backend--frontend)
5. [MinIO S3 Root Credentials](#4-minio-s3-root-credentials)
6. [Grafana Admin Password](#5-grafana-admin-password)
7. [n8n Automation Credentials](#6-n8n-automation-credentials)
8. [Wazuh Indexer & Manager API Credentials](#7-wazuh-indexer--manager-api-credentials)
9. [TheHive API Key](#8-thehive-api-key)
10. [External Threat Intelligence API Keys (VirusTotal, AbuseIPDB, OTX, URLScan, Shodan)](#9-external-threat-intelligence-api-keys)

---

## General Rotation Principles

- **Zero Git Commits**: Never commit credentials to git. All credentials reside exclusively in `.env.production` (permissions `0600`) on the VPS.
- **Atomic Updates**: When updating dependent services (e.g., changing Postgres password impacts both Backend and Keycloak), plan a 30-second maintenance window or staged migration.
- **Verification**: Always test connectivity using the verification command provided for each service before closing the rotation ticket.

---

## 1. PostgreSQL Database Password

**Services affected**: `sop-postgres`, `sop-backend`, `sop-keycloak`.

### Step-by-Step Procedure:
1. **Generate a new 32-character password**:
   ```bash
   NEW_PG_PASS=$(openssl rand -hex 16)
   echo "New Password: $NEW_PG_PASS"
   ```

2. **Update the password in the live PostgreSQL instance**:
   ```bash
   docker exec -it sop-postgres psql -U sop_admin -d sop_db -c "ALTER USER sop_admin WITH PASSWORD '$NEW_PG_PASS';"
   ```

3. **Update `.env.production`**:
   Update both `POSTGRES_PASSWORD`, `KC_DB_PASSWORD`, and the `DATABASE_URL`:
   ```bash
   sed -i "s/^POSTGRES_PASSWORD=.*/POSTGRES_PASSWORD=$NEW_PG_PASS/" .env.production
   sed -i "s/^KC_DB_PASSWORD=.*/KC_DB_PASSWORD=$NEW_PG_PASS/" .env.production
   sed -i "s|^DATABASE_URL=.*|DATABASE_URL=postgresql://sop_admin:$NEW_PG_PASS@postgres:5432/sop_db|" .env.production
   ```

4. **Restart dependent containers**:
   ```bash
   docker compose --env-file .env.production restart postgres keycloak backend
   ```

5. **Verification**:
   ```bash
   docker exec -it sop-backend python -c "import psycopg2, os; conn = psycopg2.connect(os.getenv('DATABASE_URL')); print('Postgres Connected Successfully!')"
   ```

---

## 2. Keycloak Admin Password

**Services affected**: `sop-keycloak`.

### Option A: Using the Keycloak Admin CLI (Zero Downtime)
1. Generate new password:
   ```bash
   NEW_KC_ADMIN_PASS=$(openssl rand -hex 16)
   ```
2. Log into Keycloak CLI inside the container:
   ```bash
   docker exec -it sop-keycloak /opt/keycloak/bin/kcadm.sh config credentials \
     --server http://localhost:8080 --realm master --user admin --password <CURRENT_PASSWORD>
   ```
3. Update admin password:
   ```bash
   docker exec -it sop-keycloak /opt/keycloak/bin/kcadm.sh set-password \
     -r master --username admin --new-password "$NEW_KC_ADMIN_PASS"
   ```
4. Update `.env.production`:
   ```bash
   sed -i "s/^KEYCLOAK_ADMIN_PASSWORD=.*/KEYCLOAK_ADMIN_PASSWORD=$NEW_KC_ADMIN_PASS/" .env.production
   ```

### Option B: Via Keycloak Admin UI
1. Navigate to: `https://169.58.221.49:8080` (or `http://<HOST_IP>:8080/admin`).
2. Log in with current admin credentials.
3. Switch to Realm: **master** (top-left dropdown).
4. Go to **Users** -> Select `admin` -> Click **Credentials** tab.
5. Click **Reset Password** -> Enter new password -> Toggle **Temporary: OFF** -> Click **Save**.
6. Update `.env.production` with the new password.

---

## 3. Keycloak Client Secrets (Backend & Frontend)

**Services affected**: `sop-backend`, `sop-frontend`.

### Step-by-Step Procedure:
1. Navigate to: `http://169.58.221.49:8080` and log into the Admin Console.
2. Select Realm: **soc-platform**.
3. Go to **Clients** -> Click **soc-platform-backend**.
4. Click the **Credentials** tab.
5. Click **Regenerate Secret**. Copy the new secret.
6. (If frontend is confidential) Go to **Clients** -> Click **soc-platform-frontend** -> **Credentials** -> **Regenerate Secret**.
7. Update `.env.production` (or `frontend/.env.local` / `backend/.env`):
   ```bash
   sed -i "s/^KEYCLOAK_CLIENT_SECRET=.*/KEYCLOAK_CLIENT_SECRET=<NEW_BACKEND_SECRET>/" .env.production
   sed -i "s/^AUTH_KEYCLOAK_SECRET=.*/AUTH_KEYCLOAK_SECRET=<NEW_FRONTEND_SECRET>/" .env.production
   ```
8. Restart backend and frontend:
   ```bash
   docker compose --env-file .env.production restart backend frontend
   ```
9. **Verification**:
   Open `https://app.169-58-221-49.nip.io` in a browser, sign out, and log in to verify token exchange.

---

## 4. MinIO S3 Root Credentials

**Services affected**: `sop-minio`, `sop-backend`.

### Step-by-Step Procedure:
1. Generate new password:
   ```bash
   NEW_MINIO_PASS=$(openssl rand -hex 16)
   ```
2. Update `.env.production`:
   ```bash
   sed -i "s/^MINIO_ROOT_PASSWORD=.*/MINIO_ROOT_PASSWORD=$NEW_MINIO_PASS/" .env.production
   ```
3. Restart MinIO and Backend:
   ```bash
   docker compose --env-file .env.production up -d --force-recreate minio backend
   ```
4. **Verification**:
   ```bash
   docker exec -it sop-backend python -c "
   from storage import minio_client
   print('Buckets:', [b.name for b in minio_client.list_buckets()])
   "
   ```

---

## 5. Grafana Admin Password

**Services affected**: `sop-grafana`.

### Step-by-Step Procedure:
1. Generate new password:
   ```bash
   NEW_GRAFANA_PASS=$(openssl rand -hex 16)
   ```
2. Reset password directly inside container using `grafana-cli`:
   ```bash
   docker exec -it sop-grafana grafana-cli admin reset-admin-password "$NEW_GRAFANA_PASS"
   ```
3. Update `.env.production`:
   ```bash
   sed -i "s/^GF_SECURITY_ADMIN_PASSWORD=.*/GF_SECURITY_ADMIN_PASSWORD=$NEW_GRAFANA_PASS/" .env.production
   ```
4. **Verification**:
   Access `http://169.58.221.49:3002` and log in with username `admin` and the new password.

---

## 6. n8n Automation Credentials

**Services affected**: `sop-n8n`.

### Step-by-Step Procedure:
1. Generate new basic auth password:
   ```bash
   NEW_N8N_PASS=$(openssl rand -hex 16)
   ```
2. Update `.env.production`:
   ```bash
   sed -i "s/^N8N_BASIC_AUTH_PASSWORD=.*/N8N_BASIC_AUTH_PASSWORD=$NEW_N8N_PASS/" .env.production
   ```
3. Restart n8n:
   ```bash
   docker compose --env-file .env.production up -d --force-recreate n8n
   ```
4. **Verification**:
   ```bash
   curl -I -u admin:"$NEW_N8N_PASS" https://n8n.169-58-221-49.nip.io
   ```
   Ensure it returns HTTP `200 OK` (or `302 Redirect` to `/setup` or dashboard).

---

## 7. Wazuh Indexer & Manager API Credentials

**Services affected**: `sop-wazuh-indexer`, `sop-wazuh-manager`, `sop-backend`.

### Indexer Admin Password Rotation:
1. Generate new indexer password (must include uppercase, lowercase, numbers, and special characters):
   ```bash
   NEW_INDEXER_PASS="WazuhIdxSec!$(openssl rand -hex 8)"
   ```
2. Hash the password using Wazuh Indexer tool:
   ```bash
   docker exec -it sop-wazuh-indexer /usr/share/wazuh-indexer/plugins/opensearch-security/tools/hash.sh -p "$NEW_INDEXER_PASS"
   ```
3. Update internal users config inside indexer and run `securityadmin.sh`:
   ```bash
   docker exec -it sop-wazuh-indexer bash -c "
   /usr/share/wazuh-indexer/plugins/opensearch-security/tools/securityadmin.sh \
     -cd /usr/share/wazuh-indexer/opensearch-security/ \
     -cacert /usr/share/wazuh-indexer/certs/root-ca.pem \
     -cert /usr/share/wazuh-indexer/certs/admin.pem \
     -key /usr/share/wazuh-indexer/certs/admin-key.pem \
     -nhnv
   "
   ```
4. Update `.env.production`:
   ```bash
   sed -i "s/^WAZUH_INDEXER_PASSWORD=.*/WAZUH_INDEXER_PASSWORD=$NEW_INDEXER_PASS/" .env.production
   sed -i "s/^INDEXER_PASSWORD=.*/INDEXER_PASSWORD=$NEW_INDEXER_PASS/" .env.production
   ```
5. Restart Wazuh Manager and Backend:
   ```bash
   docker compose --env-file .env.production restart wazuh-manager backend
   ```

### Wazuh Manager API Password Rotation:
1. Generate new API password:
   ```bash
   NEW_API_PASS="WazuhApi!$(openssl rand -hex 8)"
   ```
2. Update inside Wazuh Manager container:
   ```bash
   docker exec -it sop-wazuh-manager /var/ossec/framework/python/bin/python3 \
     /var/ossec/api/scripts/wazuh-passwords.py -u wazuh -p "$NEW_API_PASS"
   ```
3. Update `.env.production`:
   ```bash
   sed -i "s/^WAZUH_API_PASSWORD=.*/WAZUH_API_PASSWORD=$NEW_API_PASS/" .env.production
   sed -i "s/^API_PASSWORD=.*/API_PASSWORD=$NEW_API_PASS/" .env.production
   ```
4. Restart Backend:
   ```bash
   docker compose --env-file .env.production restart backend
   ```
5. **Verification**:
   ```bash
   docker exec -it sop-backend python -c "
   import requests, os
   resp = requests.post(os.getenv('WAZUH_API_URL') + '/security/user/authenticate',
                        auth=(os.getenv('WAZUH_API_USER'), os.getenv('WAZUH_API_PASSWORD')),
                        verify=False)
   print('Wazuh API Status:', resp.status_code)
   "
   ```

---

## 8. TheHive API Key

**Services affected**: `sop-thehive`, `sop-backend`.

### Step-by-Step Procedure:
1. Log into TheHive web console: `http://169.58.221.49:9003` (or via Traefik).
2. Go to **Admin** (top right gear icon) -> **Users**.
3. Select the service user (or `admin`).
4. Click **Create API Key** / **Renew API Key**.
5. Copy the generated key.
6. Update `.env.production`:
   ```bash
   sed -i "s|^THEHIVE_API_KEY=.*|THEHIVE_API_KEY=<NEW_KEY>|" .env.production
   ```
7. Restart backend:
   ```bash
   docker compose --env-file .env.production restart backend
   ```
8. **Verification**:
   ```bash
   docker exec -it sop-backend python -c "
   import requests, os
   headers = {'Authorization': f'Bearer {os.getenv(\"THEHIVE_API_KEY\")}'}
   resp = requests.get(os.getenv('THEHIVE_URL') + '/api/status', headers=headers)
   print('TheHive Status:', resp.status_code, resp.text[:100])
   "
   ```

---

## 9. External Threat Intelligence API Keys

### VirusTotal
1. Visit: [https://www.virustotal.com/gui/user/<username>/apikey](https://www.virustotal.com/gui/user/)
2. Click **Revoke** / **Generate new API key**.
3. Update `.env.production`:
   ```bash
   sed -i "s/^VIRUSTOTAL_API_KEY=.*/VIRUSTOTAL_API_KEY=<NEW_KEY>/" .env.production
   ```
4. Restart backend: `docker compose --env-file .env.production restart backend`
5. Test: `docker exec -it sop-backend python -c "from main import check_ip; print(check_ip('8.8.8.8'))"`

### AbuseIPDB
1. Visit: [https://www.abuseipdb.com/account/api](https://www.abuseipdb.com/account/api)
2. Click **Create Key** -> Copy Key -> Delete old key.
3. Update `.env.production`:
   ```bash
   sed -i "s/^ABUSEIPDB_API_KEY=.*/ABUSEIPDB_API_KEY=<NEW_KEY>/" .env.production
   ```
4. Restart backend: `docker compose --env-file .env.production restart backend`

### AlienVault OTX
1. Visit: [https://otx.alienvault.com/settings](https://otx.alienvault.com/settings)
2. In the **OTX Key** section, click **Generate New Key**.
3. Update `.env.production`:
   ```bash
   sed -i "s/^OTX_API_KEY=.*/OTX_API_KEY=<NEW_KEY>/" .env.production
   ```
4. Restart backend: `docker compose --env-file .env.production restart backend`

### Shodan
1. Visit: [https://account.shodan.io/](https://account.shodan.io/)
2. Click **Account** -> **Regenerate API Key**.
3. Update `.env.production`:
   ```bash
   sed -i "s/^SHODAN_API_KEY=.*/SHODAN_API_KEY=<NEW_KEY>/" .env.production
   ```
4. Restart backend: `docker compose --env-file .env.production restart backend`

### URLScan
1. Visit: [https://urlscan.io/user/profile/](https://urlscan.io/user/profile/)
2. Go to **API Keys** -> Create new key -> Delete old key.
3. Update `.env.production`:
   ```bash
   sed -i "s/^URLSCAN_API_KEY=.*/URLSCAN_API_KEY=<NEW_KEY>/" .env.production
   ```
4. Restart backend: `docker compose --env-file .env.production restart backend`
