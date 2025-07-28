import time
import requests
import os
from flask import Flask, request, jsonify

app = Flask(__name__)

# Keycloak admin/config env vars
KEYCLOAK_URL = os.getenv("KEYCLOAK_URL", "http://keycloak:8080")
KEYCLOAK_REALM = os.getenv("KEYCLOAK_REALM", "test")
KEYCLOAK_ADMIN_USER = os.getenv("KEYCLOAK_ADMIN_USER", "admin")
KEYCLOAK_ADMIN_PASSWORD = os.getenv("KEYCLOAK_ADMIN_PASSWORD", "admin")
OIDC_CLIENT_ID = os.getenv("OIDC_CLIENT_ID", "application")
TARGET_CLIENT_ID = os.getenv("TARGET_CLIENT_ID", OIDC_CLIENT_ID)
HEALTH_CHECK_URL = os.getenv("HEALTH_CHECK_URL", f"{KEYCLOAK_URL}/health")

# Use .env vars for OIDC config
OIDC_DISCOVERY_URL = os.getenv("OIDC_DISCOVERY_URL")
OIDC_CLIENT_ID = os.getenv("OIDC_CLIENT_ID", "application")
OIDC_CLIENT_SECRET = os.getenv("OIDC_CLIENT_SECRET", "")
OIDC_URL = os.getenv("OIDC_URL")  # fallback if discovery not set

def wait_for_keycloak():
    health_url = f"{HEALTH_CHECK_URL}/ready"
    while True:
        try:
            r = requests.get(health_url)
            if r.status_code == 200:
                print("Keycloak is up and running.")
                break
        except Exception:
            pass
        print("Keycloak is not ready yet. Retrying in 5 seconds...")
        time.sleep(5)

def get_admin_token():
    url = f"{KEYCLOAK_URL}/realms/master/protocol/openid-connect/token"
    data = {
        "username": KEYCLOAK_ADMIN_USER,
        "password": KEYCLOAK_ADMIN_PASSWORD,
        "grant_type": "password",
        "client_id": "admin-cli"
    }
    r = requests.post(url, data=data)
    token = r.json().get("access_token")
    if not token:
        raise Exception("Failed to get admin token from Keycloak.")
    return token

def get_client_internal_id(token, client_id):
    url = f"{KEYCLOAK_URL}/admin/realms/{KEYCLOAK_REALM}/clients?clientId={client_id}"
    headers = {"Authorization": f"Bearer {token}"}
    r = requests.get(url, headers=headers)
    result = r.json()
    if not result or not result[0].get("id"):
        raise Exception("Could not find client with ID.")
    return result[0]["id"]

def get_client_secret(token, client_id):
    url = f"{KEYCLOAK_URL}/admin/realms/{KEYCLOAK_REALM}/clients/{client_id}/client-secret"
    headers = {"Authorization": f"Bearer {token}"}
    while True:
        r = requests.get(url, headers=headers)
        if r.status_code != 200:
            print(f"Failed to fetch client secret (HTTP {r.status_code})")
            return None
        secret = r.json().get("value")
        if not secret:
            print("No client secret found.")
            return None
        if '*' in secret:
            print("Client secret is masked (contains '*'), waiting 5 seconds and retrying...")
            time.sleep(5)
            continue
        return secret

def get_token_endpoint():
    if OIDC_DISCOVERY_URL:
        try:
            r = requests.get(OIDC_DISCOVERY_URL)
            if r.status_code == 200:
                return r.json().get("token_endpoint")
        except Exception as e:
            print(f"Failed to fetch OIDC discovery: {e}")
    if OIDC_URL:
        return OIDC_URL
    # fallback default
    return "http://keycloak:8080/realms/test/protocol/openid-connect/token"

@app.route("/token", methods=["POST"])
def get_token():
    data = request.json if request.is_json else request.form
    username = data.get("username")
    password = data.get("password")
    client_id = data.get("client_id", OIDC_CLIENT_ID)
    oidc_url = data.get("oidc_url") or get_token_endpoint()
    if not username or not password:
        return jsonify({"error": "username and password required"}), 400
    # Always fetch the client secret from Keycloak admin API
    try:
        admin_token = get_admin_token()
        internal_id = get_client_internal_id(admin_token, client_id)
        client_secret = get_client_secret(admin_token, internal_id)
    except Exception as e:
        return jsonify({"error": f"Failed to fetch client secret: {e}"}), 500
    payload = {
        "grant_type": "password",
        "client_id": client_id,
        "client_secret": client_secret,
        "username": username,
        "password": password
    }
    resp = requests.post(oidc_url, data=payload)
    if resp.status_code != 200:
        return jsonify({"error": resp.text, "status": resp.status_code}), resp.status_code
    return jsonify(resp.json())

if __name__ == "__main__":
    wait_for_keycloak()
    app.run(host="0.0.0.0", port=5000)
