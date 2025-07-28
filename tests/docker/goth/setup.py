import os
import time
import requests

KEYCLOAK_URL = os.getenv("KEYCLOAK_URL", "http://keycloak:8080")
KEYCLOAK_REALM = os.getenv("KEYCLOAK_REALM", "master")
KEYCLOAK_ADMIN_USER = os.getenv("KEYCLOAK_ADMIN_USER", "admin")
KEYCLOAK_ADMIN_PASSWORD = os.getenv("KEYCLOAK_ADMIN_PASSWORD", "admin")
TARGET_CLIENT_ID = os.getenv("TARGET_CLIENT_ID", "admin-cli")
HEALTH_CHECK_URL = os.getenv("HEALTH_CHECK_URL", KEYCLOAK_URL+"/health")

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
        print(f"OIDC_CLIENT_SECRET={secret}")
        return secret

def get_client_internal_id(token):
    url = f"{KEYCLOAK_URL}/admin/realms/{KEYCLOAK_REALM}/clients?clientId={TARGET_CLIENT_ID}"
    headers = {"Authorization": f"Bearer {token}"}
    r = requests.get(url, headers=headers)
    result = r.json()
    if not result or not result[0].get("id"):
        raise Exception("Could not find client with ID.")
    return result[0]["id"]

if __name__ == "__main__":
    wait_for_keycloak()
    token = get_admin_token()
    client_id = get_client_internal_id(token)
    client_secret = get_client_secret(token, client_id)

    env_path = os.path.join(os.path.dirname(__file__), ".env")
    with open(env_path, "w") as env_file:
        env_file.write(f"OIDC_CLIENT_SECRET={client_secret}\n")
    print(f"OIDC_CLIENT_SECRET written to {env_path}")
