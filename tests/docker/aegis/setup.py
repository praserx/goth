import os
import time
import requests
import json

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
    r = requests.get(url, headers=headers)
    if r.status_code != 200:
        print(f"Failed to fetch client secret (HTTP {r.status_code})")
        return None
    secret = r.json().get("value")
    if not secret:
        print("No client secret found.")
        return None
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

def create_client_roles(token, client_id, roles):
    url = f"{KEYCLOAK_URL}/admin/realms/{KEYCLOAK_REALM}/clients/{client_id}/roles"
    headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
    for role, desc in roles.items():
        role_json = {"name": role, "description": desc}
        r = requests.post(url, headers=headers, data=json.dumps(role_json))
        if r.status_code == 201:
            print(f"Client role '{role}' created.")
        elif r.status_code == 409:
            print(f"Client role '{role}' already exists.")
        else:
            print(f"Failed to create client role '{role}' (HTTP {r.status_code})")

def update_policy_roles(token, client_id, policy_name, roles):
    # Get all policies
    url = f"{KEYCLOAK_URL}/admin/realms/{KEYCLOAK_REALM}/clients/{client_id}/authz/resource-server/policy"
    headers = {"Authorization": f"Bearer {token}"}
    r = requests.get(url, headers=headers)
    policies = r.json()
    policy_id = next((p["id"] for p in policies if p["name"] == policy_name), None)
    if not policy_id:
        print(f"Policy '{policy_name}' not found.")
        return
    # Get current policy
    policy_url = f"{url}/role/{policy_id}"
    r = requests.get(policy_url, headers=headers)
    policy_json = r.json()
    # Update roles with internal Keycloak role IDs
    # Fetch all client roles to map names to IDs
    url_roles = f"{KEYCLOAK_URL}/admin/realms/{KEYCLOAK_REALM}/clients/{client_id}/roles"
    r_roles = requests.get(url_roles, headers=headers)
    all_roles = r_roles.json()
    role_id_map = {role["name"]: role["id"] for role in all_roles if "id" in role}
    # Replace role names with internal IDs in roles list
    roles_with_ids = []
    for role in roles:
        name = role["id"]
        internal_id = role_id_map.get(name)
        if not internal_id:
            print(f"Role name '{name}' not found in client roles.")
            continue
        roles_with_ids.append({"id": internal_id, "required": role.get("required", False)})
    policy_json["roles"] = roles_with_ids
    print(json.dumps(policy_json))
    r = requests.put(policy_url, headers={**headers, "Content-Type": "application/json"}, data=json.dumps(policy_json))
    if r.status_code in (201, 204):
        print(f"Policy '{policy_name}' roles updated successfully.")
    else:
        print(f"Failed to update roles for policy '{policy_name}' (HTTP {r.status_code})")
    # Update fetchRoles
    policy_json["fetchRoles"] = True
    r = requests.put(policy_url, headers={**headers, "Content-Type": "application/json"}, data=json.dumps(policy_json))
    if r.status_code in (201, 204):
        print(f"Policy '{policy_name}' fetchRoles updated successfully.")
    else:
        print(f"Failed to update fetchRoles for policy '{policy_name}' (HTTP {r.status_code})")

def create_users_from_file(token, file_path):
    """Create users in Keycloak from a users.txt file (username:password per line)."""
    url = f"{KEYCLOAK_URL}/admin/realms/{KEYCLOAK_REALM}/users"
    headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
    try:
        with open(file_path, "r") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                if ":" not in line:
                    print(f"Skipping invalid user line: {line}")
                    continue
                username, password, email, firstname, lastname = line.split(":")
                user_json = {
                    "username": username,
                    "enabled": True,
                    "credentials": [{
                        "type": "password",
                        "value": password,
                        "temporary": False
                    }],
                    "firstName": firstname,
                    "lastName": lastname,
                    "email": email,
                }
                r = requests.post(url, headers=headers, data=json.dumps(user_json))
                if r.status_code == 201:
                    print(f"User '{username}' created.")
                elif r.status_code == 409:
                    print(f"User '{username}' already exists.")
                else:
                    print(f"Failed to create user '{username}' (HTTP {r.status_code})")
                # Assign client roles to jdoe after creation
                if username == "jdoe":
                    assign_client_roles_to_user(token, username, ["domain-admin", "system-admin"])
    except Exception as e:
        print(f"Error creating users from {file_path}: {e}")

def assign_client_roles_to_user(token, username, roles):
    """Assign specified client roles to a user in Keycloak."""
    # Get user ID
    url_users = f"{KEYCLOAK_URL}/admin/realms/{KEYCLOAK_REALM}/users?username={username}"
    headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
    r = requests.get(url_users, headers=headers)
    users = r.json()
    if not users:
        print(f"User '{username}' not found for role assignment.")
        return
    user_id = users[0]["id"]
    # Get client ID
    url_clients = f"{KEYCLOAK_URL}/admin/realms/{KEYCLOAK_REALM}/clients?clientId={TARGET_CLIENT_ID}"
    r = requests.get(url_clients, headers=headers)
    clients = r.json()
    if not clients:
        print(f"Client '{TARGET_CLIENT_ID}' not found for role assignment.")
        return
    client_id = clients[0]["id"]
    # Get available client roles
    url_roles = f"{KEYCLOAK_URL}/admin/realms/{KEYCLOAK_REALM}/clients/{client_id}/roles"
    r = requests.get(url_roles, headers=headers)
    all_roles = r.json()
    role_objs = [role for role in all_roles if role["name"] in roles]
    if not role_objs:
        print(f"No matching roles found for assignment to '{username}'.")
        return
    # Assign roles
    url_assign = f"{KEYCLOAK_URL}/admin/realms/{KEYCLOAK_REALM}/users/{user_id}/role-mappings/clients/{client_id}"
    r = requests.post(url_assign, headers=headers, data=json.dumps(role_objs))
    if r.status_code in (204, 201):
        print(f"Assigned roles {roles} to user '{username}'.")
    else:
        print(f"Failed to assign roles {roles} to user '{username}' (HTTP {r.status_code})")

if __name__ == "__main__":
    print("Starting Keycloak setup for Aegis...")
    wait_for_keycloak()
    token = get_admin_token()
    client_id = get_client_internal_id(token)
    client_secret = get_client_secret(token, client_id)
    roles = {
        "user": "Standard user",
        "domain-admin": "Domain Administrator (Ultimate Administrator)",
        "system-admin": "System Administrator (SysOps Member; SecOps Member; DevOps Member)"
    }
    create_client_roles(token, client_id, roles)
    # Example: update policy with role IDs (replace with actual IDs)
    update_policy_roles(token, client_id, "Restricted Access Policy", [
        {"id": "domain-admin", "required": False},
        {"id": "system-admin", "required": False}
    ])

    # Create users from users.txt
    users_file = os.path.join(os.path.dirname(__file__), "users.txt")
    create_users_from_file(token, users_file)

    # Write OIDC_CLIENT_SECRET to .env file for entrypoint.sh
    env_path = os.path.join(os.path.dirname(__file__), ".env")
    with open(env_path, "w") as env_file:
        env_file.write(f"OIDC_CLIENT_SECRET={client_secret}\n")
    print(f"OIDC_CLIENT_SECRET written to {env_path}")

    print("Keycloak setup completed successfully.")