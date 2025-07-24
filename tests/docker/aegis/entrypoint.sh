#!/bin/sh
set -e

# --- Function: Update Keycloak Policy via API ---
# Usage: update_policy "policy-name" '{"roles":[{"id":"ROLE_ID","required":false}]}'

# update_policy() {
#   local policy_name="$1"
#   local updated_roles_json="$2"
#   local policies_url="${KEYCLOAK_URL}/admin/realms/${KEYCLOAK_REALM}/clients/${CLIENT_INTERNAL_ID}/authz/resource-server/policy"

#   # Get all policies and find the ID for the given name
#   local policies=$(curl -s -H "Authorization: Bearer ${ADMIN_TOKEN}" "${policies_url}")
#   local policy_id=$(echo "$policies" | jq -r --arg name "$policy_name" '.[] | select(.name==$name) | .id')
#   if [ -z "$policy_id" ] || [ "$policy_id" = "null" ]; then
#     echo "Policy '$policy_name' not found."
#     return 1
#   fi

#   # Get the current policy JSON
#   local policy_json=$(curl -s -H "Authorization: Bearer ${ADMIN_TOKEN}" "${policies_url}/$policy_id")

#   # First, update roles only
#   local roles_policy_json=$(echo "$policy_json" | jq --argjson roles "$updated_roles_json" '.roles = $roles')
#   local resp_roles=$(curl -s -o /dev/null -w "%{http_code}" -X PUT \
#     -H "Authorization: Bearer ${ADMIN_TOKEN}" \
#     -H "Content-Type: application/json" \
#     -d "$roles_policy_json" \
#     "${policies_url}/role/$policy_id")
#   if [ "$resp_roles" = "201" ] || [ "$resp_roles" = "204" ]; then
#     echo "Policy '$policy_name' roles updated successfully."
#   else
#     echo "Failed to update roles for policy '$policy_name' (HTTP $resp_roles)"
#     return 1
#   fi

#   # Then, update fetchRoles only
#   local fetchroles_policy_json=$(echo "$policy_json" | jq '.fetchRoles = true')
#   local resp_fetchroles=$(curl -s -o /dev/null -w "%{http_code}" -X PUT \
#     -H "Authorization: Bearer ${ADMIN_TOKEN}" \
#     -H "Content-Type: application/json" \
#     -d "$fetchroles_policy_json" \
#     "${policies_url}/$policy_id")
#   if [ "$resp_fetchroles" = "201" ] || [ "$resp_fetchroles" = "204" ]; then
#     echo "Policy '$policy_name' fetchRoles updated successfully."
#   else
#     echo "Failed to update fetchRoles for policy '$policy_name' (HTTP $resp_fetchroles)"
#     return 1
#   fi
# }

# This script waits for Keycloak to be available, then fetches a client secret
# using the admin API and injects it as an environment variable before
# starting the main application.

# --- Configuration (can be overridden by environment variables) ---
KEYCLOAK_URL=${KEYCLOAK_URL:-"http://keycloak:8080"}
KEYCLOAK_REALM=${KEYCLOAK_REALM:-"master"}
KEYCLOAK_ADMIN_USER=${KEYCLOAK_ADMIN_USER:-"admin"}
KEYCLOAK_ADMIN_PASSWORD=${KEYCLOAK_ADMIN_PASSWORD:-"admin"}
# The client ID for which we want to fetch the secret
TARGET_CLIENT_ID=${TARGET_CLIENT_ID:-"admin-cli"}

# --- Wait for Keycloak to be ready ---
echo "Waiting for Keycloak to become available at ${KEYCLOAK_URL}..."
# In a real-world scenario, use a more robust tool like wait-for-it.sh
# For this test environment, we will poll the health endpoint.
until curl -s -f "${HEALTH_CHECK_URL}/ready" > /dev/null; do
  echo "Keycloak is not ready yet. Retrying in 5 seconds..."
  sleep 5
done
echo "Keycloak is up and running."

# --- Fetch Keycloak Admin Token ---
echo "Fetching Keycloak admin token..."
ADMIN_TOKEN=$(curl -s -X POST "${KEYCLOAK_URL}/realms/master/protocol/openid-connect/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=${KEYCLOAK_ADMIN_USER}" \
  -d "password=${KEYCLOAK_ADMIN_PASSWORD}" \
  -d "grant_type=password" \
  -d "client_id=admin-cli" | jq -r ".access_token")

if [ -z "$ADMIN_TOKEN" ] || [ "$ADMIN_TOKEN" = "null" ]; then
  echo "FATAL: Failed to get admin token from Keycloak. Check credentials."
  exit 1
fi
echo "Successfully fetched admin token."

# --- Get the internal ID of the target client ---
echo "Fetching internal ID for client '${TARGET_CLIENT_ID}'..."
CLIENT_INTERNAL_ID=$(curl -s -X GET "${KEYCLOAK_URL}/admin/realms/${KEYCLOAK_REALM}/clients?clientId=${TARGET_CLIENT_ID}" \
  -H "Authorization: Bearer ${ADMIN_TOKEN}" | jq -r ".[0].id")

if [ -z "$CLIENT_INTERNAL_ID" ] || [ "$CLIENT_INTERNAL_ID" = "null" ]; then
  echo "FATAL: Could not find client with ID '${TARGET_CLIENT_ID}' in realm '${KEYCLOAK_REALM}'."
  exit 1
fi

# --- Regenerate the client secret if it is a confidential client ---
echo "Checking if client '${TARGET_CLIENT_ID}' is confidential..."
CLIENT_TYPE=$(curl -s -X POST "${KEYCLOAK_URL}/admin/realms/${KEYCLOAK_REALM}/clients/${CLIENT_INTERNAL_ID}/client-secret" \
  -H "Authorization: Bearer ${ADMIN_TOKEN}" | jq -r ".clientType")

# --- Fetch the Client Secret ---
echo "Fetching secret for client '${TARGET_CLIENT_ID}'..."
OIDC_CLIENT_SECRET=$(curl -s -X GET "${KEYCLOAK_URL}/admin/realms/${KEYCLOAK_REALM}/clients/${CLIENT_INTERNAL_ID}/client-secret" \
  -H "Authorization: Bearer ${ADMIN_TOKEN}" | jq -r ".value")

if [ -z "$OIDC_CLIENT_SECRET" ] || [ "$OIDC_CLIENT_SECRET" = "null" ]; then
  echo "WARNING: Could not fetch client secret. This is expected for public clients."
  export OIDC_CLIENT_SECRET=""
else
  echo "Successfully fetched client secret and exported it as OIDC_CLIENT_SECRET."
  export OIDC_CLIENT_SECRET
fi

# --- Create client roles for the configured client ---
# Format: role:description,role2:description2,...
CLIENT_ROLES="user:Standard user,domain-admin:Domain Administrator (Ultimate Administrator),system-admin:System Administrator (SysOps Member; SecOps Member; DevOps Member)"
if [ -n "$CLIENT_ROLES" ]; then
  echo "Creating client roles for client '${TARGET_CLIENT_ID}': $CLIENT_ROLES"
  echo "$CLIENT_ROLES" | tr ',' '\n' | while IFS= read -r entry; do
    role=$(echo "$entry" | cut -d':' -f1)
    desc=$(echo "$entry" | cut -d':' -f2-)
    role_json="{\"name\": \"$role\", \"description\": \"$desc\"}"
    resp=$(curl -s -o /dev/null -w "%{http_code}" -X POST \
      -H "Content-Type: application/json" \
      -H "Authorization: Bearer ${ADMIN_TOKEN}" \
      -d "$role_json" \
      "${KEYCLOAK_URL}/admin/realms/${KEYCLOAK_REALM}/clients/${CLIENT_INTERNAL_ID}/roles")
    if [ "$resp" = "201" ]; then
      echo "Client role '$role' created."
    elif [ "$resp" = "409" ]; then
      echo "Client role '$role' already exists."
    else
      echo "Failed to create client role '$role' (HTTP $resp)"
    fi
  done
fi

# update_policy "Restricted Access Policy" '[{"id":"domain-admin","required":false},{"id":"system-admin","required":false}]'

# --- Add users from users.txt to the test realm ---
USERS_FILE="/users.txt"
if [ -f "$USERS_FILE" ]; then
  echo "Adding users from $USERS_FILE to realm '${KEYCLOAK_REALM}'..."
  while IFS= read -r line; do
    # Skip empty lines and comments
    case "$line" in
      ''|\#*) continue ;;
    esac
    # Expecting format: username:password[:email][:firstname][:lastname]
    username=""
    password=""
    email=""
    firstname=""
    lastname=""
    IFS=':'
    set -- $line
    username="$1"
    password="$2"
    email="$3"
    firstname="$4"
    lastname="$5"
    IFS=' '
    if [ -z "$username" ] || [ -z "$password" ]; then
      echo "Skipping invalid user line: $line"
      continue
    fi
    # Prepare JSON payload
    user_json="{\"username\": \"$username\", \"enabled\": true, \"credentials\": [{\"type\": \"password\", \"value\": \"$password\", \"temporary\": false}]}"
    if [ -n "$email" ]; then
      user_json=$(echo "$user_json" | jq --arg email "$email" '. + {email: $email}')
    fi
    if [ -n "$firstname" ]; then
      user_json=$(echo "$user_json" | jq --arg fn "$firstname" '. + {firstName: $fn}')
    fi
    if [ -n "$lastname" ]; then
      user_json=$(echo "$user_json" | jq --arg ln "$lastname" '. + {lastName: $ln}')
    fi
    # Create user
    create_resp=$(curl -s -o /dev/null -w "%{http_code}" -X POST \
      -H "Content-Type: application/json" \
      -H "Authorization: Bearer ${ADMIN_TOKEN}" \
      -d "$user_json" \
      "${KEYCLOAK_URL}/admin/realms/${KEYCLOAK_REALM}/users")
    if [ "$create_resp" = "201" ]; then
      echo "User '$username' created."
    else
      echo "Failed to create user '$username' (HTTP $create_resp)"
    fi
  done < "$USERS_FILE"
else
  echo "No users.txt file found, skipping user creation."
fi

# --- Start the Aegis Application ---
echo "Starting aegis proxy..."
# The original command passed to the container will be executed.
# This assumes the aegis binary is the CMD.
exec /aegis
