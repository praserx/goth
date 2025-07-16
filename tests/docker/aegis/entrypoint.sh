#!/bin/sh
set -e

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

# --- Start the Aegis Application ---
echo "Starting aegis proxy..."
# The original command passed to the container will be executed.
# This assumes the aegis binary is the CMD.
exec /aegis
