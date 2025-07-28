set -e

# Config
TOKEN_URL="http://localhost:5000/token"
PROTECTED_URL="http://localhost:8000/protected/dashboard.html"
USERNAME="testuser"
PASSWORD="testpass"

echo "Requesting access token from token service..."
TOKEN_RESPONSE=$(curl -s -X POST "$TOKEN_URL" \
  -H "Content-Type: application/json" \
  -d '{"username": "'$USERNAME'", "password": "'$PASSWORD'"}')

ACCESS_TOKEN=$(echo "$TOKEN_RESPONSE" | grep -o '"access_token":"[^"]*"' | cut -d '"' -f4)

if [ -z "$ACCESS_TOKEN" ]; then
  echo "Failed to obtain access token. Response: $TOKEN_RESPONSE"
  exit 1
fi

echo "Access token: ${ACCESS_TOKEN:0:40}..."

echo "Testing access to protected resource..."
curl -v -H "Proxy-Authorization: Bearer $ACCESS_TOKEN" "$PROTECTED_URL"
#!/bin/bash

