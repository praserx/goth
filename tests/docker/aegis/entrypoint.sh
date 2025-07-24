#!/bin/sh
set -e

echo "Python version:"
python3 --version

echo "Setting up Keycloak environment for Aegis..."
python3 -u /setup.py

source /.env

echo "Starting aegis proxy..."
exec /aegis
