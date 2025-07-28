#!/bin/sh
set -e

echo "Starting Goth final setup..."
python3 -u /setup.py
source /.env
echo "Starting Goth proxy..."
exec /goth
