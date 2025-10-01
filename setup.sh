#!/bin/bash
set -e

echo "🚀 Starting Sapient Kubernetes Security Auditor (Docker Runtime)..."
echo "-------------------------------------------------"

# Ensure .env exists in the current directory
if [ ! -f .env ]; then
    echo "📝 No .env file found, creating a default one..."
    # This file is created by 'appuser' inside the container, or by the current user locally.
    cat > .env <<EOL
# OpenAI configuration
OPENAI_API_KEY=""
OPENAI_MODEL="gpt-4o-mini"

# Flask settings
FLASK_DEBUG=0
FLASK_RUN_PORT=5000
FLASK_RUN_HOST=0.0.0.0
EOL
    # Set secure permissions: Owner can read/write, everyone else can only read.
    chmod 644 .env
    echo "✅ Created default .env (writable by the application)."
else
    echo "ℹ️ Using existing .env file."
fi

# Load all variables from the local .env into the environment
set -o allexport
source .env
set +o allexport

echo "-------------------------------------------------"
echo "🔎 Flask is configured to run on port ${FLASK_RUN_PORT}"
echo "🔗 Access the application at: http://localhost:${FLASK_RUN_PORT}"
echo "-------------------------------------------------"

# Launch the Flask application
# The host and port are now correctly read from the .env file
export FLASK_APP=sapient.py
flask run --host=${FLASK_RUN_HOST} --port=${FLASK_RUN_PORT}

