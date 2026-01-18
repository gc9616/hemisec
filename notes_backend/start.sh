#!/bin/bash

# Start script for Biometric Notes API

echo "=========================================="
echo "Biometric Authentication Notes API"
echo "=========================================="
echo ""

# Check if virtual environment exists
if [ ! -d "venv" ]; then
    echo "Creating virtual environment..."
    python3 -m venv venv
fi

# Activate virtual environment
echo "Activating virtual environment..."
source venv/bin/activate

# Install dependencies
echo "Installing dependencies..."
pip install -r requirements.txt

# Check if .env exists
if [ ! -f ".env" ]; then
    echo ""
    echo "⚠️  WARNING: .env file not found"
    echo "Creating .env from .env.example..."
    cp .env.example .env
    echo "Please edit .env and set JWT_SECRET_KEY before deploying to production"
    echo ""
fi

# Generate JWT secret if not set
if ! grep -q "JWT_SECRET_KEY=your-secret-key-here" .env 2>/dev/null; then
    echo "JWT_SECRET_KEY is configured in .env"
else
    echo "⚠️  Generating temporary JWT_SECRET_KEY..."
    SECRET=$(python3 -c "import secrets; print(secrets.token_hex(32))")
    export JWT_SECRET_KEY=$SECRET
    echo "✓ Temporary secret generated (not suitable for production)"
fi

echo ""
echo "=========================================="
echo "Starting Flask server on port 8080..."
echo "=========================================="
echo ""
echo "API endpoints will be available at:"
echo "  http://localhost:8080/api"
echo ""
echo "Press Ctrl+C to stop the server"
echo ""

# Run the Flask app
python main.py
