"""
Flask Backend for Biometric Authentication Notes App

This application provides a secure REST API for a notes application with
two-factor authentication (password + biometrics).

Security features:
- Argon2 password hashing with secure parameters
- JWT token-based authentication
- Biometric verification using cosine similarity
- Input validation and sanitization
- SQLite database with proper foreign key constraints
"""

import os
from flask import Flask, jsonify
from flask_cors import CORS
import helpers
from endpoints import api

# Initialize Flask app
app = Flask(__name__)

# Enable CORS for Swift app integration
CORS(app, resources={
    r"/api/*": {
        "origins": "*",  # Configure specific origins in production
        "methods": ["GET", "POST", "PUT", "DELETE"],
        "allow_headers": ["Content-Type", "Authorization"]
    }
})

# Register API blueprint
app.register_blueprint(api, url_prefix='/api')

# Initialize database on startup
with app.app_context():
    helpers.init_database()


@app.route('/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    return jsonify({
        'status': 'healthy',
        'service': 'biometric-notes-api',
        'version': '1.0.0'
    }), 200


@app.route('/', methods=['GET'])
def root():
    """Root endpoint with API documentation"""
    return jsonify({
        'message': 'Biometric Authentication Notes API',
        'version': '1.0.0',
        'endpoints': {
            'authentication': {
                'POST /api/auth/signup': 'Register new user with biometric enrollment',
                'POST /api/auth/login': 'Authenticate with password + biometric',
                'GET /api/auth/verify': 'Verify JWT token validity',
                'PUT /api/biometric/update': 'Update biometric template'
            },
            'notes': {
                'GET /api/notes': 'Get all notes for authenticated user',
                'GET /api/notes/<id>': 'Get specific note by ID',
                'POST /api/notes': 'Create new note',
                'PUT /api/notes/<id>': 'Update existing note',
                'DELETE /api/notes/<id>': 'Delete note'
            },
            'health': {
                'GET /health': 'API health check'
            }
        },
        'authentication': 'Bearer token required in Authorization header for protected endpoints'
    }), 200


@app.errorhandler(404)
def not_found(error):
    """Handle 404 errors"""
    return jsonify({'error': 'Endpoint not found'}), 404


@app.errorhandler(405)
def method_not_allowed(error):
    """Handle 405 errors"""
    return jsonify({'error': 'Method not allowed'}), 405


@app.errorhandler(500)
def internal_error(error):
    """Handle 500 errors"""
    return jsonify({'error': 'Internal server error'}), 500


if __name__ == '__main__':
    # Set JWT secret key from environment variable (generate if not set)
    if 'JWT_SECRET_KEY' not in os.environ:
        print("WARNING: JWT_SECRET_KEY not set. Using generated key (not suitable for production)")
        print("Set JWT_SECRET_KEY environment variable before deploying to production")
    
    # Run the application
    # In production, use a proper WSGI server like gunicorn
    app.run(
        host='0.0.0.0',  # Listen on all interfaces
        port=8080,
        debug=False  # Set to False in production
    )
