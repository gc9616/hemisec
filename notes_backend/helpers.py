import numpy as np
import base64
import sqlite3
import os
import secrets
import jwt
from datetime import datetime, timedelta
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from functools import wraps
from flask import request, jsonify
import cv2
from pathlib import Path
import io
import tempfile

# Configuration
DATABASE_PATH = os.path.join(os.path.dirname(__file__), 'notes_app.db')
SECRET_KEY = os.environ.get('JWT_SECRET_KEY', secrets.token_hex(32))  # Use env var in production
BIOMETRIC_THRESHOLD = 0.85  # Cosine similarity threshold for biometric match
TOKEN_EXPIRY_HOURS = 24

# Password hasher with secure defaults
ph = PasswordHasher(
    time_cost=3,        # Number of iterations
    memory_cost=65536,  # 64 MB
    parallelism=4,      # Number of parallel threads
    hash_len=32,        # Length of hash in bytes
    salt_len=16         # Length of salt in bytes
)

def init_database():
    """Initialize SQLite database with required tables"""
    conn = sqlite3.connect(DATABASE_PATH)
    cursor = conn.cursor()
    
    # Users table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            last_login TIMESTAMP
        )
    ''')
    
    # Biometric templates table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS biometric_templates (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER UNIQUE NOT NULL,
            template_vector BLOB NOT NULL,
            enrolled_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        )
    ''')
    
    # Notes table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS notes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            title TEXT NOT NULL,
            content TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        )
    ''')
    
    # Create indexes for performance
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_notes_user_id ON notes(user_id)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_biometric_user_id ON biometric_templates(user_id)')
    
    conn.commit()
    conn.close()


def get_db_connection():
    """Get a database connection with row factory"""
    conn = sqlite3.connect(DATABASE_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def hash_password(password):
    """Hash password using Argon2"""
    return ph.hash(password)


def verify_password(password_hash, password):
    """Verify password against Argon2 hash"""
    try:
        ph.verify(password_hash, password)
        # Check if rehashing is needed (e.g., parameters changed)
        if ph.check_needs_rehash(password_hash):
            return True, hash_password(password)  # Return new hash for update
        return True, None
    except VerifyMismatchError:
        return False, None


def decode_biometric_vector(base64_vector):
    """Decode base64 encoded biometric vector to numpy array"""
    try:
        vector_bytes = base64.b64decode(base64_vector)
        vector = np.frombuffer(vector_bytes, dtype=np.float32)
        return vector
    except Exception as e:
        raise ValueError(f"Invalid biometric vector format: {str(e)}")


def encode_biometric_vector(vector):
    """Encode numpy array to base64 string"""
    return base64.b64encode(vector.tobytes()).decode('utf-8')


def get_similarity(vector1, vector2):
    """
    Calculate cosine similarity between two biometric vectors
    Returns a score between -1 and 1, where 1 is identical
    """
    if vector1.shape != vector2.shape:
        raise ValueError("Vectors must have the same dimensions")
    
    # Normalize vectors
    norm1 = np.linalg.norm(vector1)
    norm2 = np.linalg.norm(vector2)
    
    if norm1 == 0 or norm2 == 0:
        return 0.0
    
    # Cosine similarity
    similarity = np.dot(vector1, vector2) / (norm1 * norm2)
    return float(similarity)


def generate_token(user_id, username):
    """Generate JWT access token"""
    payload = {
        'user_id': user_id,
        'username': username,
        'exp': datetime.utcnow() + timedelta(hours=TOKEN_EXPIRY_HOURS),
        'iat': datetime.utcnow()
    }
    token = jwt.encode(payload, SECRET_KEY, algorithm='HS256')
    return token


def decode_token(token):
    """Decode and validate JWT token"""
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
        return payload
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None


def token_required(f):
    """Decorator to protect endpoints with JWT authentication"""
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        
        # Get token from Authorization header
        if 'Authorization' in request.headers:
            auth_header = request.headers['Authorization']
            try:
                token = auth_header.split(' ')[1]  # Format: "Bearer <token>"
            except IndexError:
                return jsonify({'error': 'Invalid authorization header format'}), 401
        
        if not token:
            return jsonify({'error': 'Authentication token is missing'}), 401
        
        # Decode token
        payload = decode_token(token)
        if not payload:
            return jsonify({'error': 'Invalid or expired token'}), 401
        
        # Pass user info to the endpoint
        return f(current_user_id=payload['user_id'], 
                current_username=payload['username'], 
                *args, **kwargs)
    
    return decorated


def validate_input(data, required_fields):
    """Validate that required fields are present in request data"""
    missing_fields = [field for field in required_fields if field not in data]
    if missing_fields:
        return False, f"Missing required fields: {', '.join(missing_fields)}"
    
    # Check for empty values
    empty_fields = [field for field in required_fields if not data.get(field)]
    if empty_fields:
        return False, f"Empty values not allowed for: {', '.join(empty_fields)}"
    
    return True, None


def sanitize_input(text, max_length=10000):
    """Basic input sanitization"""
    if not isinstance(text, str):
        return str(text)
    
    # Trim whitespace
    text = text.strip()
    
    # Limit length
    if len(text) > max_length:
        text = text[:max_length]
    
    return text


def compute_biometric_vector_from_image(image_b64: str) -> np.ndarray:
    """
    Compute biometric feature vector from base64 encoded image.
    
    This function:
    1. Decodes the base64 image
    2. Reads it as grayscale
    3. Creates hand segmentation mask
    4. Extracts OEG feature vector using the same parameters as the CLI
    
    Args:
        image_b64: Base64 encoded image string
    
    Returns:
        Feature vector as numpy array (float32)
    
    Raises:
        ValueError: If image decoding fails or feature extraction fails
    """
    try:
        # Decode base64 image
        image_bytes = base64.b64decode(image_b64)
        
        # Load image from bytes
        nparr = np.frombuffer(image_bytes, np.uint8)
        img = cv2.imdecode(nparr, cv2.IMREAD_GRAYSCALE)
        
        if img is None:
            raise ValueError("Could not decode image from base64")
        
        # Import feature extraction functions from feature_map
        # We need to add the feature_extraction module to sys.path
        import sys
        feature_extraction_path = os.path.join(
            os.path.dirname(os.path.dirname(__file__)), 
            'feature_extraction'
        )
        if feature_extraction_path not in sys.path:
            sys.path.insert(0, feature_extraction_path)
        
        from feature_map import (
            create_hand_segmentation_mask,
            extract_oeg_feature_vector
        )
        
        # Create hand segmentation mask using same parameters as CLI
        hand_mask, safe_mask = create_hand_segmentation_mask(
            img,
            method="hybrid",
            preprocess=True,
            otsu_bias=0.85,
            canny_low=30,
            canny_high=100,
            exclude_fingers_flag=True,
            finger_width=60,
        )
        
        # Extract OEG feature vector
        vec = extract_oeg_feature_vector(
            img,
            safe_mask,
            roi_size=256,
            roi_margin=10,
            ntheta=8,
            grid=16,
            ksize=31,
            sig=5.0,
            lambd=10.0,
            gamma=0.5,
        )
        
        return vec
        
    except Exception as e:
        raise ValueError(f"Failed to compute biometric vector from image: {str(e)}")