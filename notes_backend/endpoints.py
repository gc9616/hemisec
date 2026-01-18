"""
Authentication and Notes API Endpoints
Implements secure user authentication with biometric verification and CRUD operations for notes
"""

from flask import Blueprint, request, jsonify
from datetime import datetime
import helpers

# Create blueprint for API endpoints
api = Blueprint('api', __name__)


@api.route('/auth/signup', methods=['POST'])
def signup():
    """
    Register a new user with password and biometric template
    
    Expected JSON:
    {
        "username": str (3-50 chars, alphanumeric + underscore),
        "password": str (min 8 chars),
        "biometric_vector": str (base64 encoded numpy array)
    }
    
    Returns:
    - 201: User created successfully
    - 400: Invalid input
    - 409: Username already exists
    """
    try:
        data = request.get_json()
        
        # Validate required fields
        valid, error = helpers.validate_input(data, ['username', 'password', 'biometric_vector'])
        if not valid:
            return jsonify({'error': error}), 400
        
        username = helpers.sanitize_input(data['username'], max_length=50)
        password = data['password']
        biometric_vector_b64 = data['biometric_vector']
        
        # Validate username format
        if not username.replace('_', '').isalnum() or len(username) < 3:
            return jsonify({'error': 'Username must be 3-50 alphanumeric characters (underscore allowed)'}), 400
        
        # Validate password strength
        if len(password) < 8:
            return jsonify({'error': 'Password must be at least 8 characters long'}), 400
        
        # Decode and validate biometric vector
        try:
            biometric_vector = helpers.decode_biometric_vector(biometric_vector_b64)
        except ValueError as e:
            return jsonify({'error': str(e)}), 400
        
        # Hash password
        password_hash = helpers.hash_password(password)
        
        # Insert user into database
        conn = helpers.get_db_connection()
        cursor = conn.cursor()
        
        try:
            # Insert user
            cursor.execute(
                'INSERT INTO users (username, password_hash) VALUES (?, ?)',
                (username, password_hash)
            )
            user_id = cursor.lastrowid
            
            # Store biometric template
            cursor.execute(
                'INSERT INTO biometric_templates (user_id, template_vector) VALUES (?, ?)',
                (user_id, biometric_vector.tobytes())
            )
            
            conn.commit()
            
            return jsonify({
                'message': 'User registered successfully',
                'user_id': user_id,
                'username': username
            }), 201
            
        except conn.IntegrityError:
            conn.rollback()
            return jsonify({'error': 'Username already exists'}), 409
        finally:
            conn.close()
            
    except Exception as e:
        return jsonify({'error': f'Server error: {str(e)}'}), 500


@api.route('/auth/login', methods=['POST'])
def login():
    """
    Authenticate user with password and biometric verification
    
    Expected JSON:
    {
        "username": str,
        "password": str,
        "biometric_vector": str (base64 encoded numpy array)
    }
    
    Returns:
    - 200: Authentication successful with access token
    - 401: Invalid credentials or biometric mismatch
    - 400: Invalid input
    """
    try:
        data = request.get_json()
        
        # Validate required fields
        valid, error = helpers.validate_input(data, ['username', 'password', 'biometric_vector'])
        if not valid:
            return jsonify({'error': error}), 400
        
        username = helpers.sanitize_input(data['username'])
        password = data['password']
        biometric_vector_b64 = data['biometric_vector']
        
        # Decode biometric vector
        try:
            provided_vector = helpers.decode_biometric_vector(biometric_vector_b64)
        except ValueError as e:
            return jsonify({'error': str(e)}), 400
        
        # Retrieve user from database
        conn = helpers.get_db_connection()
        cursor = conn.cursor()
        
        cursor.execute('SELECT id, username, password_hash FROM users WHERE username = ?', (username,))
        user = cursor.fetchone()
        
        if not user:
            conn.close()
            return jsonify({'error': 'Invalid credentials'}), 401
        
        user_id = user['id']
        password_hash = user['password_hash']
        
        # Verify password
        password_valid, new_hash = helpers.verify_password(password_hash, password)
        if not password_valid:
            conn.close()
            return jsonify({'error': 'Invalid credentials'}), 401
        
        # Update password hash if rehashing is needed
        if new_hash:
            cursor.execute('UPDATE users SET password_hash = ? WHERE id = ?', (new_hash, user_id))
            conn.commit()
        
        # Retrieve stored biometric template
        cursor.execute('SELECT template_vector FROM biometric_templates WHERE user_id = ?', (user_id,))
        template_row = cursor.fetchone()
        
        if not template_row:
            conn.close()
            return jsonify({'error': 'Biometric template not found. Please re-enroll.'}), 401
        
        # Convert stored template from bytes to numpy array
        import numpy as np
        stored_vector = np.frombuffer(template_row['template_vector'], dtype=np.float32)
        
        # Calculate similarity
        similarity = helpers.get_similarity(stored_vector, provided_vector)
        
        if similarity < helpers.BIOMETRIC_THRESHOLD:
            conn.close()
            return jsonify({
                'error': 'Biometric verification failed',
                'similarity': round(similarity, 3)
            }), 401
        
        # Update last login
        cursor.execute(
            'UPDATE users SET last_login = ? WHERE id = ?',
            (datetime.utcnow().isoformat(), user_id)
        )
        conn.commit()
        conn.close()
        
        # Generate access token
        access_token = helpers.generate_token(user_id, username)
        
        return jsonify({
            'message': 'Authentication successful',
            'access_token': access_token,
            'similarity': round(similarity, 3),
            'username': username
        }), 200
        
    except Exception as e:
        return jsonify({'error': f'Server error: {str(e)}'}), 500


@api.route('/auth/verify', methods=['GET'])
@helpers.token_required
def verify_token(current_user_id, current_username):
    """
    Verify if the provided token is valid
    
    Headers:
        Authorization: Bearer <token>
    
    Returns:
    - 200: Token is valid
    - 401: Invalid or expired token
    """
    return jsonify({
        'valid': True,
        'user_id': current_user_id,
        'username': current_username
    }), 200


@api.route('/notes', methods=['GET'])
@helpers.token_required
def get_notes(current_user_id, current_username):
    """
    Retrieve all notes for the authenticated user
    
    Headers:
        Authorization: Bearer <token>
    
    Returns:
    - 200: List of notes
    """
    try:
        conn = helpers.get_db_connection()
        cursor = conn.cursor()
        
        cursor.execute(
            '''SELECT id, title, content, created_at, updated_at 
               FROM notes 
               WHERE user_id = ? 
               ORDER BY updated_at DESC''',
            (current_user_id,)
        )
        
        notes = []
        for row in cursor.fetchall():
            notes.append({
                'id': row['id'],
                'title': row['title'],
                'content': row['content'],
                'created_at': row['created_at'],
                'updated_at': row['updated_at']
            })
        
        conn.close()
        
        return jsonify({'notes': notes}), 200
        
    except Exception as e:
        return jsonify({'error': f'Server error: {str(e)}'}), 500


@api.route('/notes/<int:note_id>', methods=['GET'])
@helpers.token_required
def get_note(current_user_id, current_username, note_id):
    """
    Retrieve a specific note by ID
    
    Headers:
        Authorization: Bearer <token>
    
    Returns:
    - 200: Note details
    - 404: Note not found
    - 403: Unauthorized access
    """
    try:
        conn = helpers.get_db_connection()
        cursor = conn.cursor()
        
        cursor.execute(
            'SELECT id, user_id, title, content, created_at, updated_at FROM notes WHERE id = ?',
            (note_id,)
        )
        
        note = cursor.fetchone()
        conn.close()
        
        if not note:
            return jsonify({'error': 'Note not found'}), 404
        
        # Verify ownership
        if note['user_id'] != current_user_id:
            return jsonify({'error': 'Unauthorized access to this note'}), 403
        
        return jsonify({
            'id': note['id'],
            'title': note['title'],
            'content': note['content'],
            'created_at': note['created_at'],
            'updated_at': note['updated_at']
        }), 200
        
    except Exception as e:
        return jsonify({'error': f'Server error: {str(e)}'}), 500


@api.route('/notes', methods=['POST'])
@helpers.token_required
def create_note(current_user_id, current_username):
    """
    Create a new note
    
    Headers:
        Authorization: Bearer <token>
    
    Expected JSON:
    {
        "title": str,
        "content": str
    }
    
    Returns:
    - 201: Note created successfully
    - 400: Invalid input
    """
    try:
        data = request.get_json()
        
        # Validate required fields
        valid, error = helpers.validate_input(data, ['title', 'content'])
        if not valid:
            return jsonify({'error': error}), 400
        
        title = helpers.sanitize_input(data['title'], max_length=200)
        content = helpers.sanitize_input(data['content'], max_length=50000)
        
        # Insert note into database
        conn = helpers.get_db_connection()
        cursor = conn.cursor()
        
        cursor.execute(
            'INSERT INTO notes (user_id, title, content) VALUES (?, ?, ?)',
            (current_user_id, title, content)
        )
        
        note_id = cursor.lastrowid
        conn.commit()
        
        # Retrieve the created note
        cursor.execute(
            'SELECT id, title, content, created_at, updated_at FROM notes WHERE id = ?',
            (note_id,)
        )
        note = cursor.fetchone()
        conn.close()
        
        return jsonify({
            'message': 'Note created successfully',
            'note': {
                'id': note['id'],
                'title': note['title'],
                'content': note['content'],
                'created_at': note['created_at'],
                'updated_at': note['updated_at']
            }
        }), 201
        
    except Exception as e:
        return jsonify({'error': f'Server error: {str(e)}'}), 500


@api.route('/notes/<int:note_id>', methods=['PUT'])
@helpers.token_required
def update_note(current_user_id, current_username, note_id):
    """
    Update an existing note
    
    Headers:
        Authorization: Bearer <token>
    
    Expected JSON:
    {
        "title": str (optional),
        "content": str (optional)
    }
    
    Returns:
    - 200: Note updated successfully
    - 400: Invalid input
    - 403: Unauthorized access
    - 404: Note not found
    """
    try:
        data = request.get_json()
        
        if not data or ('title' not in data and 'content' not in data):
            return jsonify({'error': 'At least one field (title or content) must be provided'}), 400
        
        conn = helpers.get_db_connection()
        cursor = conn.cursor()
        
        # Verify note exists and user owns it
        cursor.execute('SELECT user_id FROM notes WHERE id = ?', (note_id,))
        note = cursor.fetchone()
        
        if not note:
            conn.close()
            return jsonify({'error': 'Note not found'}), 404
        
        if note['user_id'] != current_user_id:
            conn.close()
            return jsonify({'error': 'Unauthorized access to this note'}), 403
        
        # Build update query dynamically
        update_fields = []
        params = []
        
        if 'title' in data:
            update_fields.append('title = ?')
            params.append(helpers.sanitize_input(data['title'], max_length=200))
        
        if 'content' in data:
            update_fields.append('content = ?')
            params.append(helpers.sanitize_input(data['content'], max_length=50000))
        
        # Always update the updated_at timestamp
        update_fields.append('updated_at = ?')
        params.append(datetime.utcnow().isoformat())
        
        params.append(note_id)
        
        # Execute update
        cursor.execute(
            f'UPDATE notes SET {", ".join(update_fields)} WHERE id = ?',
            params
        )
        conn.commit()
        
        # Retrieve updated note
        cursor.execute(
            'SELECT id, title, content, created_at, updated_at FROM notes WHERE id = ?',
            (note_id,)
        )
        updated_note = cursor.fetchone()
        conn.close()
        
        return jsonify({
            'message': 'Note updated successfully',
            'note': {
                'id': updated_note['id'],
                'title': updated_note['title'],
                'content': updated_note['content'],
                'created_at': updated_note['created_at'],
                'updated_at': updated_note['updated_at']
            }
        }), 200
        
    except Exception as e:
        return jsonify({'error': f'Server error: {str(e)}'}), 500


@api.route('/notes/<int:note_id>', methods=['DELETE'])
@helpers.token_required
def delete_note(current_user_id, current_username, note_id):
    """
    Delete a note
    
    Headers:
        Authorization: Bearer <token>
    
    Returns:
    - 200: Note deleted successfully
    - 403: Unauthorized access
    - 404: Note not found
    """
    try:
        conn = helpers.get_db_connection()
        cursor = conn.cursor()
        
        # Verify note exists and user owns it
        cursor.execute('SELECT user_id FROM notes WHERE id = ?', (note_id,))
        note = cursor.fetchone()
        
        if not note:
            conn.close()
            return jsonify({'error': 'Note not found'}), 404
        
        if note['user_id'] != current_user_id:
            conn.close()
            return jsonify({'error': 'Unauthorized access to this note'}), 403
        
        # Delete the note
        cursor.execute('DELETE FROM notes WHERE id = ?', (note_id,))
        conn.commit()
        conn.close()
        
        return jsonify({'message': 'Note deleted successfully'}), 200
        
    except Exception as e:
        return jsonify({'error': f'Server error: {str(e)}'}), 500


@api.route('/biometric/update', methods=['PUT'])
@helpers.token_required
def update_biometric(current_user_id, current_username):
    """
    Update biometric template for the authenticated user
    
    Headers:
        Authorization: Bearer <token>
    
    Expected JSON:
    {
        "biometric_vector": str (base64 encoded numpy array),
        "password": str (for verification)
    }
    
    Returns:
    - 200: Biometric template updated successfully
    - 401: Invalid password
    - 400: Invalid input
    """
    try:
        data = request.get_json()
        
        # Validate required fields
        valid, error = helpers.validate_input(data, ['biometric_vector', 'password'])
        if not valid:
            return jsonify({'error': error}), 400
        
        biometric_vector_b64 = data['biometric_vector']
        password = data['password']
        
        # Decode biometric vector
        try:
            biometric_vector = helpers.decode_biometric_vector(biometric_vector_b64)
        except ValueError as e:
            return jsonify({'error': str(e)}), 400
        
        # Verify password before allowing update
        conn = helpers.get_db_connection()
        cursor = conn.cursor()
        
        cursor.execute('SELECT password_hash FROM users WHERE id = ?', (current_user_id,))
        user = cursor.fetchone()
        
        password_valid, _ = helpers.verify_password(user['password_hash'], password)
        if not password_valid:
            conn.close()
            return jsonify({'error': 'Invalid password'}), 401
        
        # Update or insert biometric template
        cursor.execute(
            '''INSERT INTO biometric_templates (user_id, template_vector, enrolled_at) 
               VALUES (?, ?, ?) 
               ON CONFLICT(user_id) 
               DO UPDATE SET template_vector = ?, enrolled_at = ?''',
            (current_user_id, biometric_vector.tobytes(), datetime.utcnow().isoformat(),
             biometric_vector.tobytes(), datetime.utcnow().isoformat())
        )
        
        conn.commit()
        conn.close()
        
        return jsonify({'message': 'Biometric template updated successfully'}), 200
        
    except Exception as e:
        return jsonify({'error': f'Server error: {str(e)}'}), 500
