# Biometric Authentication Notes API

A secure Flask-based REST API backend for a notes application with two-factor authentication using password and biometric verification.

## Features

- 🔐 **Two-Factor Authentication**: Password (Argon2) + Biometric verification
- 🔑 **JWT Token-based Sessions**: Secure token authentication for API requests
- 📝 **Full CRUD Operations**: Create, Read, Update, Delete notes
- 🗄️ **SQLite Database**: Lightweight, embedded database
- 🛡️ **Security-First Design**: Input validation, sanitization, and secure password hashing
- 🔬 **Biometric Matching**: Cosine similarity-based biometric verification

## Security Features

1. **Argon2id Password Hashing**: Industry-standard KDF with secure parameters
   - Time cost: 3 iterations
   - Memory cost: 64 MB
   - Parallelism: 4 threads

2. **JWT Authentication**: Stateless token-based authentication with expiry

3. **Biometric Verification**: Cosine similarity matching with configurable threshold (default: 0.85)

4. **Input Validation**: Comprehensive validation and sanitization of all inputs

5. **Database Security**: Foreign key constraints, CASCADE deletes, indexed queries

## Installation

1. Install dependencies:
```bash
cd notes_backend
pip install -r requirements.txt
```

2. Set environment variables (recommended for production):
```bash
export JWT_SECRET_KEY="your-secure-random-key-here"
export BIOMETRIC_THRESHOLD="0.85"
export FLASK_DEBUG="False"
```

3. Run the server:
```bash
python main.py
```

The API will be available at `http://localhost:8080`

## API Endpoints

### Authentication

#### 1. Sign Up
**POST** `/api/auth/signup`

Register a new user with password and biometric enrollment.

**Request Body:**
```json
{
  "username": "john_doe",
  "password": "SecurePass123!",
  "biometric_vector": "base64_encoded_numpy_array"
}
```

**Response (201):**
```json
{
  "message": "User registered successfully",
  "user_id": 1,
  "username": "john_doe"
}
```

#### 2. Login
**POST** `/api/auth/login`

Authenticate with password and biometric verification.

**Request Body:**
```json
{
  "username": "john_doe",
  "password": "SecurePass123!",
  "biometric_vector": "base64_encoded_numpy_array"
}
```

**Response (200):**
```json
{
  "message": "Authentication successful",
  "access_token": "eyJ0eXAiOiJKV1QiLCJhbGc...",
  "similarity": 0.923,
  "username": "john_doe"
}
```

#### 3. Verify Token
**GET** `/api/auth/verify`

Verify if the current JWT token is valid.

**Headers:**
```
Authorization: Bearer <token>
```

**Response (200):**
```json
{
  "valid": true,
  "user_id": 1,
  "username": "john_doe"
}
```

#### 4. Update Biometric Template
**PUT** `/api/biometric/update`

Update the biometric template for the authenticated user.

**Headers:**
```
Authorization: Bearer <token>
```

**Request Body:**
```json
{
  "biometric_vector": "base64_encoded_numpy_array",
  "password": "SecurePass123!"
}
```

**Response (200):**
```json
{
  "message": "Biometric template updated successfully"
}
```

### Notes Management

All notes endpoints require authentication via JWT token in the Authorization header.

#### 5. Get All Notes
**GET** `/api/notes`

Retrieve all notes for the authenticated user.

**Headers:**
```
Authorization: Bearer <token>
```

**Response (200):**
```json
{
  "notes": [
    {
      "id": 1,
      "title": "Shopping List",
      "content": "Milk, Eggs, Bread",
      "created_at": "2026-01-17T10:30:00",
      "updated_at": "2026-01-17T10:30:00"
    }
  ]
}
```

#### 6. Get Note by ID
**GET** `/api/notes/<note_id>`

Retrieve a specific note.

**Headers:**
```
Authorization: Bearer <token>
```

**Response (200):**
```json
{
  "id": 1,
  "title": "Shopping List",
  "content": "Milk, Eggs, Bread",
  "created_at": "2026-01-17T10:30:00",
  "updated_at": "2026-01-17T10:30:00"
}
```

#### 7. Create Note
**POST** `/api/notes`

Create a new note.

**Headers:**
```
Authorization: Bearer <token>
```

**Request Body:**
```json
{
  "title": "Meeting Notes",
  "content": "Discuss project timeline and deliverables"
}
```

**Response (201):**
```json
{
  "message": "Note created successfully",
  "note": {
    "id": 2,
    "title": "Meeting Notes",
    "content": "Discuss project timeline and deliverables",
    "created_at": "2026-01-17T11:00:00",
    "updated_at": "2026-01-17T11:00:00"
  }
}
```

#### 8. Update Note
**PUT** `/api/notes/<note_id>`

Update an existing note.

**Headers:**
```
Authorization: Bearer <token>
```

**Request Body:**
```json
{
  "title": "Updated Title",
  "content": "Updated content"
}
```

**Response (200):**
```json
{
  "message": "Note updated successfully",
  "note": {
    "id": 2,
    "title": "Updated Title",
    "content": "Updated content",
    "created_at": "2026-01-17T11:00:00",
    "updated_at": "2026-01-17T12:00:00"
  }
}
```

#### 9. Delete Note
**DELETE** `/api/notes/<note_id>`

Delete a note.

**Headers:**
```
Authorization: Bearer <token>
```

**Response (200):**
```json
{
  "message": "Note deleted successfully"
}
```

## Biometric Vector Format

The biometric vectors must be:
- Numpy arrays of float32 values
- Base64 encoded before sending to the API
- Consistent dimensions for all vectors

**Example (Python):**
```python
import numpy as np
import base64

# Create a biometric feature vector (example)
biometric_vector = np.random.rand(128).astype(np.float32)

# Encode to base64
biometric_b64 = base64.b64encode(biometric_vector.tobytes()).decode('utf-8')

# Use in API request
data = {
    "username": "john_doe",
    "password": "SecurePass123!",
    "biometric_vector": biometric_b64
}
```

**Example (Swift):**
```swift
import Foundation

// Assuming you have a Float array from your biometric extraction
let biometricVector: [Float] = // ... your biometric features

// Convert to Data
let data = biometricVector.withUnsafeBytes { Data($0) }

// Encode to base64
let biometricB64 = data.base64EncodedString()

// Use in API request
let requestBody: [String: Any] = [
    "username": "john_doe",
    "password": "SecurePass123!",
    "biometric_vector": biometricB64
]
```

## Error Handling

The API returns standard HTTP status codes:

- **200**: Success
- **201**: Created
- **400**: Bad Request (invalid input)
- **401**: Unauthorized (invalid credentials or token)
- **403**: Forbidden (accessing another user's resource)
- **404**: Not Found
- **409**: Conflict (e.g., username already exists)
- **500**: Internal Server Error

**Error Response Format:**
```json
{
  "error": "Descriptive error message"
}
```

## Database Schema

### Users Table
- `id`: INTEGER PRIMARY KEY
- `username`: TEXT UNIQUE NOT NULL
- `password_hash`: TEXT NOT NULL
- `created_at`: TIMESTAMP
- `last_login`: TIMESTAMP

### Biometric Templates Table
- `id`: INTEGER PRIMARY KEY
- `user_id`: INTEGER UNIQUE (FK → users.id)
- `template_vector`: BLOB NOT NULL
- `enrolled_at`: TIMESTAMP

### Notes Table
- `id`: INTEGER PRIMARY KEY
- `user_id`: INTEGER (FK → users.id)
- `title`: TEXT NOT NULL
- `content`: TEXT NOT NULL
- `created_at`: TIMESTAMP
- `updated_at`: TIMESTAMP

## Production Deployment

For production deployment:

1. **Set environment variables:**
   - `JWT_SECRET_KEY`: Strong random key (use `secrets.token_hex(32)`)
   - `BIOMETRIC_THRESHOLD`: Adjust based on your biometric system
   - `FLASK_DEBUG`: Set to `False`
   - `CORS_ORIGINS`: Set to your Swift app's origin

2. **Use a production WSGI server:**
   ```bash
   pip install gunicorn
   gunicorn -w 4 -b 0.0.0.0:8080 main:app
   ```

3. **Enable HTTPS**: Use a reverse proxy (nginx, Apache) with SSL/TLS

4. **Database**: Consider using PostgreSQL for production instead of SQLite

5. **Rate Limiting**: Implement rate limiting to prevent brute-force attacks

6. **Logging**: Add comprehensive logging for security auditing

## Testing

Example test with curl:

```bash
# Sign up
curl -X POST http://localhost:8080/api/auth/signup \
  -H "Content-Type: application/json" \
  -d '{
    "username": "testuser",
    "password": "TestPass123!",
    "biometric_vector": "AAAAAAA..."
  }'

# Login
curl -X POST http://localhost:8080/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "username": "testuser",
    "password": "TestPass123!",
    "biometric_vector": "AAAAAAA..."
  }'

# Create note (replace TOKEN with actual token from login)
curl -X POST http://localhost:8080/api/notes \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer TOKEN" \
  -d '{
    "title": "Test Note",
    "content": "This is a test note"
  }'
```

## License

See LICENSE file for details.

## Security Considerations

1. **JWT Secret**: Always use a strong, randomly generated secret key in production
2. **HTTPS**: Never deploy without TLS/SSL encryption in production
3. **Biometric Data**: Handle biometric vectors with extreme care; consider encryption at rest
4. **Rate Limiting**: Implement rate limiting on authentication endpoints
5. **Input Validation**: The API validates all inputs, but always validate on the client side too
6. **Token Storage**: Store JWT tokens securely on the client (iOS Keychain for Swift apps)
7. **Password Policy**: Enforce strong password requirements on the client side
8. **Biometric Threshold**: Adjust the similarity threshold based on your security requirements and false positive/negative rates

## Support

For issues or questions, please open an issue in the repository.
