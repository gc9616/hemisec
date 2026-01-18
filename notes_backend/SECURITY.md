# Security Recommendations and Best Practices

This document outlines critical security measures for deploying the Biometric Authentication Notes API.

## 🔐 Critical Security Checklist

### Before Production Deployment

- [ ] **Set strong JWT secret key** - Use `python -c "import secrets; print(secrets.token_hex(32))"` to generate
- [ ] **Enable HTTPS/TLS** - Never deploy without SSL certificate
- [ ] **Configure CORS properly** - Restrict to specific origins, not `*`
- [ ] **Use environment variables** - Never hardcode secrets in code
- [ ] **Secure the database** - Set proper file permissions (600 for SQLite)
- [ ] **Implement rate limiting** - Prevent brute-force attacks
- [ ] **Enable logging** - Monitor authentication attempts and errors
- [ ] **Regular security audits** - Review code and dependencies
- [ ] **Backup strategy** - Regular encrypted database backups
- [ ] **Use production WSGI server** - Never use Flask's built-in server

## Authentication Security

### Password Security

**Current Implementation:**
- Argon2id hashing with secure parameters
- Time cost: 3 iterations
- Memory cost: 64 MB
- Parallelism: 4 threads
- Automatic rehashing when parameters change

**Recommendations:**
```python
# Monitor and adjust Argon2 parameters based on:
# - Server hardware capabilities
# - Response time requirements
# - Security threat level

# For high-security environments, increase parameters:
ph = PasswordHasher(
    time_cost=4,        # More iterations
    memory_cost=131072, # 128 MB
    parallelism=8,      # More threads
    hash_len=32,
    salt_len=16
)
```

**Password Policy (enforce on client side):**
- Minimum 12 characters (current: 8)
- Mix of uppercase, lowercase, numbers, symbols
- No common passwords (implement password blacklist)
- No personal information
- Force password rotation every 90 days

### JWT Token Security

**Current Implementation:**
- HS256 algorithm
- 24-hour expiration
- Signature verification

**Recommendations:**

1. **Token Rotation:**
```python
# Implement refresh tokens
def generate_refresh_token(user_id):
    payload = {
        'user_id': user_id,
        'type': 'refresh',
        'exp': datetime.utcnow() + timedelta(days=30)
    }
    return jwt.encode(payload, SECRET_KEY, algorithm='HS256')

# Endpoint to refresh access token
@api.route('/auth/refresh', methods=['POST'])
def refresh_token():
    refresh_token = request.json.get('refresh_token')
    # Validate and issue new access token
    # ...
```

2. **Token Blacklist:**
```python
# Implement token revocation for logout
# Store revoked tokens in Redis or database
REVOKED_TOKENS = set()

def is_token_revoked(token):
    return token in REVOKED_TOKENS

@api.route('/auth/logout', methods=['POST'])
@token_required
def logout(current_user_id, current_username):
    token = request.headers['Authorization'].split(' ')[1]
    REVOKED_TOKENS.add(token)
    return jsonify({'message': 'Logged out successfully'}), 200
```

3. **Enhanced Token Claims:**
```python
def generate_token(user_id, username, ip_address):
    payload = {
        'user_id': user_id,
        'username': username,
        'ip': ip_address,  # Bind to IP
        'jti': str(uuid.uuid4()),  # Unique token ID
        'exp': datetime.utcnow() + timedelta(hours=24),
        'iat': datetime.utcnow()
    }
    return jwt.encode(payload, SECRET_KEY, algorithm='HS256')
```

### Biometric Security

**Current Implementation:**
- Cosine similarity matching
- Threshold: 0.85
- Templates stored as binary blobs

**Critical Recommendations:**

1. **Encrypt Biometric Templates:**
```python
from cryptography.fernet import Fernet

# Generate encryption key (store securely, separate from JWT secret)
BIOMETRIC_KEY = Fernet.generate_key()
cipher = Fernet(BIOMETRIC_KEY)

def encrypt_template(vector):
    encrypted = cipher.encrypt(vector.tobytes())
    return encrypted

def decrypt_template(encrypted):
    decrypted = cipher.decrypt(encrypted)
    return np.frombuffer(decrypted, dtype=np.float32)
```

2. **Implement Template Aging:**
```python
# Force biometric re-enrollment after X days
MAX_TEMPLATE_AGE_DAYS = 90

def is_template_expired(enrolled_at):
    age = datetime.utcnow() - datetime.fromisoformat(enrolled_at)
    return age.days > MAX_TEMPLATE_AGE_DAYS
```

3. **Multi-Sample Enrollment:**
```python
# Store multiple biometric samples and compare against all
# Requires 3-5 samples during enrollment for robustness
def validate_against_multiple_templates(provided_vector, stored_templates):
    similarities = [get_similarity(provided_vector, t) for t in stored_templates]
    # Require match against majority of templates
    return sum(s >= BIOMETRIC_THRESHOLD for s in similarities) >= len(stored_templates) / 2
```

4. **Liveness Detection:**
- Implement liveness checks to prevent spoofing
- Use challenge-response mechanisms
- Detect presentation attacks

## Input Validation & Sanitization

### Current Implementation

All inputs are validated and sanitized. Enhance with:

```python
import bleach
import html

def advanced_sanitize(text):
    # Remove HTML tags
    text = bleach.clean(text, strip=True)
    # Escape special characters
    text = html.escape(text)
    # Remove null bytes
    text = text.replace('\x00', '')
    return text

# SQL injection prevention (already handled by parameterized queries)
# Never use string formatting for SQL queries
# ✅ Good: cursor.execute('SELECT * FROM users WHERE id = ?', (user_id,))
# ❌ Bad:  cursor.execute(f'SELECT * FROM users WHERE id = {user_id}')
```

### Additional Validation

```python
import re

def validate_username(username):
    # Only alphanumeric and underscore, 3-50 chars
    pattern = r'^[a-zA-Z0-9_]{3,50}$'
    if not re.match(pattern, username):
        return False, "Invalid username format"
    
    # Prevent SQL keywords as usernames
    sql_keywords = ['SELECT', 'DROP', 'INSERT', 'UPDATE', 'DELETE']
    if username.upper() in sql_keywords:
        return False, "Username not allowed"
    
    return True, None

def validate_note_content(content):
    # Check for suspicious patterns
    suspicious_patterns = [
        r'<script',  # XSS attempts
        r'javascript:',  # XSS attempts
        r'\x00',  # Null bytes
    ]
    
    for pattern in suspicious_patterns:
        if re.search(pattern, content, re.IGNORECASE):
            return False, "Content contains suspicious patterns"
    
    return True, None
```

## Rate Limiting

**Critical for preventing brute-force attacks:**

```python
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"],
    storage_uri="memory://"  # Use Redis in production
)

# Apply strict limits to authentication endpoints
@api.route('/auth/login', methods=['POST'])
@limiter.limit("5 per minute")  # Max 5 login attempts per minute
@limiter.limit("20 per hour")   # Max 20 per hour
def login():
    # ... implementation
    pass

@api.route('/auth/signup', methods=['POST'])
@limiter.limit("3 per hour")  # Limit signups
def signup():
    # ... implementation
    pass
```

## Database Security

### SQLite Hardening

```python
import sqlite3

def get_secure_db_connection():
    conn = sqlite3.connect(DATABASE_PATH)
    conn.row_factory = sqlite3.Row
    
    # Enable foreign keys
    conn.execute('PRAGMA foreign_keys = ON')
    
    # Set secure defaults
    conn.execute('PRAGMA auto_vacuum = FULL')
    conn.execute('PRAGMA secure_delete = ON')  # Overwrite deleted data
    
    return conn

# File permissions (run once)
import os
os.chmod(DATABASE_PATH, 0o600)  # Read/write for owner only
```

### Migration to PostgreSQL (Production)

For production, migrate to PostgreSQL:

```python
import psycopg2
from psycopg2 import pool

# Connection pool
db_pool = psycopg2.pool.SimpleConnectionPool(
    1, 20,
    user=os.environ['DB_USER'],
    password=os.environ['DB_PASSWORD'],
    host=os.environ['DB_HOST'],
    port=os.environ['DB_PORT'],
    database=os.environ['DB_NAME'],
    sslmode='require'  # Enforce SSL
)
```

## HTTPS/TLS Configuration

### Nginx Reverse Proxy

```nginx
server {
    listen 443 ssl http2;
    server_name api.yourdomain.com;

    # SSL certificates
    ssl_certificate /path/to/cert.pem;
    ssl_certificate_key /path/to/key.pem;

    # Strong SSL configuration
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers 'ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256';
    ssl_prefer_server_ciphers off;

    # HSTS
    add_header Strict-Transport-Security "max-age=63072000" always;

    # Security headers
    add_header X-Content-Type-Options nosniff;
    add_header X-Frame-Options DENY;
    add_header X-XSS-Protection "1; mode=block";

    location / {
        proxy_pass http://localhost:8080;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}

# Redirect HTTP to HTTPS
server {
    listen 80;
    server_name api.yourdomain.com;
    return 301 https://$server_name$request_uri;
}
```

## Logging & Monitoring

```python
import logging
from logging.handlers import RotatingFileHandler

# Configure logging
handler = RotatingFileHandler(
    'logs/api.log',
    maxBytes=10485760,  # 10MB
    backupCount=10
)
handler.setFormatter(logging.Formatter(
    '%(asctime)s %(levelname)s: %(message)s [in %(pathname)s:%(lineno)d]'
))

app.logger.addHandler(handler)
app.logger.setLevel(logging.INFO)

# Log security events
def log_auth_attempt(username, success, ip_address):
    if success:
        app.logger.info(f'Successful login: {username} from {ip_address}')
    else:
        app.logger.warning(f'Failed login attempt: {username} from {ip_address}')

def log_biometric_failure(username, similarity, ip_address):
    app.logger.warning(
        f'Biometric verification failed: {username} from {ip_address} '
        f'(similarity: {similarity})'
    )
```

## Security Headers

```python
@app.after_request
def set_security_headers(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    response.headers['Content-Security-Policy'] = "default-src 'self'"
    return response
```

## Dependency Security

```bash
# Regular dependency audits
pip install safety
safety check

# Keep dependencies updated
pip install --upgrade pip
pip list --outdated
pip install --upgrade package_name

# Use pip-audit
pip install pip-audit
pip-audit
```

## Backup Strategy

```bash
#!/bin/bash
# backup.sh - Run daily via cron

DATE=$(date +%Y%m%d_%H%M%S)
BACKUP_DIR="/secure/backups"
DB_PATH="/path/to/notes_app.db"

# Backup database
sqlite3 $DB_PATH ".backup '$BACKUP_DIR/notes_db_$DATE.db'"

# Encrypt backup
gpg --encrypt --recipient your@email.com "$BACKUP_DIR/notes_db_$DATE.db"

# Remove unencrypted backup
rm "$BACKUP_DIR/notes_db_$DATE.db"

# Keep only last 30 days
find $BACKUP_DIR -name "notes_db_*.gpg" -mtime +30 -delete
```

## Incident Response Plan

1. **Suspected Breach:**
   - Immediately revoke all JWT tokens
   - Force password reset for all users
   - Audit logs for suspicious activity
   - Notify affected users

2. **Database Compromise:**
   - Passwords are hashed with Argon2 (safe)
   - Biometric templates should be encrypted
   - Investigate attack vector
   - Patch vulnerabilities

3. **DDoS Attack:**
   - Enable rate limiting
   - Use CloudFlare or similar DDoS protection
   - Scale infrastructure

## Compliance Considerations

### GDPR Compliance

- Implement data export endpoint
- Implement account deletion endpoint
- Document data retention policies
- Obtain explicit consent for biometric processing

```python
@api.route('/user/export', methods=['GET'])
@token_required
def export_user_data(current_user_id, current_username):
    """Export all user data (GDPR right to data portability)"""
    # ... implementation
    pass

@api.route('/user/delete', methods=['DELETE'])
@token_required
def delete_account(current_user_id, current_username):
    """Permanently delete user account (GDPR right to erasure)"""
    # Verify password before deletion
    # Delete all user data
    # Log deletion for audit
    pass
```

## Regular Security Checklist

- [ ] Weekly: Review authentication logs
- [ ] Weekly: Check for failed login patterns
- [ ] Monthly: Update dependencies
- [ ] Monthly: Review and rotate JWT secrets
- [ ] Quarterly: Security audit
- [ ] Quarterly: Penetration testing
- [ ] Annually: Comprehensive security review

## Additional Resources

- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [OWASP API Security Top 10](https://owasp.org/www-project-api-security/)
- [Flask Security Best Practices](https://flask.palletsprojects.com/en/latest/security/)
- [JWT Best Practices](https://tools.ietf.org/html/rfc8725)
