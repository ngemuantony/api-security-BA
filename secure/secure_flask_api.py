from flask import Flask, request, jsonify
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import jwt
import bcrypt
import sqlite3
import secrets
import re
from datetime import datetime, timedelta
from functools import wraps
import time

app = Flask(__name__)
app.secret_key = secrets.token_hex(32)  # Strong secret key

# Rate limiting setup
limiter = Limiter(
    app,
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"]
)

# In-memory store for failed login attempts (in production, use Redis)
failed_attempts = {}
locked_accounts = {}

# Strong JWT secret
JWT_SECRET = secrets.token_hex(32)
JWT_ALGORITHM = 'HS256'

def init_db():
    conn = sqlite3.connect('secure_users.db')
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            email TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            last_login TIMESTAMP,
            is_locked BOOLEAN DEFAULT FALSE
        )
    ''')
    
    # Insert test user with strong password
    strong_password = 'StrongP@ssw0rd123!'
    password_hash = bcrypt.hashpw(strong_password.encode('utf-8'), bcrypt.gensalt())
    
    cursor.execute('''
        INSERT OR REPLACE INTO users (username, password_hash, email) 
        VALUES (?, ?, ?)
    ''', ('admin', password_hash, 'admin@example.com'))
    
    conn.commit()
    conn.close()

def is_strong_password(password):
    """Validate password strength"""
    if len(password) < 8:
        return False, "Password must be at least 8 characters long"
    
    if not re.search(r"[A-Z]", password):
        return False, "Password must contain at least one uppercase letter"
    
    if not re.search(r"[a-z]", password):
        return False, "Password must contain at least one lowercase letter"
    
    if not re.search(r"\d", password):
        return False, "Password must contain at least one digit"
    
    if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
        return False, "Password must contain at least one special character"
    
    return True, "Password is strong"

def check_account_lockout(username):
    """Check if account is locked due to failed attempts"""
    current_time = time.time()
    
    if username in locked_accounts:
        if current_time < locked_accounts[username]:
            return True, "Account is temporarily locked due to multiple failed attempts"
    
    return False, ""

def record_failed_attempt(username):
    """Record a failed login attempt"""
    current_time = time.time()
    
    if username not in failed_attempts:
        failed_attempts[username] = []
    
    # Remove attempts older than 15 minutes
    failed_attempts[username] = [
        attempt for attempt in failed_attempts[username] 
        if current_time - attempt < 900
    ]
    
    failed_attempts[username].append(current_time)
    
    # Lock account if more than 5 failed attempts in 15 minutes
    if len(failed_attempts[username]) >= 5:
        locked_accounts[username] = current_time + 1800  # Lock for 30 minutes

def clear_failed_attempts(username):
    """Clear failed attempts after successful login"""
    if username in failed_attempts:
        del failed_attempts[username]
    if username in locked_accounts:
        del locked_accounts[username]

def token_required(f):
    """Decorator to validate JWT tokens"""
    @wraps(f)
    def decorated(*args, **kwargs):
        auth_header = request.headers.get('Authorization')
        
        if not auth_header or not auth_header.startswith('Bearer '):
            return jsonify({'error': 'No valid token provided'}), 401
        
        token = auth_header.split(' ')[1]
        
        try:
            decoded = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
            # Validate token expiration
            if datetime.utcnow() > datetime.fromtimestamp(decoded['exp']):
                return jsonify({'error': 'Token has expired'}), 401
                
            request.current_user = decoded
        except jwt.ExpiredSignatureError:
            return jsonify({'error': 'Token has expired'}), 401
        except jwt.InvalidTokenError:
            return jsonify({'error': 'Invalid token'}), 401
        
        return f(*args, **kwargs)
    
    return decorated

@app.route('/login', methods=['POST'])
@limiter.limit("5 per minute")  # Strict rate limiting for login
def login():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    
    if not username or not password:
        return jsonify({'error': 'Username and password required'}), 400
    
    # Check account lockout
    is_locked, lock_message = check_account_lockout(username)
    if is_locked:
        return jsonify({'error': lock_message}), 429
    
    conn = sqlite3.connect('secure_users.db')
    cursor = conn.cursor()
    cursor.execute('SELECT id, username, password_hash FROM users WHERE username = ?', 
                   (username,))
    user = cursor.fetchone()
    conn.close()
    
    if user and bcrypt.checkpw(password.encode('utf-8'), user[2]):
        # Clear failed attempts on successful login
        clear_failed_attempts(username)
        
        # Generate secure JWT token with expiration
        payload = {
            'user_id': user[0],
            'username': user[1],
            'exp': datetime.utcnow() + timedelta(hours=1),
            'iat': datetime.utcnow()
        }
        token = jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)
        
        # Update last login
        conn = sqlite3.connect('secure_users.db')
        cursor = conn.cursor()
        cursor.execute('UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE username = ?', 
                       (username,))
        conn.commit()
        conn.close()
        
        return jsonify({
            'token': token,
            'message': 'Login successful',
            'expires_in': 3600
        })
    else:
        # Record failed attempt
        record_failed_attempt(username)
        return jsonify({'error': 'Invalid credentials'}), 401

@app.route('/register', methods=['POST'])
@limiter.limit("3 per minute")
def register():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    email = data.get('email')
    
    if not username or not password or not email:
        return jsonify({'error': 'Username, password, and email required'}), 400
    
    # Validate password strength
    is_strong, message = is_strong_password(password)
    if not is_strong:
        return jsonify({'error': message}), 400
    
    # Validate email format
    if not re.match(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', email):
        return jsonify({'error': 'Invalid email format'}), 400
    
    # Hash password securely
    password_hash = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
    
    try:
        conn = sqlite3.connect('secure_users.db')
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO users (username, password_hash, email) 
            VALUES (?, ?, ?)
        ''', (username, password_hash, email))
        conn.commit()
        conn.close()
        
        return jsonify({'message': 'User registered successfully'}), 201
    except sqlite3.IntegrityError:
        return jsonify({'error': 'Username already exists'}), 409

@app.route('/update_email', methods=['PUT'])
@token_required
def update_email():
    data = request.get_json()
    new_email = data.get('email')
    current_password = data.get('current_password')  # Require password confirmation
    
    if not new_email or not current_password:
        return jsonify({'error': 'New email and current password required'}), 400
    
    # Validate email format
    if not re.match(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', new_email):
        return jsonify({'error': 'Invalid email format'}), 400
    
    username = request.current_user['username']
    
    # Verify current password
    conn = sqlite3.connect('secure_users.db')
    cursor = conn.cursor()
    cursor.execute('SELECT password_hash FROM users WHERE username = ?', (username,))
    user = cursor.fetchone()
    
    if not user or not bcrypt.checkpw(current_password.encode('utf-8'), user[0]):
        conn.close()
        return jsonify({'error': 'Current password is incorrect'}), 401
    
    # Update email
    cursor.execute('UPDATE users SET email = ? WHERE username = ?', 
                   (new_email, username))
    conn.commit()
    conn.close()
    
    return jsonify({'message': 'Email updated successfully'})

@app.route('/change_password', methods=['PUT'])
@token_required
@limiter.limit("3 per minute")
def change_password():
    data = request.get_json()
    current_password = data.get('current_password')
    new_password = data.get('new_password')
    
    if not current_password or not new_password:
        return jsonify({'error': 'Current password and new password required'}), 400
    
    # Validate new password strength
    is_strong, message = is_strong_password(new_password)
    if not is_strong:
        return jsonify({'error': message}), 400
    
    username = request.current_user['username']
    
    # Verify current password
    conn = sqlite3.connect('secure_users.db')
    cursor = conn.cursor()
    cursor.execute('SELECT password_hash FROM users WHERE username = ?', (username,))
    user = cursor.fetchone()
    
    if not user or not bcrypt.checkpw(current_password.encode('utf-8'), user[0]):
        conn.close()
        return jsonify({'error': 'Current password is incorrect'}), 401
    
    # Hash new password
    new_password_hash = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt())
    
    # Update password
    cursor.execute('UPDATE users SET password_hash = ? WHERE username = ?', 
                   (new_password_hash, username))
    conn.commit()
    conn.close()
    
    return jsonify({'message': 'Password changed successfully'})

@app.route('/profile', methods=['GET'])
@token_required
def get_profile():
    username = request.current_user['username']
    
    conn = sqlite3.connect('secure_users.db')
    cursor = conn.cursor()
    cursor.execute('SELECT username, email, created_at, last_login FROM users WHERE username = ?', 
                   (username,))
    user = cursor.fetchone()
    conn.close()
    
    if user:
        return jsonify({
            'username': user[0],
            'email': user[1],
            'created_at': user[2],
            'last_login': user[3]
        })
    else:
        return jsonify({'error': 'User not found'}), 404

@app.route('/health')
def health():
    return jsonify({'status': 'running', 'security': 'enhanced'})

@app.errorhandler(429)
def ratelimit_handler(e):
    return jsonify({'error': 'Rate limit exceeded', 'message': str(e.description)}), 429

if __name__ == '__main__':
    init_db()
    app.run(debug=True, port=5001)