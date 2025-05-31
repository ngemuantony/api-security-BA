from flask import Flask, request, jsonify, session
import jwt
import hashlib
import sqlite3
import os
from datetime import datetime, timedelta

app = Flask(__name__)
app.secret_key = 'weak_secret_key'  # Weak secret key

# Initialize database
def init_db():
    conn = sqlite3.connect('insecure_users.db')
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            email TEXT NOT NULL
        )
    ''')
    
    # Insert test user with weak password
    cursor.execute('''
        INSERT OR REPLACE INTO users (username, password, email) 
        VALUES (?, ?, ?)
    ''', ('admin', hashlib.md5('password'.encode()).hexdigest(), 'admin@example.com'))
    
    cursor.execute('''
        INSERT OR REPLACE INTO users (username, password, email) 
        VALUES (?, ?, ?)
    ''', ('victim', hashlib.md5('123456'.encode()).hexdigest(), 'victim@example.com'))
    
    conn.commit()
    conn.close()

# VULNERABILITY: No rate limiting, allows brute force attacks
@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    
    if not username or not password:
        return jsonify({'error': 'Username and password required'}), 400
    
    # VULNERABILITY: Using weak MD5 hashing
    password_hash = hashlib.md5(password.encode()).hexdigest()
    
    conn = sqlite3.connect('insecure_users.db')
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM users WHERE username = ? AND password = ?', 
                   (username, password_hash))
    user = cursor.fetchone()
    conn.close()
    
    if user:
        # VULNERABILITY: Using weak signing algorithm and no expiration
        token = jwt.encode({'username': username},key=None, algorithm='none')
        return jsonify({'token': token, 'message': 'Login successful'})
    else:
        return jsonify({'error': 'Invalid credentials'}), 401

# VULNERABILITY: GraphQL-like batching that bypasses rate limiting
@app.route('/batch_login', methods=['POST'])
def batch_login():
    data = request.get_json()
    results = []
    
    if isinstance(data, list):
        for login_attempt in data:
            username = login_attempt.get('username')
            password = login_attempt.get('password')
            
            if username and password:
                password_hash = hashlib.md5(password.encode()).hexdigest()
                
                conn = sqlite3.connect('insecure_users.db')
                cursor = conn.cursor()
                cursor.execute('SELECT * FROM users WHERE username = ? AND password = ?', 
                               (username, password_hash))
                user = cursor.fetchone()
                conn.close()
                
                if user:
                    token = jwt.encode({'username': username},key=None, algorithm='none')
                    results.append({'success': True, 'token': token})
                else:
                    results.append({'success': False, 'error': 'Invalid credentials'})
            else:
                results.append({'success': False, 'error': 'Missing credentials'})
    
    return jsonify(results)

# VULNERABILITY: Sensitive operation without password confirmation
@app.route('/update_email', methods=['PUT'])
def update_email():
    auth_header = request.headers.get('Authorization')
    if not auth_header or not auth_header.startswith('Bearer '):
        return jsonify({'error': 'No token provided'}), 401
    
    token = auth_header.split(' ')[1]
    
    try:
        # VULNERABILITY: Not validating token signature (algorithm='none')
        decoded = jwt.decode(token, options={"verify_signature": False})
        username = decoded.get('username')
    except:
        return jsonify({'error': 'Invalid token'}), 401
    
    data = request.get_json()
    new_email = data.get('email')
    
    if not new_email:
        return jsonify({'error': 'Email required'}), 400
    
    # VULNERABILITY: No password confirmation for sensitive operation
    conn = sqlite3.connect('insecure_users.db')
    cursor = conn.cursor()
    cursor.execute('UPDATE users SET email = ? WHERE username = ?', 
                   (new_email, username))
    conn.commit()
    conn.close()
    
    return jsonify({'message': 'Email updated successfully'})

# VULNERABILITY: Password reset without proper validation
@app.route('/reset_password', methods=['POST'])
def reset_password():
    data = request.get_json()
    email = data.get('email')
    new_password = data.get('new_password')
    
    if not email or not new_password:
        return jsonify({'error': 'Email and new password required'}), 400
    
    # VULNERABILITY: Accepts weak passwords
    if len(new_password) < 3:
        return jsonify({'error': 'Password too short'}), 400
    
    # VULNERABILITY: Using weak MD5 hashing
    password_hash = hashlib.md5(new_password.encode()).hexdigest()
    
    conn = sqlite3.connect('insecure_users.db')
    cursor = conn.cursor()
    cursor.execute('UPDATE users SET password = ? WHERE email = ?', 
                   (password_hash, email))
    conn.commit()
    conn.close()
    
    return jsonify({'message': 'Password reset successful'})

# VULNERABILITY: Sends sensitive data in URL parameters
@app.route('/login_url')
def login_url():
    username = request.args.get('username')
    password = request.args.get('password')
    
    if not username or not password:
        return jsonify({'error': 'Username and password required'}), 400
    
    password_hash = hashlib.md5(password.encode()).hexdigest()
    
    conn = sqlite3.connect('insecure_users.db')
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM users WHERE username = ? AND password = ?', 
                   (username, password_hash))
    user = cursor.fetchone()
    conn.close()
    
    if user:
        token = jwt.encode({'username': username}, 'weak_secret', algorithm='none')
        return jsonify({'token': token, 'message': 'Login successful'})
    else:
        return jsonify({'error': 'Invalid credentials'}), 401

@app.route('/health')
def health():
    return jsonify({'status': 'running', 'vulnerabilities': 'many'})

if __name__ == '__main__':
    init_db()
    app.run(debug=True, port=5000)