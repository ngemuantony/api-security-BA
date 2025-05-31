# Secure Flask API - Proper Authentication Implementation

✅ **This application demonstrates secure authentication practices based on OWASP guidelines.**

This Flask application implements proper authentication security measures to prevent the vulnerabilities shown in OWASP API Security Top 10 - API2:2023 Broken Authentication.

## Security Features Implemented

### 1. **Rate Limiting**
- Strict rate limiting on authentication endpoints (5 login attempts per minute)
- General API rate limiting (200 requests per day, 50 per hour)
- Account lockout after 5 failed attempts in 15 minutes
- 30-minute lockout period for suspicious accounts

### 2. **Strong Password Policies**
- Minimum 8 characters required
- Must contain uppercase, lowercase, numbers, and special characters
- Password strength validation on registration and changes

### 3. **Secure Password Storage**
- bcrypt hashing with automatic salt generation
- Cryptographically secure password storage
- Protection against rainbow table attacks

### 4. **Secure JWT Implementation**
- Strong HMAC-SHA256 signing algorithm
- Cryptographically secure secret keys
- Token expiration validation (1 hour)
- Proper token structure with issued-at timestamps

### 5. **Re-authentication for Sensitive Operations**
- Password confirmation required for email updates
- Password confirmation required for password changes
- Critical operations require current password verification

### 6. **Secure Communication**
- No credentials in URL parameters
- All sensitive data in request bodies
- Proper HTTP methods for different operations

### 7. **Account Security Measures**
- Failed login attempt tracking
- Automatic account lockout mechanisms
- Clear failed attempts on successful login

## Installation & Setup

```bash
# Install dependencies
pip install flask flask-limiter pyjwt bcrypt

# Run the secure application
python secure_api.py
```

The application will start on `http://localhost:5001`

## Default Test User

| Username | Password | Email |
|----------|----------|-------|
| admin    | StrongP@ssw0rd123! | admin@example.com |

## API Endpoints

### Authentication
- `POST /login` - Secure login with rate limiting
- `POST /register` - User registration with strong password requirements

### Account Management  
- `PUT /update_email` - Update email with password confirmation
- `PUT /change_password` - Change password with current password verification
- `GET /profile` - Get user profile information

### Utility
- `GET /health` - Health check endpoint

## Usage Examples

### 1. User Registration
```bash
curl -X POST http://localhost:5001/register \
  -H "Content-Type: application/json" \
  -d '{
    "username":"newuser",
    "password":"SecureP@ssw0rd123!",
    "email":"user@example.com"
  }'
```

### 2. Secure Login
```bash
curl -X POST http://localhost:5001/login \
  -H "Content-Type: application/json" \
  -d '{
    "username":"admin",
    "password":"StrongP@ssw0rd123!"
  }'
```

### 3. Update Email (with password confirmation)
```bash
# Get token first
TOKEN=$(curl -X POST http://localhost:5001/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"StrongP@ssw0rd123!"}' | jq -r '.token')

# Update email with current password
curl -X PUT http://localhost:5001/update_email \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "email":"newemail@example.com",
    "current_password":"StrongP@ssw0rd123!"
  }'
```

### 4. Change Password
```bash
curl -X PUT http://localhost:5001/change_password \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "current_password":"StrongP@ssw0rd123!",
    "new_password":"NewSecureP@ssw0rd456!"
  }'
```

### 5. Get User Profile
```bash
curl -X GET http://localhost:5001/profile \
  -H "Authorization: Bearer $TOKEN"
```

## Security Controls

### Rate Limiting
The application implements multiple layers of rate limiting:
- **Login endpoint**: 5 attempts per minute
- **Registration**: 3 attempts per minute  
- **Password change**: 3 attempts per minute
- **General API**: 200 requests per day, 50 per hour

### Account Lockout
- Tracks failed login attempts per username
- Locks account for 30 minutes after 5 failed attempts in 15 minutes
- Automatically clears failed attempts on successful login
- Uses time-based sliding window for attempt tracking

### Token Security
- Uses cryptographically secure random keys
- HMAC-SHA256 signing algorithm
- 1-hour token expiration
- Proper token validation including expiration checks

### Password Security
- bcrypt with automatic salt generation
- Strong password requirements enforced
- No password storage in plain text or weak hashing

## Error Handling

The application provides appropriate error responses:
- `400 Bad Request` - Invalid input data
- `401 Unauthorized` - Authentication failed
- `409 Conflict` - Username already exists
- `429 Too Many Requests` - Rate limit exceeded

## Testing Security Features

### 1. Test Rate Limiting
```bash
# This will