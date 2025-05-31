# OWASP API Security Top 10 - Broken Authentication Demo

![OWASP](https://img.shields.io/badge/OWASP-API%20Security%20Top%2010-red)
![Python](https://img.shields.io/badge/Python-3.7+-blue)
![Flask](https://img.shields.io/badge/Flask-Web%20Framework-green)
![Security](https://img.shields.io/badge/Security-Educational-orange)

This project demonstrates **API2:2023 Broken Authentication** vulnerabilities from the OWASP API Security Top 10, providing both vulnerable and secure implementations to help developers understand authentication security risks and proper mitigation strategies.

## 🎯 Project Overview

Authentication mechanisms are critical security components that are often implemented incorrectly, making them attractive targets for attackers. This educational project provides hands-on examples of:

- **Vulnerable Flask API** - Demonstrates common authentication flaws
- **Secure Flask API** - Shows proper authentication implementation
- **Real-world attack scenarios** - Practical exploitation examples
- **Security best practices** - Industry-standard mitigation techniques

## 📊 OWASP API2:2023 - Broken Authentication

| **Threat Agents** | **Attack Vectors** | **Security Weakness** | **Technical Impact** | **Business Impact** |
|-------------------|-------------------|----------------------|---------------------|-------------------|
| API Specific | Easy Exploitability | Common Prevalence | Severe | Specific |
| Exposed authentication mechanisms make easy targets | Authentication boundaries misunderstood by developers | Easy to detect with available tools | Complete account takeover possible | System unable to distinguish legitimate users from attackers |

## 🚨 Vulnerabilities Demonstrated

### Critical Authentication Flaws

1. **🔓 Credential Stuffing & Brute Force**
   - No rate limiting on authentication endpoints
   - Missing account lockout mechanisms
   - GraphQL batch query abuse

2. **🔑 Weak Password Policies**
   - Acceptance of weak passwords
   - No complexity requirements
   - Poor password storage practices

3. **🎭 JWT Token Vulnerabilities**
   - Unsigned tokens (`"alg":"none"`)
   - Missing expiration validation
   - Weak signing secrets

4. **⚠️ Missing Re-authentication**
   - Sensitive operations without password confirmation
   - Account takeover through email changes
   - No step-up authentication

5. **📡 Information Disclosure**
   - Credentials in URL parameters
   - Sensitive data in server logs
   - Insecure password reset flows

## 🏗️ Project Structure

```
owasp-api-broken-auth/
├── insecure_api.py          # Vulnerable Flask application
├── secure_api.py            # Secure Flask application
├── requirements.txt         # Python dependencies
├── README.md               # This file
├── insecure/
│   └── README.md           # Vulnerable app documentation
├── secure/
│   └── README.md           # Secure app documentation
└── examples/
    ├── attack_scripts/     # Exploitation examples
    └── test_cases/         # Security test cases
```

## 🛠️ Quick Start

### Prerequisites

- Python 3.7 or higher
- pip package manager

### Installation

```bash
# Clone the repository
git clone https://github.com/your-repo/owasp-api-broken-auth.git
cd owasp-api-broken-auth

# Install dependencies
pip install -r requirements.txt
```

### Running the Applications

#### Vulnerable API (Educational Purpose Only)
```bash
python insecure_api.py
# Runs on http://localhost:5000
```

#### Secure API (Best Practices)
```bash
python secure_api.py  
# Runs on http://localhost:5001
```

## 🎭 Attack Scenarios

### Scenario 1: GraphQL Batch Attack
Bypass rate limiting using GraphQL-style batch requests to perform rapid brute force attacks.

```bash
curl -X POST http://localhost:5000/batch_login \
  -H "Content-Type: application/json" \
  -d '[
    {"username":"victim","password":"password123"},
    {"username":"victim","password":"admin"},
    {"username":"victim","password":"123456"},
    {"username":"victim","password":"qwerty"}
  ]'
```

### Scenario 2: Account Takeover Chain
Exploit missing re-authentication to take over user accounts.

```bash
# 1. Get victim's token (through various means)
TOKEN="eyJ0eXAiOiJKV1QiLCJhbGciOiJub25lIn0..."

# 2. Change email without password confirmation
curl -X PUT http://localhost:5000/update_email \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"email":"attacker@evil.com"}'

# 3. Reset password using new email
curl -X POST http://localhost:5000/reset_password \
  -d '{"email":"attacker@evil.com","new_password":"hacked123"}'
```

### Scenario 3: JWT Manipulation
Exploit unsigned JWT tokens to impersonate users.

```bash
# Tokens use "alg":"none" - can be modified without signature
# Original: {"username":"user1"}
# Modified: {"username":"admin"}
```

## 🛡️ Security Implementations

The secure API demonstrates proper authentication controls:

| **Vulnerability** | **Secure Implementation** |
|-------------------|---------------------------|
| No rate limiting | Flask-Limiter with strict limits (5 login/min) |
| Weak passwords | Complex password requirements + bcrypt |
| Unsigned JWTs | HMAC-SHA256 with secure secrets + expiration |
| Missing re-auth | Password confirmation for sensitive operations |
| Credentials in URLs | POST requests with proper headers only |
| Account enumeration | Consistent error messages + timing |

## 📈 Testing & Validation

### Automated Security Tests

```bash
# Test rate limiting
./test_rate_limiting.sh

# Test password policies  
./test_password_strength.sh

# Test JWT security
./test_jwt_validation.sh

# Test account lockout
./test_account_lockout.sh
```

### Manual Testing Checklist

- [ ] Attempt brute force attacks
- [ ] Test weak password acceptance
- [ ] Validate JWT token security
- [ ] Check sensitive operation protection
- [ ] Verify rate limiting effectiveness
- [ ] Test account lockout mechanisms

## 📚 Educational Resources

### OWASP References
- [OWASP API Security Top 10](https://owasp.org/www-project-api-security/)
- [Authentication Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html)
- [JSON Web Token Security](https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_for_Java_Cheat_Sheet.html)

### Learning Objectives
- Understand common authentication vulnerabilities
- Learn secure authentication implementation patterns
- Practice vulnerability identification and exploitation
- Master security testing techniques

## ⚠️ Important Disclaimers

### 🔒 Security Warning
**The vulnerable application contains intentional security flaws and should NEVER be deployed in production or any publicly accessible environment.**

### 🎓 Educational Use Only
This project is designed for:
- Security education and training
- Penetration testing practice  
- Developer security awareness
- Academic research purposes

### 🚫 Prohibited Uses
- Attacking systems without explicit permission
- Deploying vulnerable code in production
- Using techniques for malicious purposes
- Violating any applicable laws or regulations

## 🤝 Contributing

We welcome contributions to improve this educational resource:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/improvement`)
3. Commit your changes (`git commit -am 'Add security improvement'`)
4. Push to the branch (`git push origin feature/improvement`)
5. Create a Pull Request

### Contribution Guidelines
- Maintain educational focus
- Document all security implications
- Include both vulnerable and secure examples
- Follow secure coding practices in secure implementations

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🔗 Related Projects

- [OWASP WebGoat](https://github.com/WebGoat/WebGoat) - Interactive security learning
- [DVWA](https://github.com/digininja/DVWA) - Web application security testing
- [VulnHub](https://www.vulnhub.com/) - Vulnerable system practice

## 📞 Support & Contact

- **Issues**: Please report bugs and vulnerabilities through GitHub Issues
- **Discussions**: Join our community discussions for questions and improvements
- **Security**: For security-related concerns, please use responsible disclosure

## 🏆 Acknowledgments

- OWASP Foundation for API Security Top 10 research
- Security researchers who identified these vulnerability patterns
- Open source community for security tools and frameworks
- Contributors who help improve this educational resource

---

**Remember: Use this knowledge responsibly to build more secure applications! 🛡️**