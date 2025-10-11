# Quick Security Reference Guide

## For Developers

### 🚀 Quick Start

1. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

2. **Set up environment:**
   ```bash
   cp .env.example .env
   # Edit .env with your values
   ```

3. **Generate password hash:**
   ```bash
   echo -n "your_password" | sha256sum
   # Copy hash to .env as MASTER_PASSWORD_HASH
   ```

4. **Run application:**
   ```bash
   python app.py
   ```

---

## 🔐 Security Checklist

### Before Committing Code
- [ ] No hardcoded credentials or secrets
- [ ] All user inputs validated and sanitized
- [ ] No sensitive data in logs
- [ ] Error messages don't leak info
- [ ] SQL queries use parameterization
- [ ] `.env` file not committed

### Before Deploying
- [ ] `FLASK_DEBUG=False` in production
- [ ] `MONGO_URI` environment variable set
- [ ] `MASTER_PASSWORD_HASH` configured
- [ ] `ALLOWED_ORIGINS` restricted to your domains
- [ ] HTTPS/SSL enabled
- [ ] Firewall rules configured
- [ ] Database backups enabled
- [ ] Monitoring and alerts set up

### After Deployment
- [ ] Test authentication endpoint
- [ ] Verify CORS restrictions
- [ ] Check security headers
- [ ] Monitor logs for errors
- [ ] Test rate limiting
- [ ] Verify HTTPS redirect

---

## 🔑 Authentication Flow

### 1. Login
```javascript
POST /key
{
  "password": "your_password"
}

Response:
{
  "success": true,
  "message": "Authentication successful",
  "token": "v7K2n9X4pL8mQ3wR..." // 32-byte random token
}
```

### 2. Use Token
```javascript
GET /teams
Headers:
  X-Auth-Token: v7K2n9X4pL8mQ3wR...

Response:
{
  "success": true,
  "teams": [...]
}
```

### 3. Token Expiry
- Tokens expire after **24 hours**
- Must re-authenticate to get new token
- No automatic refresh (implement if needed)

---

## 🛡️ Security Features

### Input Sanitization
All user inputs are sanitized using `html.escape()`:
```python
# Dangerous input
"<script>alert('XSS')</script>"

# Sanitized output
"&lt;script&gt;alert('XSS')&lt;/script&gt;"
```

### Password Hashing
Passwords are hashed using SHA-256:
```python
# Password (never stored)
"mypassword"

# Hash (stored in environment)
"5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8"
```

### Token Generation
Tokens are cryptographically secure random strings:
```python
token = secrets.token_urlsafe(32)
# Example: "v7K2n9X4pL8mQ3wR6tY2zB5nM8aH1cK9fE3jL7"
```

---

## 🚨 Common Security Mistakes

### ❌ DON'T
```python
# Hardcoded credentials
PASSWORD = "admin123"

# Plaintext password comparison
if password == stored_password:

# Unsafe SQL
cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")

# XSS vulnerability
return f"<h1>Welcome {username}</h1>"

# Debug mode in production
app.run(debug=True)

# Unrestricted CORS
CORS(app)
```

### ✅ DO
```python
# Environment variables
PASSWORD_HASH = os.environ.get('PASSWORD_HASH')

# Hash comparison
if hash_password(password) == PASSWORD_HASH:

# Parameterized queries
cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))

# Sanitized output
return f"<h1>Welcome {html.escape(username)}</h1>"

# Environment-controlled debug
debug = os.environ.get('FLASK_DEBUG', 'False') == 'True'
app.run(debug=debug)

# Restricted CORS
CORS(app, origins=['https://yourdomain.com'])
```

---

## 📊 Security Headers Explained

### X-Content-Type-Options: nosniff
Prevents MIME-type sniffing attacks.

### X-Frame-Options: DENY
Prevents clickjacking by disallowing iframe embedding.

### X-XSS-Protection: 1; mode=block
Enables browser's XSS filter in blocking mode.

### Strict-Transport-Security
Enforces HTTPS connections (requires SSL).

### Content-Security-Policy
Controls which resources can be loaded (prevents XSS).

---

## 🔍 Debugging Security Issues

### Authentication Not Working
```bash
# Check password hash
python3 -c "import hashlib; print(hashlib.sha256(b'your_password').hexdigest())"

# Compare with environment variable
echo $MASTER_PASSWORD_HASH

# Check logs
grep "authentication" app.log
```

### CORS Errors
```bash
# Check ALLOWED_ORIGINS
echo $ALLOWED_ORIGINS

# Should include your frontend domain
# Example: https://yourdomain.com,http://localhost:3000
```

### Token Expired
```bash
# Tokens expire after 24 hours
# Re-authenticate to get new token
curl -X POST http://localhost:5000/key -d '{"password":"..."}'
```

---

## 📚 Further Reading

### Documentation
- [SECURITY_AUDIT_REPORT.md](./SECURITY_AUDIT_REPORT.md) - Complete audit report
- [SECURITY.md](./SECURITY.md) - Detailed security guidelines
- [SECURITY_README.md](./SECURITY_README.md) - Security overview
- [MIGRATION.md](./MIGRATION.md) - Migration guide

### External Resources
- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [Flask Security](https://flask.palletsprojects.com/en/latest/security/)
- [MongoDB Security](https://docs.mongodb.com/manual/security/)

---

## 🆘 Emergency Procedures

### If Credentials Compromised
1. **Immediately** change master password
2. Generate new password hash
3. Update `MASTER_PASSWORD_HASH` environment variable
4. Restart application (clears all tokens)
5. Review logs for unauthorized access
6. Notify affected users

### If Security Vulnerability Found
1. **DO NOT** create public issue
2. Create private security advisory on GitHub
3. Document steps to reproduce
4. Suggest a fix if possible
5. Allow time for remediation before disclosure

---

## 💡 Quick Tips

### Generate Strong Password
```bash
# 32-character random password
python3 -c "import secrets; print(secrets.token_urlsafe(24))"
```

### Test Security Headers
```bash
curl -I http://localhost:5000/health
```

### Monitor Failed Authentications
```bash
grep "Failed authentication" app.log | tail -20
```

### Check Rate Limiting
```bash
for i in {1..15}; do 
  curl http://localhost:5000/health
  echo ""
done
```

---

## 🔗 Useful Commands

```bash
# Install dependencies
pip install -r requirements.txt

# Generate password hash
echo -n "password" | sha256sum

# Run with environment file
export $(cat .env | xargs) && python app.py

# Test authentication
curl -X POST http://localhost:5000/key \
  -H "Content-Type: application/json" \
  -d '{"password":"your_password"}'

# Test protected endpoint
TOKEN="your_token_here"
curl http://localhost:5000/teams \
  -H "X-Auth-Token: $TOKEN"

# Check security headers
curl -I http://localhost:5000/health | grep -E "^X-|^Strict|^Content-Security"
```

---

**Last Updated:** October 11, 2025  
**Version:** 1.0  
**Status:** ✅ Production Ready
