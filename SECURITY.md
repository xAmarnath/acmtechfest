# Security Guidelines

## Security Issues Fixed

This document outlines the security vulnerabilities that were identified and fixed in this application.

### Critical Issues Fixed

1. **Hardcoded Credentials** ✅
   - **Issue**: Master password "0022" was hardcoded in multiple locations
   - **Fix**: Moved to environment variable with SHA-256 hashing
   - **Action Required**: Set `MASTER_PASSWORD_HASH` environment variable

2. **Weak Authentication** ✅
   - **Issue**: Password was returned as token, allowing plaintext transmission
   - **Fix**: Implemented secure token generation using `secrets.token_urlsafe()`
   - **Details**: Tokens are 32-byte random strings with 24-hour expiration

3. **No Password Hashing** ✅
   - **Issue**: Passwords were compared in plaintext
   - **Fix**: Implemented SHA-256 hashing for password verification
   - **Note**: Consider upgrading to bcrypt or argon2 for production

### High Priority Issues Fixed

4. **Debug Mode Enabled** ✅
   - **Issue**: `app.run(debug=True)` exposed sensitive information
   - **Fix**: Made debug mode environment-dependent via `FLASK_DEBUG`
   - **Production**: Always set `FLASK_DEBUG=False`

5. **Unrestricted CORS** ✅
   - **Issue**: `CORS(app)` allowed all origins
   - **Fix**: Restricted to specific origins via `ALLOWED_ORIGINS`
   - **Configuration**: Update `.env` with your actual domains

6. **Missing Security Headers** ✅
   - **Issue**: No security headers were set
   - **Fix**: Added middleware for:
     - X-Content-Type-Options: nosniff
     - X-Frame-Options: DENY
     - X-XSS-Protection: 1; mode=block
     - Strict-Transport-Security (HSTS)
     - Content-Security-Policy (CSP)

### Medium Priority Issues

7. **MongoDB URI Fallback** ✅
   - **Issue**: Unsafe default fallback value
   - **Fix**: Application now fails securely if MONGO_URI is not set
   - **Action Required**: Always set MONGO_URI environment variable

8. **Rate Limiting Storage** ⚠️
   - **Current**: Uses in-memory storage (not persistent across restarts)
   - **Recommendation**: For production, use Redis for persistent rate limiting
   - **Example**: `storage_uri="redis://localhost:6379"`

### Low Priority Considerations

9. **IP Address Logging** ℹ️
   - **Note**: Application logs user IP addresses for security monitoring
   - **Privacy**: Ensure compliance with GDPR/privacy laws in your jurisdiction
   - **Recommendation**: Implement IP address anonymization or obtain user consent

## Deployment Checklist

Before deploying to production:

- [ ] Set `MONGO_URI` environment variable
- [ ] Generate and set `MASTER_PASSWORD_HASH` (don't use default!)
  ```bash
  echo -n "your_secure_password" | sha256sum
  ```
- [ ] Configure `ALLOWED_ORIGINS` with your actual domains
- [ ] Set `FLASK_DEBUG=False`
- [ ] Enable HTTPS/SSL (required for HSTS header to work)
- [ ] Configure Redis for rate limiting (optional but recommended)
- [ ] Review and update Content-Security-Policy if needed
- [ ] Set up monitoring and logging
- [ ] Regular security audits and dependency updates

## Password Hash Generation

To generate a password hash for `MASTER_PASSWORD_HASH`:

```bash
# Linux/Mac
echo -n "your_password" | sha256sum

# Python
python3 -c "import hashlib; print(hashlib.sha256(b'your_password').hexdigest())"
```

## Token Management

- Tokens expire after 24 hours
- Tokens are stored in memory (will be lost on restart)
- For production, consider using:
  - Redis for distributed token storage
  - JWT tokens with signing keys
  - Session-based authentication with secure cookies

## HTTPS Configuration

The application includes HSTS headers that require HTTPS. When deploying:

1. Use a reverse proxy (nginx, Apache) with SSL/TLS certificates
2. Configure Let's Encrypt for free SSL certificates
3. Redirect all HTTP traffic to HTTPS

Example nginx configuration:
```nginx
server {
    listen 80;
    server_name yourdomain.com;
    return 301 https://$server_name$request_uri;
}

server {
    listen 443 ssl;
    server_name yourdomain.com;
    
    ssl_certificate /path/to/cert.pem;
    ssl_certificate_key /path/to/key.pem;
    
    location / {
        proxy_pass http://localhost:5000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }
}
```

## Security Best Practices

1. **Keep dependencies updated**: Regularly run `pip list --outdated`
2. **Monitor logs**: Watch for suspicious authentication attempts
3. **Backup data**: Regular MongoDB and SQLite backups
4. **Input validation**: All user inputs are validated (email, phone, team name)
5. **Rate limiting**: Protects against brute force and DoS attacks
6. **Error handling**: Generic error messages to avoid information leakage

## Reporting Security Issues

If you discover a security vulnerability, please:
1. Do NOT open a public issue
2. Email the security team directly
3. Include detailed steps to reproduce
4. Allow time for a fix before public disclosure

## Compliance Notes

- **GDPR**: User data is collected with consent (registration form)
- **Data retention**: Implement data deletion on request
- **Privacy policy**: Update to reflect data collection practices
- **Terms of service**: Include acceptable use policies

## Additional Recommendations

### For Enhanced Security:

1. **Implement 2FA**: Add two-factor authentication for admin access
2. **Audit logging**: Log all administrative actions
3. **Input sanitization**: Add additional XSS protection
4. **Database encryption**: Encrypt sensitive fields in MongoDB
5. **API rate limiting**: More aggressive limits for authentication endpoints
6. **CAPTCHA**: Add CAPTCHA to registration and login forms
7. **Password policy**: Enforce strong password requirements
8. **Regular penetration testing**: Schedule periodic security audits

### Monitoring and Alerts:

1. Set up alerts for:
   - Multiple failed authentication attempts
   - Unusual traffic patterns
   - Database errors or slow queries
   - Server resource exhaustion

2. Use tools like:
   - Sentry for error tracking
   - Prometheus + Grafana for metrics
   - ELK stack for log analysis

## License

This security documentation is part of the application and should be kept up-to-date with any security-related changes.
