# Migration Guide: Security Updates

## Overview

This guide helps you migrate from the old authentication system to the new secure implementation.

## Breaking Changes

### 1. Authentication Token Format

**Old System:**
- Token was the master password itself ("0022")
- Tokens never expired
- Password sent in plaintext

**New System:**
- Token is a secure random string (32 bytes, URL-safe)
- Tokens expire after 24 hours
- Password is hashed before comparison

### 2. Environment Variables

**Required Environment Variables:**

```bash
# MongoDB connection (REQUIRED)
MONGO_URI=mongodb://your-mongo-host:27017/

# Password hash (REQUIRED)
MASTER_PASSWORD_HASH=<sha256-hash-of-your-password>

# CORS origins (REQUIRED for production)
ALLOWED_ORIGINS=https://yourdomain.com,https://www.yourdomain.com
```

## Migration Steps

### Step 1: Generate Password Hash

If you want to keep using "0022" as the password:

```bash
echo -n "0022" | sha256sum
# Output: 1a089ed67ca61c641ce8b150c96e1a9c4c5d8c37c6f6d44bcf2e7f1e4b4f5d8a
```

Or choose a new, more secure password:

```bash
echo -n "your_secure_password" | sha256sum
```

### Step 2: Set Environment Variables

Create a `.env` file (copy from `.env.example`):

```bash
cp .env.example .env
```

Edit `.env` with your values:

```bash
MONGO_URI=mongodb://localhost:27017/
MASTER_PASSWORD_HASH=1a089ed67ca61c641ce8b150c96e1a9c4c5d8c37c6f6d44bcf2e7f1e4b4f5d8a
ALLOWED_ORIGINS=http://localhost:5000
FLASK_DEBUG=False
PORT=5000
```

### Step 3: Update Frontend Code

If you have custom frontend code that authenticates:

**Old code:**
```javascript
// Login
const response = await fetch('/key', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ password: '0022' })
});
const data = await response.json();
const token = data.token; // This was "0022"

// Use token
fetch('/teams', {
    headers: { 'X-Auth-Token': token } // Sent "0022"
});
```

**New code:**
```javascript
// Login (no changes needed in request)
const response = await fetch('/key', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ password: '0022' })
});
const data = await response.json();
const token = data.token; // Now a secure random token

// Use token (same as before)
fetch('/teams', {
    headers: { 'X-Auth-Token': token } // Now sends random token
});

// Note: Token expires after 24 hours, implement re-authentication
```

### Step 4: Update Deployment Configuration

**For systemd service:**

```ini
[Unit]
Description=ACM Tech Fest Application
After=network.target

[Service]
Type=simple
User=www-data
WorkingDirectory=/path/to/app
Environment="MONGO_URI=mongodb://localhost:27017/"
Environment="MASTER_PASSWORD_HASH=your_hash_here"
Environment="ALLOWED_ORIGINS=https://yourdomain.com"
Environment="FLASK_DEBUG=False"
ExecStart=/usr/bin/python3 app.py
Restart=always

[Install]
WantedBy=multi-user.target
```

**For Docker:**

```dockerfile
FROM python:3.9-slim

WORKDIR /app
COPY requirements.txt .
RUN pip install -r requirements.txt

COPY . .

# Environment variables should be passed at runtime
# docker run -e MONGO_URI=... -e MASTER_PASSWORD_HASH=...

EXPOSE 5000
CMD ["python", "app.py"]
```

### Step 5: Test the Migration

1. **Test authentication endpoint:**
```bash
curl -X POST http://localhost:5000/key \
  -H "Content-Type: application/json" \
  -d '{"password":"0022"}'
```

Expected response:
```json
{
  "success": true,
  "message": "Authentication successful",
  "token": "long_random_string_here"
}
```

2. **Test protected endpoint:**
```bash
TOKEN="token_from_previous_step"
curl http://localhost:5000/teams \
  -H "X-Auth-Token: $TOKEN"
```

3. **Test token expiration (wait 24 hours or test with modified code)**

## Backward Compatibility

The new system maintains API compatibility:
- Same endpoints
- Same request/response structure
- Only token format changed internally

However, stored tokens (if any) will NOT work with the new system. Users will need to re-authenticate.

## Security Improvements Summary

1. ✅ No more hardcoded passwords
2. ✅ Passwords are hashed (SHA-256)
3. ✅ Secure random token generation
4. ✅ Token expiration (24 hours)
5. ✅ CORS restrictions
6. ✅ Security headers enabled
7. ✅ Debug mode disabled by default
8. ✅ Environment-based configuration

## Troubleshooting

### "MONGO_URI must be set in environment variables"

**Solution:** Set the MONGO_URI environment variable:
```bash
export MONGO_URI="mongodb://localhost:27017/"
```

### "Invalid password" with correct password

**Solution:** Verify your password hash:
```bash
echo -n "0022" | sha256sum
# Compare with MASTER_PASSWORD_HASH
```

### CORS errors in browser

**Solution:** Add your frontend domain to ALLOWED_ORIGINS:
```bash
export ALLOWED_ORIGINS="http://localhost:3000,https://yourdomain.com"
```

### Tokens keep expiring

**Solution:** This is expected behavior (24-hour expiration). Implement token refresh or re-authentication in your frontend.

## Rolling Back (Emergency Only)

If you need to temporarily roll back:

1. Checkout the previous commit:
```bash
git checkout <previous-commit-hash>
```

2. Restart the application

**Warning:** This removes all security improvements and is NOT recommended.

## Support

For issues or questions:
1. Check the SECURITY.md documentation
2. Review the .env.example file
3. Check application logs for detailed error messages

## Next Steps

After successful migration:
1. Monitor logs for authentication attempts
2. Consider implementing 2FA
3. Set up monitoring and alerts
4. Schedule regular security audits
5. Update password to something more secure than "0022"
