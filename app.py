from flask import Flask, request, jsonify, render_template
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from pymongo import MongoClient
import re
import os
import sqlite3
import json
from datetime import datetime
import logging
import secrets
import hashlib

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = Flask(__name__)

# Configure CORS with specific origins (update with your actual domains)
ALLOWED_ORIGINS = os.environ.get('ALLOWED_ORIGINS', '*').split(',')
CORS(app, origins=ALLOWED_ORIGINS, supports_credentials=True)

limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["200 per day", "50 per hour"],
    storage_uri="memory://",
)

# MongoDB setup
MONGO_URI = os.environ.get('MONGO_URI')
if not MONGO_URI:
    logger.error("MONGO_URI environment variable is not set")
    raise ValueError("MONGO_URI must be set in environment variables")

DB_NAME = 'astrisk_tournament'
client = MongoClient(MONGO_URI)
db = client[DB_NAME]
registrations = db.registrations

# Master password from environment variable (hashed)
MASTER_PASSWORD_HASH = os.environ.get('MASTER_PASSWORD_HASH')
if not MASTER_PASSWORD_HASH:
    logger.warning("MASTER_PASSWORD_HASH not set, generating temporary hash for '0022'")
    # For backwards compatibility, hash the old password
    MASTER_PASSWORD_HASH = hashlib.sha256("0022".encode()).hexdigest()

# Store active tokens with expiration (in-memory for simplicity)
# In production, use Redis or database
active_tokens = {}

registrations.create_index([("team_name", 1)], unique=True)
registrations.create_index([("members.email", 1)], unique=True, sparse=True)
registrations.create_index([("timestamp", 1)], expireAfterSeconds=8640000)

# remove last create_index

registrations.drop_index([("timestamp", 1)])

# Security headers middleware
@app.after_request
def add_security_headers(response):
    """Add security headers to all responses"""
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    response.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'self' 'unsafe-inline' https://cdn.tailwindcss.com https://fonts.googleapis.com; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com https://fonts.cdnfonts.com; font-src 'self' https://fonts.gstatic.com https://fonts.cdnfonts.com; img-src 'self' data: https:; connect-src 'self'"
    return response

def hash_password(password):
    """Hash password using SHA-256"""
    return hashlib.sha256(password.encode()).hexdigest()

def generate_token():
    """Generate a secure random token"""
    return secrets.token_urlsafe(32)

def verify_token(token):
    """Verify if token is valid and not expired"""
    if not token:
        return False
    token_data = active_tokens.get(token)
    if not token_data:
        return False
    # Check if token is expired (24 hours)
    if (datetime.utcnow() - token_data['created_at']).total_seconds() > 86400:
        del active_tokens[token]
        return False
    return True

# SQLite setup (backup database)
SQLITE_DB = 'registrations_backup.db'

def init_sqlite():
    """Initialize SQLite database with required tables"""
    conn = sqlite3.connect(SQLITE_DB)
    cursor = conn.cursor()
    
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS registrations (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            registration_id TEXT UNIQUE NOT NULL,
            team_name TEXT UNIQUE NOT NULL,
            college_name TEXT,
            lead_name TEXT NOT NULL,
            lead_email TEXT NOT NULL,
            lead_contact TEXT NOT NULL,
            members TEXT NOT NULL,
            substitute TEXT,
            ip_address TEXT,
            timestamp TEXT NOT NULL,
            payment_status TEXT NOT NULL,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    cursor.execute('''
        CREATE INDEX IF NOT EXISTS idx_team_name ON registrations(team_name)
    ''')
    
    cursor.execute('''
        CREATE INDEX IF NOT EXISTS idx_payment_status ON registrations(payment_status)
    ''')
    
    cursor.execute('''
        CREATE INDEX IF NOT EXISTS idx_registration_id ON registrations(registration_id)
    ''')
    
    conn.commit()
    conn.close()
    logger.info("SQLite backup database initialized")

# Initialize SQLite on startup
init_sqlite()

def save_to_sqlite(registration_data):
    """Save registration data to SQLite as backup"""
    try:
        conn = sqlite3.connect(SQLITE_DB)
        cursor = conn.cursor()
        
        # Serialize members and substitute as JSON
        members_json = json.dumps(registration_data['members'])
        substitute_json = json.dumps(registration_data.get('substitute', {}))
        
        cursor.execute('''
            INSERT INTO registrations 
            (registration_id, team_name, college_name, lead_name, lead_email, lead_contact, 
             members, substitute, ip_address, timestamp, payment_status)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            registration_data['registration_id'],
            registration_data['team_name'],
            registration_data.get('college_name', ''),
            registration_data['lead']['name'],
            registration_data['lead']['email'],
            registration_data['lead']['contact'],
            members_json,
            substitute_json,
            registration_data.get('ip_address', ''),
            registration_data['timestamp'].isoformat() if isinstance(registration_data['timestamp'], datetime) else str(registration_data['timestamp']),
            registration_data['payment_status']
        ))
        
        conn.commit()
        conn.close()
        logger.info(f"Registration backed up to SQLite: {registration_data['team_name']}")
        return True
    except sqlite3.IntegrityError as e:
        logger.warning(f"SQLite backup failed (duplicate): {str(e)}")
        return False
    except Exception as e:
        logger.error(f"SQLite backup error: {str(e)}")
        return False

def update_payment_sqlite(team_name, new_status):
    """Update payment status in SQLite backup"""
    try:
        conn = sqlite3.connect(SQLITE_DB)
        cursor = conn.cursor()
        
        cursor.execute('''
            UPDATE registrations 
            SET payment_status = ?
            WHERE team_name = ?
        ''', (new_status, team_name))
        
        conn.commit()
        rows_affected = cursor.rowcount
        conn.close()
        
        if rows_affected > 0:
            logger.info(f"SQLite backup updated: {team_name} -> {new_status}")
            return True
        return False
    except Exception as e:
        logger.error(f"SQLite update error: {str(e)}")
        return False

def validate_email(email):
    """Validate email format"""
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return re.match(pattern, email) is not None

def validate_phone(phone):
    """Validate Indian phone number"""
    pattern = r'^[6-9]\d{9}$'
    return re.match(pattern, phone) is not None

def validate_team_name(team_name):
    """Validate team name"""
    if len(team_name) < 3 or len(team_name) > 50:
        return False
    pattern = r'^[a-zA-Z0-9\s\-_\.]+$'
    return re.match(pattern, team_name) is not None

def check_duplicate_emails(emails):
    """Check if any email is already registered"""
    for email in emails:
        if registrations.find_one({
            "$or": [
                {"members.email": email},
                {"substitute.email": email}
            ],
            "payment_status": "completed"
        }):
            return True, email
    return False, None

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/register', methods=['POST'])
@limiter.limit("5 per minute")
def register_team():
    try:
        data = request.get_json()
        
        required_fields = ['team_name', 'lead', 'members']
        for field in required_fields:
            if field not in data:
                return jsonify({
                    'success': False,
                    'message': f'Missing required field: {field}'
                }), 400

        team_name = data['team_name'].strip()
        college_name = data.get('college_name', '').strip()
        lead = data['lead']
        members = data['members']
        substitute = data.get('substitute', {})

        if not validate_team_name(team_name):
            return jsonify({
                'success': False,
                'message': 'Invalid team name. Only alphanumeric characters, spaces, hyphens, underscores, and dots are allowed (3-50 characters).'
            }), 400

        if registrations.find_one({"team_name": team_name, "payment_status": "completed"}):
            return jsonify({
                'success': False,
                'message': 'Team name already taken. Please choose a different name.'
            }), 400

        if not all([lead.get('name'), lead.get('email'), lead.get('contact')]):
            return jsonify({
                'success': False,
                'message': 'All team lead fields are required'
            }), 400

        if not validate_email(lead['email']):
            return jsonify({
                'success': False,
                'message': 'Invalid team lead email format'
            }), 400

        if not validate_phone(lead['contact']):
            return jsonify({
                'success': False,
                'message': 'Invalid team lead phone number. Must be a valid 10-digit Indian number.'
            }), 400

        # Check team size: minimum 4 members (excluding lead and substitute)
        # Team structure: 1 lead + 4 members + 1 optional substitute = 6 total
        if len(members) < 4:
            return jsonify({
                'success': False,
                'message': 'Minimum 4 team members required (excluding team lead and substitute)'
            }), 400

        if len(members) > 5:
            return jsonify({
                'success': False,
                'message': 'Maximum 5 team members allowed (4 required + 1 optional substitute in separate field)'
            }), 400

        all_emails = [lead['email']]
        member_emails = []

        for i, member in enumerate(members, 1):
            if not all([member.get('name'), member.get('email'), member.get('contact')]):
                return jsonify({
                    'success': False,
                    'message': f'All fields for team member {i} are required'
                }), 400

            if not validate_email(member['email']):
                return jsonify({
                    'success': False,
                    'message': f'Invalid email format for team member {i}'
                }), 400

            if not validate_phone(member['contact']):
                return jsonify({
                    'success': False,
                    'message': f'Invalid phone number for team member {i}. Must be a valid 10-digit Indian number.'
                }), 400

            all_emails.append(member['email'])
            member_emails.append(member['email'])

        if substitute and any([substitute.get('name'), substitute.get('email'), substitute.get('contact')]):
            if not all([substitute.get('name'), substitute.get('email'), substitute.get('contact')]):
                return jsonify({
                    'success': False,
                    'message': 'All substitute fields must be filled if any are provided'
                }), 400

            if not validate_email(substitute['email']):
                return jsonify({
                    'success': False,
                    'message': 'Invalid substitute email format'
                }), 400

            if not validate_phone(substitute['contact']):
                return jsonify({
                    'success': False,
                    'message': 'Invalid substitute phone number. Must be a valid 10-digit Indian number.'
                }), 400

            all_emails.append(substitute['email'])

        is_duplicate, duplicate_email = check_duplicate_emails(all_emails)
        if is_duplicate:
            return jsonify({
                'success': False,
                'message': f'Email {duplicate_email} is already registered in another team'
            }), 400

        all_contacts = [lead['contact']] + [m['contact'] for m in members]
        if substitute and substitute.get('contact'):
            all_contacts.append(substitute['contact'])

        if len(all_contacts) != len(set(all_contacts)):
            return jsonify({
                'success': False,
                'message': 'Duplicate phone numbers found. Each team member must have a unique phone number.'
            }), 400

        registration_data = {
            'team_name': team_name,
            'college_name': college_name,
            'lead': {
                'name': lead['name'].strip(),
                'email': lead['email'].lower().strip(),
                'contact': lead['contact'].strip()
            },
            'members': [{
                'name': member['name'].strip(),
                'email': member['email'].lower().strip(),
                'contact': member['contact'].strip()
            } for member in members],
            'substitute': {
                'name': substitute.get('name', '').strip(),
                'email': substitute.get('email', '').lower().strip(),
                'contact': substitute.get('contact', '').strip()
            } if substitute and substitute.get('name') else {},
            'ip_address': get_remote_address(),
            'timestamp': datetime.utcnow(),
            'payment_status': 'pending',
            'registration_id': f"AST{datetime.utcnow().strftime('%Y%m%d%H%M%S')}"
        }

        # Save to MongoDB (primary)
        try:
            registrations.insert_one(registration_data)
            logger.info(f"New registration: {team_name} from IP {get_remote_address()}")
        except Exception as mongo_error:
            logger.error(f"MongoDB error: {str(mongo_error)}")
            return jsonify({
                'success': False,
                'message': 'Database error. Please try again.'
            }), 500
        
        # Save to SQLite (backup) - non-blocking
        save_to_sqlite(registration_data)

        return jsonify({
            'success': True,
            'message': 'Registration successful! Proceeding to payment...',
            'registration_id': registration_data['registration_id'],
            'team_name': team_name,
            'total_members': len(members) + 1 + (1 if registration_data['substitute'] else 0),
            'amount': 600
        }), 200

    except Exception as e:
        logger.error(f"Registration error: {str(e)}")
        return jsonify({
            'success': False,
            'message': 'Internal server error. Please try again later.'
        }), 500

@app.route('/teams', methods=['GET'])
@limiter.limit("10 per minute")
def get_teams():
    try:
        # Check if request is authenticated using the new token system
        auth_header = request.headers.get('X-Auth-Token', '')
        is_authenticated = verify_token(auth_header)
        
        teams = []
        for reg in registrations.find(
            {},
            {
                "_id": 0,
                "team_name": 1,
                "college_name": 1,
                "lead.name": 1,
                "lead.contact": 1,
                "members.name": 1,
                "members.contact": 1,
                "substitute.name": 1,
                "substitute.contact": 1,
                "payment_status": 1,
            },
        ).sort("timestamp", -1):
            # Mask phone numbers and names if not authenticated
            def mask_phone(phone):
                if not phone or not is_authenticated:
                    return "••••••••••"
                return phone
            
            def mask_name(name):
                if not name or not is_authenticated:
                    return "••••••••"
                return name
            
            # Get substitute data
            substitute_data = reg.get("substitute", {})
            substitute = None
            if substitute_data and substitute_data.get("name"):
                substitute = {
                    "name": mask_name(substitute_data.get("name")),
                    "contact": mask_phone(substitute_data.get("contact"))
                }
            
            team_info = {
                "team_name": reg.get("team_name"),
                "college_name": reg.get("college_name"),
                "lead": {
                    "name": mask_name(reg.get("lead", {}).get("name")),
                    "contact": mask_phone(reg.get("lead", {}).get("contact"))
                },
                "members": [
                    {
                        "name": mask_name(m.get("name")), 
                        "contact": mask_phone(m.get("contact"))
                    }
                    for m in reg.get("members", [])
                ],
                "substitute": substitute,
                "payment_status": reg.get("payment_status"),
            }
            teams.append(team_info)
        return jsonify({"success": True, "teams": teams}), 200
    except Exception as e:
        logger.error(f"Teams fetch error: {str(e)}")
        return jsonify({"success": False, "message": "Internal server error"}), 500

@app.route('/health', methods=['GET'])
def health_check():
    return jsonify({'status': 'healthy', 'timestamp': datetime.utcnow().isoformat()})


@app.route('/key', methods=['POST'])
@limiter.limit("10 per minute")
def verify_key():
    """Verify master password for teams page access"""
    try:
        data = request.get_json()
        password = data.get('password', '')
        
        # Hash the provided password and compare with stored hash
        password_hash = hash_password(password)
        
        if password_hash == MASTER_PASSWORD_HASH:
            # Generate a secure token instead of returning the password
            token = generate_token()
            active_tokens[token] = {
                'created_at': datetime.utcnow(),
                'ip_address': get_remote_address()
            }
            
            logger.info(f"Successful authentication from IP {get_remote_address()}")
            
            return jsonify({
                'success': True, 
                'message': 'Authentication successful',
                'token': token
            }), 200
        else:
            logger.warning(f"Failed authentication attempt from IP {get_remote_address()}")
            return jsonify({'success': False, 'message': 'Invalid password'}), 401
    except Exception as e:
        logger.error(f"Key verification error: {str(e)}")
        return jsonify({'success': False, 'message': 'Internal server error'}), 500


@app.route('/update-payment', methods=['POST'])
@limiter.limit("20 per minute")
def update_payment_status():
    """Update payment status of a team (requires authentication)"""
    try:
        # Check authentication using the new token system
        auth_header = request.headers.get('X-Auth-Token', '')
        
        if not verify_token(auth_header):
            logger.warning(f"Unauthorized payment update attempt from IP {get_remote_address()}")
            return jsonify({'success': False, 'message': 'Unauthorized'}), 401
        
        data = request.get_json()
        team_name = data.get('team_name', '').strip()
        new_status = data.get('status', '').strip()
        
        if not team_name:
            return jsonify({'success': False, 'message': 'Team name is required'}), 400
        
        if new_status not in ['pending', 'completed']:
            return jsonify({'success': False, 'message': 'Invalid status. Must be "pending" or "completed"'}), 400
        
        # Update MongoDB (primary)
        result = registrations.update_one(
            {'team_name': team_name},
            {'$set': {'payment_status': new_status}}
        )
        
        if result.matched_count == 0:
            return jsonify({'success': False, 'message': 'Team not found'}), 404
        
        # Update SQLite (backup) - non-blocking
        update_payment_sqlite(team_name, new_status)
        
        logger.info(f"Payment status updated for team '{team_name}' to '{new_status}' by admin")
        
        if result.modified_count == 0:
            return jsonify({
                'success': True, 
                'message': f'Payment status is already set to "{new_status}"'
            }), 200
        
        return jsonify({
            'success': True, 
            'message': f'Payment status updated to "{new_status}" successfully'
        }), 200
        
    except Exception as e:
        logger.error(f"Payment update error: {str(e)}")
        return jsonify({'success': False, 'message': 'Internal server error'}), 500

if __name__ == '__main__':
    # Use debug mode only in development, controlled by environment variable
    debug_mode = os.environ.get('FLASK_DEBUG', 'False').lower() in ('true', '1', 't')
    port = int(os.environ.get('PORT', 5000))
    
    if debug_mode:
        logger.warning("Running in DEBUG mode - not suitable for production!")
    
    app.run(debug=debug_mode, host='0.0.0.0', port=port)
