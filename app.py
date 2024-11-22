from flask import Flask, request, jsonify
import requests
import smtplib
from email.mime.text import MIMEText
import os
from functools import wraps
import logging
import logging.config
import re

# Configuration du logging
LOGGING_CONFIG = {
    'version': 1,
    'disable_existing_loggers': False,
    'formatters': {
        'standard': {
            'format': '%(asctime)s [%(levelname)s] %(name)s: %(message)s'
        },
        'detailed': {
            'format': '%(asctime)s [%(levelname)s] %(name)s:%(lineno)d: %(message)s'
        }
    },
    'handlers': {
        'console': {
            'class': 'logging.StreamHandler',
            'level': 'DEBUG',
            'formatter': 'standard',
            'stream': 'ext://sys.stdout'
        },
        'file': {
            'class': 'logging.handlers.RotatingFileHandler',
            'level': 'DEBUG',
            'formatter': 'detailed',
            'filename': 'app.log',
            'maxBytes': 10485760,
            'backupCount': 5
        }
    },
    'loggers': {
        '': {
            'handlers': ['console', 'file'],
            'level': 'DEBUG',
            'propagate': True
        },
        'werkzeug': {
            'handlers': ['console'],
            'level': 'ERROR',
            'propagate': False
        }
    }
}

logging.config.dictConfig(LOGGING_CONFIG)
logger = logging.getLogger(__name__)

app = Flask(__name__)

class Config:
    ACCOUNT_ID = os.getenv('KEYGEN_ACCOUNT_ID')
    PRODUCT_TOKEN = os.getenv('KEYGEN_PRODUCT_TOKEN')
    SMTP_SERVER = os.getenv('SMTP_SERVER')
    SMTP_PORT = int(os.getenv('SMTP_PORT', 587))
    EMAIL_USER = os.getenv('EMAIL_USER')
    EMAIL_PASSWORD = os.getenv('EMAIL_PASSWORD')
    TRIAL_POLICY_ID = os.getenv('KEYGEN_TRIAL_POLICY_ID')
    STANDALONE_POLICY_ID = os.getenv('KEYGEN_STANDALONE_POLICY_ID')

class KeygenError(Exception):
    """Exception personnalisée pour les erreurs Keygen."""
    pass

def validate_email(email):
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    if not re.match(pattern, email):
        raise ValueError("Invalid email format")
    return True

def validate_smtp_config():
    required_configs = ['SMTP_SERVER', 'SMTP_PORT', 'EMAIL_USER', 'EMAIL_PASSWORD']
    missing = [config for config in required_configs if not getattr(Config, config)]
    if missing:
        raise ValueError(f"Missing SMTP configuration: {', '.join(missing)}")

def test_smtp_connection():
    try:
        with smtplib.SMTP(Config.SMTP_SERVER, Config.SMTP_PORT, timeout=5) as server:
            server.starttls()
            server.login(Config.EMAIL_USER, Config.EMAIL_PASSWORD)
            return True
    except Exception as e:
        logger.error(f"SMTP Connection test failed: {str(e)}")
        return False

class KeygenAPI:
    BASE_URL = "https://api.keygen.sh/v1/accounts"
    
    @staticmethod
    def get_headers():
        return {
            "Authorization": f"Bearer {Config.PRODUCT_TOKEN}",
            "Accept": "application/vnd.api+json",
            "Content-Type": "application/vnd.api+json"
        }

    @staticmethod
    def handle_response(response):
        if response.status_code == 422:
            error_data = response.json()
            error_message = error_data.get('errors', [{}])[0].get('detail', 'Validation error')
            raise KeygenError(f"Validation error: {error_message}")
            
        try:
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            error_message = "Unknown error"
            if response.content:
                try:
                    error_data = response.json()
                    error_message = error_data.get('errors', [{}])[0].get('detail', 'Unknown error')
                except:
                    error_message = response.text
            logger.error(f"Keygen API error: {error_message}")
            raise KeygenError(f"Keygen API error: {error_message}")

    @staticmethod
    def get_policy_id(license_type):
        if license_type.lower() not in ['trial', 'standalone']:
            raise ValueError("Invalid license type. Must be 'trial' or 'standalone'")
        return Config.TRIAL_POLICY_ID if license_type.lower() == 'trial' else Config.STANDALONE_POLICY_ID

    @staticmethod
    def get_user_by_email(email):
        """Récupère un utilisateur par son email."""
        logger.info(f"Looking up user with email: {email}")
        url = f"{KeygenAPI.BASE_URL}/{Config.ACCOUNT_ID}/users"
        params = {'email': email}
        
        response = requests.get(
            url=url,
            params=params,
            headers=KeygenAPI.get_headers()
        )
        
        try:
            response_data = KeygenAPI.handle_response(response)
            users = response_data.get('data', [])
            return users[0] if users else None
        except KeygenError:
            return None

    @staticmethod
    def create_user(first_name, last_name, email):
        """Crée un nouvel utilisateur dans Keygen."""
        logger.info(f"Creating user for {email}")
        url = f"{KeygenAPI.BASE_URL}/{Config.ACCOUNT_ID}/users"
        
        payload = {
            "data": {
                "type": "users",
                "attributes": {
                    "first-name": first_name,
                    "last-name": last_name,
                    "email": email
                }
            }
        }
        
        response = requests.post(
            url=url,
            json=payload,
            headers=KeygenAPI.get_headers()
        )
        
        return KeygenAPI.handle_response(response)

    @staticmethod
    def create_license(user_id, license_type):
        """Crée une nouvelle licence pour l'utilisateur."""
        logger.info(f"Creating {license_type} license for user {user_id}")
        url = f"{KeygenAPI.BASE_URL}/{Config.ACCOUNT_ID}/licenses"
        
        license_attrs = {
            "name": f"License for {user_id}"
        }
        
        if license_type.lower() == 'trial':
            license_attrs["expiry"] = "30d"
        
        payload = {
            "data": {
                "type": "licenses",
                "attributes": license_attrs,
                "relationships": {
                    "policy": {
                        "data": {
                            "type": "policies",
                            "id": KeygenAPI.get_policy_id(license_type)
                        }
                    },
                    "user": {
                        "data": {
                            "type": "users",
                            "id": user_id
                        }
                    }
                }
            }
        }
        
        response = requests.post(
            url=url,
            json=payload,
            headers=KeygenAPI.get_headers()
        )
        
        return KeygenAPI.handle_response(response)

    @staticmethod
    def get_user_licenses(user_id):
        """Récupère toutes les licences d'un utilisateur."""
        logger.info(f"Getting licenses for user: {user_id}")
        url = f"{KeygenAPI.BASE_URL}/{Config.ACCOUNT_ID}/licenses"
        params = {'user': user_id}
        
        response = requests.get(
            url=url,
            params=params,
            headers=KeygenAPI.get_headers()
        )
        
        try:
            response_data = KeygenAPI.handle_response(response)
            return response_data.get('data', [])
        except KeygenError:
            logger.error(f"Failed to get licenses for user {user_id}")
            return []

def send_license_email(email, license_key, is_trial=True):
    try:
        validate_smtp_config()
        
        subject = "Welcome to StoryboardMaker Pro - Your License Key"
        body = f"""
Dear StoryboardMaker Pro User,

Thank you for choosing StoryboardMaker Pro! I'm excited to have you join our community of creative professionals.

Here's your license key to get started:

    {license_key}

{'Your trial license is valid for 30 days, giving you full access to explore all premium features.' if is_trial else 'Your license has been activated with full access to all premium features.'}

Getting Started:
1. Launch StoryboardMaker Pro
2. Click on 'Enter License' in the settings menu
3. Copy and paste your license key
4. Start creating amazing storyboards!

Key Features You Can Now Access:
• Professional template library
• Advanced export options
• Custom panel layouts
• High-resolution exports
• And much more!

Need Help?
If you have any questions or need assistance, don't hesitate to contact our support team at storyboardmakerpro@dityan.com

{'Make the most of your 30-day trial! We hope StoryboardMaker Pro helps bring your visual stories to life.' if is_trial else 'We hope StoryboardMaker Pro helps bring your visual stories to life.'}

Best regards,
The StoryboardMaker Pro Creator

Note: Please keep this email for your records. Your license key may be needed for future reinstallations.
        """
        
        msg = MIMEText(body)
        msg['Subject'] = subject
        msg['From'] = Config.EMAIL_USER
        msg['To'] = email

        with smtplib.SMTP(Config.SMTP_SERVER, Config.SMTP_PORT) as server:
            server.ehlo()
            server.starttls()
            server.ehlo()
            server.login(Config.EMAIL_USER, Config.EMAIL_PASSWORD)
            server.sendmail(Config.EMAIL_USER, email, msg.as_string())
            logger.info(f"License email sent to {email}")
            return True
    except Exception as e:
        logger.error(f"Failed to send license email: {str(e)}")
        return False

def validate_json_payload(*required_fields):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not request.is_json:
                return jsonify({"success": False, "error": "Content-Type must be application/json"}), 415
            
            data = request.get_json()
            missing_fields = [field for field in required_fields if field not in data]
            
            if missing_fields:
                return jsonify({
                    "success": False,
                    "error": "Missing required fields",
                    "fields": missing_fields
                }), 400
                
            return f(*args, **kwargs)
        return decorated_function
    return decorator

@app.route('/register', methods=['POST'])
@validate_json_payload('first_name', 'last_name', 'email')
def register():
    try:
        data = request.get_json()
        
        # Validation des données
        validate_email(data['email'])
        if not all([data['first_name'].strip(), data['last_name'].strip()]):
            return jsonify({
                "success": False,
                "error": "First name and last name cannot be empty"
            }), 400

        # Vérifier si l'utilisateur existe
        existing_user = KeygenAPI.get_user_by_email(data['email'])
        
        if existing_user:
            user_id = existing_user['id']
            # Vérifier les licences existantes
            existing_licenses = KeygenAPI.get_user_licenses(user_id)
            active_license = next((lic for lic in existing_licenses if lic['attributes']['status'] == 'active'), None)
            
            if active_license:
                return jsonify({
                    "success": True,
                    "message": "Existing license found",
                    "licenseKey": active_license['attributes']['key']
                }), 200
        else:
            # Créer nouvel utilisateur
            user_result = KeygenAPI.create_user(
                data['first_name'],
                data['last_name'],
                data['email']
            )
            user_id = user_result['data']['id']

        # Créer nouvelle licence
        license_result = KeygenAPI.create_license(user_id, 'trial')
        license_key = license_result['data']['attributes']['key']

        # Envoyer email
        email_sent = send_license_email(data['email'], license_key, is_trial=True)

        return jsonify({
            "success": True,
            "licenseKey": license_key,
            "emailSent": email_sent
        }), 201

    except ValueError as e:
        return jsonify({
            "success": False,
            "error": str(e)
        }), 400
    except KeygenError as e:
        return jsonify({
            "success": False,
            "error": str(e)
        }), 400
    except Exception as e:
        logger.error(f"Unexpected error: {str(e)}", exc_info=True)
        return jsonify({
            "success": False,
            "error": "An unexpected error occurred"
        }), 500

@app.errorhandler(404)
def not_found_error(error):
    return jsonify({
        "success": False,
        "error": "Resource not found"
    }), 404

@app.errorhandler(500)
def internal_error(error):
    logger.error(f"500 Error: {str(error)}")
    return jsonify({
        "success": False,
        "error": "Internal server error"
    }), 500

@app.before_request
def log_request_info():
    logger.debug('Request Method: %s', request.method)
    logger.debug('Request URL: %s', request.url)
    logger.debug('Request Path: %s', request.path)
    logger.debug('Headers:')
    for header, value in request.headers.items():
        logger.debug('    %s: %s', header, value)
    if request.get_data():
        try:
            if request.is_json:
                logger.debug('Request JSON Body: %s', request.get_json())
            else:
                logger.debug('Request Body: %s', request.get_data().decode('utf-8'))
        except Exception as e:
            logger.warning('Could not decode request body: %s', str(e))

@app.after_request
def log_response_info(response):
    logger.debug('Response Status: %s', response.status)
    logger.debug('Response Headers:')
    for header, value in response.headers.items():
        logger.debug('    %s: %s', header, value)
    return response

if __name__ == '__main__':
    logger.info("Starting Flask application")
    app.run(host='0.0.0.0', port=5000)