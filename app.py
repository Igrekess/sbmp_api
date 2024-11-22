from flask import Flask, request, jsonify
import requests
import smtplib
from email.mime.text import MIMEText
import os
from functools import wraps
import logging
import logging.config
import re
from http import HTTPStatus

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
            'level': 'WARNING',
            'propagate': True
        },
        'werkzeug': {
            'handlers': ['console'],
            'level': 'WARNING',
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
    ENTERPRISE6_POLICY_ID = os.getenv('KEYGEN_ENTERPRISE6_POLICY_ID')
    ENTERPRISE10_POLICY_ID = os.getenv('KEYGEN_ENTERPRISE10_POLICY_ID')  
    ENTERPRISE20_POLICY_ID = os.getenv('KEYGEN_ENTERPRISE20_POLICY_ID')

class KeygenError(Exception):
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
        logger.warning(f"Missing SMTP configuration: {', '.join(missing)}. Email sending will be disabled.")
        return False
    return True

def test_smtp_connection():
    if not validate_smtp_config():
        return False
    
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
        policy_id_map = {
            'trial': Config.TRIAL_POLICY_ID,
            'standalone': Config.STANDALONE_POLICY_ID,
            'enterprise6': Config.ENTERPRISE6_POLICY_ID,
            'enterprise10': Config.ENTERPRISE10_POLICY_ID,
            'enterprise20': Config.ENTERPRISE20_POLICY_ID
        }
        if license_type.lower() not in policy_id_map:
            raise ValueError("Invalid license type. Must be one of 'trial', 'standalone', 'enterprise6', 'enterprise10', 'enterprise20'")
        return policy_id_map[license_type.lower()]

    @staticmethod
    def get_user_by_email(email):
        url = f"{KeygenAPI.BASE_URL}/{Config.ACCOUNT_ID}/users"
        params = {'email': email}
        
        try:
            response = requests.get(
                url=url,
                params=params,
                headers=KeygenAPI.get_headers()
            )
            response_data = KeygenAPI.handle_response(response)
            users = response_data.get('data', [])
            
            for user in users:
                if user.get('attributes', {}).get('email') == email:
                    return user
            return None
            
        except KeygenError:
            return None

    @staticmethod
    def create_user(first_name, last_name, email):
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
    def create_license(user_id, policy_id, first_name, last_name):
        url = f"https://api.keygen.sh/v1/accounts/{Config.ACCOUNT_ID}/licenses"
        
        headers = {
            "Authorization": f"Bearer {Config.PRODUCT_TOKEN}",
            "Content-Type": "application/json"
        }
        
        payload = {
            "data": {
                "type": "licenses",
                "attributes": {
                    "metadata": {
                        "first_name": first_name,
                        "last_name": last_name
                    }
                },
                "relationships": {
                    "policy": {"data": {"type": "policies", "id": policy_id}},
                    "user": {"data": {"type": "users", "id": user_id}}
                }
            }
        }
        
        response = requests.post(url, json=payload, headers=headers)
        if response.status_code == 201:
            return response.json()
        raise KeygenError(f"Failed to create license: {response.text}")

    @staticmethod
    def get_license_id_by_key(license_key):
        url = f"{KeygenAPI.BASE_URL}/{Config.ACCOUNT_ID}/licenses"
        params = {'key': license_key}
        
        try:
            response = requests.get(
                url=url,
                params=params,
                headers=KeygenAPI.get_headers()
            )
            response_data = KeygenAPI.handle_response(response)
            licenses = response_data.get('data', [])
            
            if licenses:
                logger.debug(f"License ID for key {license_key}: {licenses[0]['id']}")
                return licenses[0]['id']
            else:
                logger.error(f"No license found for key {license_key}")
                return None
            
        except KeygenError as e:
            logger.error(f"Error getting license ID for key {license_key}: {str(e)}")
            return None

    @staticmethod
    def validate_license(license_key, fingerprint, email):
        """Valide une licence avec la clé via Keygen API
        
        Args:
            license_key (str): Clé de licence à valider
            fingerprint (str): Empreinte machine
            email (str): Email de l'utilisateur
        """
        url = f"https://api.keygen.sh/v1/accounts/{Config.ACCOUNT_ID}/licenses/actions/validate-key"
        
        headers = {
            "Authorization": f"Bearer {Config.PRODUCT_TOKEN}",
            "Content-Type": "application/json"
        }
        
        payload = {
            "meta": {
                "key": license_key,
                "fingerprint": fingerprint,
                "email": email
            }
        }
        
        try:
            response = requests.post(url, json=payload, headers=headers)
            response_data = response.json()
            
            if response.status_code == 200:
                # Récupérer les informations de la licence
                license_data = response_data.get('data', {})
                policy_id = license_data.get('relationships', {}).get('policy', {}).get('data', {}).get('id')
                
                # Mapping des types de licence
                policy_mapping = {
                    Config.TRIAL_POLICY_ID: {'type': 'trial', 'max_machines': 1},
                    Config.STANDALONE_POLICY_ID: {'type': 'standalone', 'max_machines': 2},
                    Config.ENTERPRISE6_POLICY_ID: {'type': 'enterprise6', 'max_machines': 6},
                    Config.ENTERPRISE10_POLICY_ID: {'type': 'enterprise10', 'max_machines': 10},
                    Config.ENTERPRISE20_POLICY_ID: {'type': 'enterprise20', 'max_machines': 20}
                }
                
                license_info = policy_mapping.get(policy_id, {'type': 'unknown', 'max_machines': 0})
                
                return {
                    "success": True,
                    "licenseType": license_info['type'],
                    "expiry": license_data.get('attributes', {}).get('expiry'),
                    "machinesRemaining": license_info['max_machines']
                }
            else:
                error_msg = response_data.get('errors', [{'detail': 'Validation failed'}])[0]['detail']
                logger.error(f"License validation failed: {error_msg}")
                return {"success": False, "error": error_msg}
                
        except Exception as e:
            logger.error(f"License validation request failed: {str(e)}")
            return {"success": False, "error": "Validation request failed"}

    @staticmethod
    def create_machine(license_id, fingerprint):
        url = f"https://api.keygen.sh/v1/accounts/{Config.ACCOUNT_ID}/machines"
        
        headers = {
            "Authorization": f"Bearer {Config.PRODUCT_TOKEN}",
            "Content-Type": "application/json"
        }
        
        payload = {
            "data": {
                "type": "machines",
                "attributes": {
                    "fingerprint": fingerprint,
                    "platform": "macOS"
                },
                "relationships": {
                    "license": {
                        "data": {"type": "licenses", "id": license_id}
                    }
                }
            }
        }
        
        response = requests.post(url, json=payload, headers=headers)
        if response.status_code == 201:
            return response.json()
        raise KeygenError(f"Failed to create machine: {response.text}")

    @staticmethod
    def is_fingerprint_registered(license_id, fingerprint):
        url = f"{KeygenAPI.BASE_URL}/{Config.ACCOUNT_ID}/machines"
        params = {'license': license_id}
        
        try:
            response = requests.get(
                url=url,
                params=params,
                headers=KeygenAPI.get_headers()
            )
            response_data = KeygenAPI.handle_response(response)
            machines = response_data.get('data', [])
            
            for machine in machines:
                if machine.get('attributes', {}).get('fingerprint') == fingerprint:
                    return True
            return False
            
        except KeygenError:
            return False

    @staticmethod
    def get_license_details(license_key):
        url = f"https://api.keygen.sh/v1/accounts/{Config.ACCOUNT_ID}/licenses/{license_key}"
        headers = {
            "Authorization": f"Bearer {Config.PRODUCT_TOKEN}",
            "Content-Type": "application/json"
        }
        response = requests.get(url, headers=headers)
        return response.json() if response.status_code == 200 else None

    @staticmethod
    def get_machines_for_license(license_key):
        url = f"https://api.keygen.sh/v1/accounts/{Config.ACCOUNT_ID}/licenses/{license_key}/machines"
        headers = {
            "Authorization": f"Bearer {Config.PRODUCT_TOKEN}",
            "Content-Type": "application/json"
        }
        response = requests.get(url, headers=headers)
        return response.json()['data'] if response.status_code == 200 else []

def send_license_email(email, license_key, first_name, is_trial=True):
    if not validate_smtp_config():
        logger.warning("SMTP not configured correctly. Skipping email sending.")
        return False
    
    try:        
        subject = "Welcome to StoryboardMaker Pro - Your License Key"
        body = f"""
Dear {first_name},

Thank you for choosing StoryboardMaker Pro! I'm excited to have you join the growing community of photo DITs, photographers, and creative teams using this tool to streamline their workflow.

Here's your license key to get started:

    {license_key}

{'Your trial license is valid for 30 days, giving you full access to explore all premium features.' if is_trial else 'Your license has been activated with full access to all premium features.'}

Getting Started:

   1 Launch Capture One.
   2 Start Storyboard maker pro create or setup.
   3 Enter your mail and copy and paste your license key.
   4 Start creating layouts, boards, or storyboards directly from Capture One!

Key Features You Can Now Access:
• Professional layout and board templates tailored for Capture One workflows.
• Advanced export options for seamless integration into creative projects.
• Custom panel layouts to suit your needs.
• High-resolution exports for professional delivery.
• Tools designed to optimize the workflow of photo DITs, photographers, and creative teams.

Need Help?
If you have any questions or need assistance, feel free to contact me at support@dityan.com.

Make the most of your 30-day trial! I hope StoryboardMaker Pro helps you save time and elevate your creative output.

Best regards,
Yan Senez
Creator of StoryboardMaker Pro

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
            return True
    except Exception as e:
        logger.error(f"Failed to send license email: {str(e)}")
        return False

def validate_json_payload(*required_fields):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not request.is_json:
                return jsonify({"success": False, "error": "Invalid content type"}), HTTPStatus.UNSUPPORTED_MEDIA_TYPE
            
            data = request.get_json()
            missing_fields = [field for field in required_fields if field not in data]
            
            if missing_fields:
                return jsonify({"success": False, "error": f"Missing required fields: {', '.join(missing_fields)}"}), HTTPStatus.BAD_REQUEST
                
            return f(*args, **kwargs)
        return decorated_function
    return decorator

@app.route('/create', methods=['POST'])
@validate_json_payload('first_name', 'last_name', 'email', 'fingerprint', 'license_type')
def create_license():
    try:
        data = request.get_json()
        
        # Validation
        try:
            validate_email(data['email'])
        except ValueError:
            return jsonify({"success": False, "error": "Invalid email format"}), HTTPStatus.BAD_REQUEST
            
        if not all([data['first_name'].strip(), data['last_name'].strip()]):
            return jsonify({"success": False, "error": "Invalid name"}), HTTPStatus.BAD_REQUEST

        # Vérifier utilisateur existant
        existing_user = KeygenAPI.get_user_by_email(data['email'])
        if existing_user and data['license_type'] == 'trial':
            return jsonify({"success": False, "error": "User already has a trial license"}), HTTPStatus.CONFLICT

        # Créer nouvel utilisateur si nécessaire
        if not existing_user:
            user_result = KeygenAPI.create_user(
                data['first_name'],
                data['last_name'],
                data['email']
            )
            user_id = user_result['data']['id']
        else:
            user_id = existing_user['id']

        # Déterminer policy_id
        policy_mapping = {
            'trial': Config.TRIAL_POLICY_ID,
            'standalone': Config.STANDALONE_POLICY_ID,
            'enterprise6': Config.ENTERPRISE6_POLICY_ID,
            'enterprise10': Config.ENTERPRISE10_POLICY_ID,
            'enterprise20': Config.ENTERPRISE20_POLICY_ID
        }
        policy_id = policy_mapping.get(data['license_type'])
        
        if not policy_id:
            return jsonify({"success": False, "error": "Invalid license type"}), HTTPStatus.BAD_REQUEST

        # Créer licence avec fingerprint
        license_result = KeygenAPI.create_license(
            user_id=user_id,
            policy_id=policy_id,
            first_name=data['first_name'],
            last_name=data['last_name']
        )
        
        # Enregistrer la machine
        license_id = license_result['data']['id']
        KeygenAPI.create_machine(license_id, data['fingerprint'])
        
        # Envoyer email
        license_key = license_result['data']['attributes']['key']
        if send_license_email(data['email'], license_key, data['license_type']):
            return jsonify({"success": True}), HTTPStatus.CREATED
        else:
            return jsonify({"success": False, "error": "Failed to send email"}), HTTPStatus.INTERNAL_SERVER_ERROR

    except Exception as e:
        logger.error(f"License creation error: {str(e)}")
        return jsonify({"success": False, "error": str(e)}), HTTPStatus.INTERNAL_SERVER_ERROR

@app.route('/validate', methods=['POST'])
@validate_json_payload('email', 'licenseKey', 'fingerprint')
def validate_license():
    try:
        data = request.get_json()
        
        validation_result = KeygenAPI.validate_license(
            license_key=data['licenseKey'],
            fingerprint=data['fingerprint'],
            email=data['email']
        )
        
        return jsonify(validation_result), HTTPStatus.OK if validation_result["success"] else HTTPStatus.UNAUTHORIZED

    except Exception as e:
        logger.error(f"License validation error: {str(e)}")
        return jsonify({
            "success": False,
            "error": str(e)
        }), HTTPStatus.INTERNAL_SERVER_ERROR

@app.errorhandler(HTTPStatus.NOT_FOUND) 
def not_found_error(error):
    return jsonify({"success": False, "error": str(error)}), HTTPStatus.NOT_FOUND

@app.errorhandler(HTTPStatus.INTERNAL_SERVER_ERROR)
def internal_error(error):
    return jsonify({"success": False, "error": str(error)}), HTTPStatus.INTERNAL_SERVER_ERROR

@app.before_request
def log_request_info():
    logger.debug('Request Method: %s', request.method)
    logger.debug('Request URL: %s', request.url)
    logger.debug('Request Path: %s', request.path)
    
    if request.get_data():
        try:
            if request.is_json:
                logger.debug('Request JSON Body: %s', request.get_json())
        except Exception:
            pass

@app.after_request
def log_response_info(response):
    logger.debug('Response Status: %s', response.status)
    return response

if __name__ == '__main__':
    if test_smtp_connection():
        logger.info("SMTP connection test successful")
    else:
        logger.warning("SMTP connection test failed. Email sending will be disabled.")
    
    app.run(host='0.0.0.0', port=5000)