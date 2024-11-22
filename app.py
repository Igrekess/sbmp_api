from flask import Flask, request, jsonify
import requests
import smtplib
from email.mime.text import MIMEText
import os
from functools import wraps
import logging
import logging.config
import re

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
    def create_license(user_id, license_type):
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
            return []

    @staticmethod
    def validate_license(email, license_key, fingerprint):
        try:
            license_url = f"{KeygenAPI.BASE_URL}/{Config.ACCOUNT_ID}/licenses/{license_key}/actions/validate"
            license_response = requests.post(
                license_url,
                headers=KeygenAPI.get_headers(),
                json={
                    "meta": {
                        "key": license_key,
                        "scope": {
                            "user": email,
                            "fingerprint": fingerprint
                        }
                    }
                }
            )
            license_data = KeygenAPI.handle_response(license_response)

            result = {
                "success": False,
                "expiry": None,
                "maxMachines": None,
                "status": "INVALID"
            }

            if not license_data.get("meta", {}).get("valid"):
                return result

            # Récupérer les détails de la licence
            license_attrs = license_data.get("data", {}).get("attributes", {})
            result.update({
                "success": True,
                "expiry": license_attrs.get("expiry"),
                "maxMachines": license_attrs.get("maxMachines"),
                "status": license_attrs.get("status", "ACTIVE")
            })

            return result

        except Exception as e:
            logger.error(f"License validation failed: {str(e)}")
            return {
                "success": False,
                "expiry": None,
                "maxMachines": None,
                "status": "ERROR"
            }

    @staticmethod
    def create_machine(license_id, fingerprint):
        url = f"{KeygenAPI.BASE_URL}/{Config.ACCOUNT_ID}/machines"
        payload = {
            "data": {
                "type": "machines",
                "attributes": {
                    "fingerprint": fingerprint
                },
                "relationships": {
                    "license": {
                        "data": {
                            "type": "licenses",
                            "id": license_id
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

def send_license_email(email, license_key, first_name, is_trial=True):
    try:
        validate_smtp_config()
        
        subject = "Welcome to StoryboardMaker Pro - Your License Key"
        body = f"""
Dear {first_name},

Thank you for choosing StoryboardMaker Pro! I'm excited to have you join the growing community of photo DITs, photographers, and creative teams using this tool to streamline their workflow.

Here's your license key to get started:

    {license_key}

{'Your trial license is valid for 30 days, giving you full access to explore all premium features.' if is_trial else 'Your license has been activated with full access to all premium features.'}

Your trial license is valid for 30 days, giving you full access to explore all the premium features.

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
                return jsonify({"success": False}), 415
            
            data = request.get_json()
            missing_fields = [field for field in required_fields if field not in data]
            
            if missing_fields:
                return jsonify({"success": False}), 400
                
            return f(*args, **kwargs)
        return decorated_function
    return decorator

@app.route('/register', methods=['POST'])
@validate_json_payload('first_name', 'last_name', 'email')
def register():
    try:
        data = request.get_json()
        
        validate_email(data['email'])
        if not all([data['first_name'].strip(), data['last_name'].strip()]):
            return jsonify({"success": False}), 400

        existing_user = KeygenAPI.get_user_by_email(data['email'])
        
        if existing_user:
            user_id = existing_user['id']
            existing_licenses = KeygenAPI.get_user_licenses(user_id)
            active_license = next((lic for lic in existing_licenses if lic['attributes']['status'] == 'ACTIVE'), None)
            
            if active_license:
                return jsonify({"success": True}), 200
            # Si l'utilisateur existe mais n'a pas de licence active, on continue avec cet utilisateur
        else:
            # Création d'un nouvel utilisateur
            try:
                user_result = KeygenAPI.create_user(
                    data['first_name'],
                    data['last_name'],
                    data['email']
                )
                user_id = user_result['data']['id']
            except KeygenError:
                return jsonify({"success": False}), 400

        # Création de la licence
        try:
            license_result = KeygenAPI.create_license(user_id, 'trial')
            license_key = license_result['data']['attributes']['key']
        except KeygenError:
            return jsonify({"success": False}), 400

        email_sent = send_license_email(
            data['email'], 
            license_key, 
            data['first_name'],
            is_trial=True
        )

        return jsonify({"success": email_sent}), 201 if email_sent else 500

    except ValueError:
        return jsonify({"success": False}), 400
    except Exception:
        return jsonify({"success": False}), 500


@app.route('/validate', methods=['POST'])
@validate_json_payload('email', 'licenseKey', 'fingerprint')
def validate_license():
    try:
        data = request.get_json()
        
        validate_email(data['email'])
        
        # Validation de la licence
        validation_result = KeygenAPI.validate_license(
            data['email'],
            data['licenseKey'],
            data['fingerprint']
        )
        
        if not validation_result["success"]:
            # Si la validation échoue, vérifier si le fingerprint doit être enregistré
            license_id = data['licenseKey']
            try:
                KeygenAPI.create_machine(license_id, data['fingerprint'])
                # Réessayer la validation après l'enregistrement du fingerprint
                validation_result = KeygenAPI.validate_license(
                    data['email'],
                    data['licenseKey'],
                    data['fingerprint']
                )
            except KeygenError as e:
                logger.error(f"Failed to register fingerprint: {str(e)}")
                return jsonify({
                    "success": False,
                    "expiry": None,
                    "maxMachines": None,
                    "status": "ERROR"
                }), 400

        return jsonify(validation_result), 200 if validation_result["success"] else 401

    except ValueError:
        return jsonify({
            "success": False,
            "expiry": None,
            "maxMachines": None,
            "status": "ERROR"
        }), 400
    except Exception:
        return jsonify({
            "success": False,
            "expiry": None,
            "maxMachines": None,
            "status": "ERROR"
        }), 500
    
@app.errorhandler(404)
def not_found_error(error):
    return jsonify({"success": False}), 404

@app.errorhandler(500)
def internal_error(error):
    return jsonify({"success": False}), 500

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
        logger.error("SMTP connection test failed")
    
    app.run(host='0.0.0.0', port=5000)