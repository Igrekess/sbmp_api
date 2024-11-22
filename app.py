from flask import Flask, request, jsonify
import requests
import smtplib
from email.mime.text import MIMEText
import os
from functools import wraps
import logging
import logging.config
import re

# Configuration complète du logging
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
            'maxBytes': 10485760,  # 10MB
            'backupCount': 5
        }
    },
    'loggers': {
        '': {  # root logger
            'handlers': ['console', 'file'],
            'level': 'DEBUG',
            'propagate': True
        },
        'werkzeug': {  # Flask's logging
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
    FRONTEND_URL = os.getenv('FRONTEND_URL')
    TRIAL_POLICY_ID = os.getenv('KEYGEN_TRIAL_POLICY_ID')
    STANDALONE_POLICY_ID = os.getenv('KEYGEN_STANDALONE_POLICY_ID')

class KeygenError(Exception):
    """Exception personnalisée pour les erreurs Keygen."""
    pass

def validate_email(email):
    """Valide le format de l'adresse email."""
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    if not re.match(pattern, email):
        raise ValueError("Invalid email format")
    return True

def validate_smtp_config():
    """Valide la configuration SMTP au démarrage."""
    required_configs = ['SMTP_SERVER', 'SMTP_PORT', 'EMAIL_USER', 'EMAIL_PASSWORD']
    missing = [config for config in required_configs if not getattr(Config, config)]
    if missing:
        raise ValueError(f"Missing SMTP configuration: {', '.join(missing)}")

def test_smtp_connection():
    """Test la connexion SMTP."""
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
        """Gère les réponses de l'API Keygen de manière uniforme."""
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
        """Retourne l'ID de la politique en fonction du type de licence."""
        if license_type.lower() not in ['trial', 'standalone']:
            raise ValueError("Invalid license type. Must be 'trial' or 'standalone'")
        return Config.TRIAL_POLICY_ID if license_type.lower() == 'trial' else Config.STANDALONE_POLICY_ID

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
    def create_activation_token(user_id):
        """Crée un token d'activation pour l'utilisateur."""
        logger.info(f"Creating activation token for user {user_id}")
        url = f"{KeygenAPI.BASE_URL}/{Config.ACCOUNT_ID}/tokens"
        
        payload = {
            "data": {
                "type": "tokens",
                "attributes": {
                    "expiry": "24h",
                    "user": user_id
                }
            }
        }
        
        response = requests.post(
            url=url,
            json=payload,
            headers=KeygenAPI.get_headers()
        )
        
        result = KeygenAPI.handle_response(response)
        return result["data"]["attributes"]["token"]

    @staticmethod
    def validate_and_activate_user(token):
        """Valide et active un utilisateur avec son token."""
        logger.info("Validating and activating user with token")
        url = f"{KeygenAPI.BASE_URL}/{Config.ACCOUNT_ID}/tokens/{token}/actions/validate"
        
        response = requests.post(
            url=url,
            headers=KeygenAPI.get_headers()
        )
        
        return KeygenAPI.handle_response(response)

def send_license_email(email, license_key, token, is_trial=True):
    """Envoie l'email avec la clé de licence et le lien d'activation."""
    try:
        validate_smtp_config()
        
        activation_link = f"{Config.FRONTEND_URL}/activate?token={token}"
        subject = "Your License Key and Account Activation"
        body = f"""
        Welcome!
        
        Your license key is: {license_key}
        
        {"This license is valid for 30 days." if is_trial else "This is a permanent license."}
        
        Please click the following link to activate your account:
        {activation_link}
        
        This activation link will expire in 24 hours.
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
    except Exception as e:
        logger.error(f"Failed to send license email: {str(e)}")
        raise

def validate_json_payload(*required_fields):
    """Décorateur pour valider les payloads JSON."""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not request.is_json:
                return jsonify({"error": "Content-Type must be application/json"}), 415
            
            data = request.get_json()
            missing_fields = [field for field in required_fields if field not in data]
            
            if missing_fields:
                return jsonify({
                    "error": "Missing required fields",
                    "fields": missing_fields
                }), 400
                
            return f(*args, **kwargs)
        return decorated_function
    return decorator

@app.route('/register', methods=['POST'])
@validate_json_payload('first_name', 'last_name', 'email')
def register():
    """Point d'entrée pour l'inscription d'un nouvel utilisateur."""
    try:
        data = request.get_json()
        
        # Validation des données
        validate_email(data['email'])
        if not all([data['first_name'].strip(), data['last_name'].strip()]):
            raise ValueError("First name and last name cannot be empty")

        # Test SMTP avant de créer l'utilisateur
        if not test_smtp_connection():
            raise ValueError("SMTP configuration error. Please contact support.")

        # Création de l'utilisateur
        user_result = KeygenAPI.create_user(
            data['first_name'],
            data['last_name'],
            data['email']
        )
        user_id = user_result['data']['id']

        # Création de la licence trial
        license_result = KeygenAPI.create_license(user_id, 'trial')
        license_key = license_result['data']['attributes']['key']
        
        # Création du token d'activation
        activation_token = KeygenAPI.create_activation_token(user_id)

        try:
            # Envoi de l'email
            send_license_email(data['email'], license_key, activation_token, is_trial=True)
        except Exception as email_error:
            logger.warning(f"User created but email failed: {str(email_error)}")
            return jsonify({
                "message": "User registered successfully but email delivery failed. Please contact support.",
                "userId": user_id,
                "licenseKey": license_key
            }), 201
        
        return jsonify({
            "message": "User registered successfully. Please check your email for your license key and activation link.",
            "userId": user_id,
            "licenseKey": license_key
        }), 201
        
    except ValueError as e:
        return jsonify({"error": str(e)}), 400
    except KeygenError as e:
        return jsonify({"error": str(e)}), 400
    except Exception as e:
        logger.error(f"Unexpected error during registration: {str(e)}")
        return jsonify({"error": "An unexpected error occurred"}), 500

@app.route('/activate', methods=['POST'])
@validate_json_payload('token')
def activate_user():
    """Point d'entrée pour l'activation d'un utilisateur."""
    try:
        token = request.get_json()['token']
        
        # Valide et active l'utilisateur
        result = KeygenAPI.validate_and_activate_user(token)
        user_id = result['data']['id']
        
        return jsonify({
            "message": "User activated successfully",
            "userId": user_id
        }), 200
        
    except KeygenError as e:
        return jsonify({"error": str(e)}), 400
    except Exception as e:
        logger.error(f"Unexpected error during activation: {str(e)}")
        return jsonify({"error": "An unexpected error occurred"}), 500

@app.errorhandler(404)
def not_found_error(error):
    return jsonify({"error": "Resource not found"}), 404

@app.errorhandler(500)
def internal_error(error):
    logger.error(f"500 Error: {str(error)}")
    return jsonify({"error": "Internal server error"}), 500

@app.before_request
def log_request_info():
    """Log les informations de requête."""
    logger.debug('Headers: %s', dict(request.headers))
    if request.get_data():
        logger.debug('Body: %s', request.get_data().decode('utf-8'))

@app.after_request
def log_response_info(response):
    """Log les informations de réponse."""
    logger.debug('Response status: %s', response.status)
    return response

if __name__ == '__main__':
    # Test SMTP au démarrage
    if test_smtp_connection():
        logger.info("SMTP connection test successful")
    else:
        logger.error("SMTP connection test failed")
    
    logger.info("Starting Flask application")
    app.run(host='0.0.0.0', port=5000)