from flask import Flask, request, jsonify, url_for
import requests
import smtplib
from email.mime.text import MIMEText
import os
from functools import wraps
import logging
import re
from datetime import datetime, timedelta

# Configuration du logging
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
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

class KeygenError(Exception):
    """Exception personnalisée pour les erreurs Keygen."""
    pass

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
        
        expiry = "30d" if license_type.lower() == 'trial' else None
        
        payload = {
            "data": {
                "type": "licenses",
                "attributes": {
                    "name": f"License for {user_id}",
                    **({"expiry": expiry} if expiry else {})
                },
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
                    "expiry": "24h"
                },
                "relationships": {
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

def send_activation_email(email, token):
    """Envoie l'email d'activation à l'utilisateur."""
    try:
        validate_smtp_config()
        
        activation_link = f"{Config.FRONTEND_URL}/activate?token={token}"
        subject = "Activate your account"
        body = f"""
        Welcome!
        
        Please click the following link to activate your account:
        {activation_link}
        
        This link will expire in 24 hours.
        """
        
        msg = MIMEText(body)
        msg['Subject'] = subject
        msg['From'] = Config.EMAIL_USER
        msg['To'] = email

        with smtplib.SMTP(Config.SMTP_SERVER, Config.SMTP_PORT) as server:
            server.starttls()
            server.login(Config.EMAIL_USER, Config.EMAIL_PASSWORD)
            server.sendmail(Config.EMAIL_USER, email, msg.as_string())
            logger.info(f"Activation email sent to {email}")
    except Exception as e:
        logger.error(f"Failed to send activation email: {e}")
        raise

def validate_json_payload(*required_fields):
    """Décorateur pour valider les payloads JSON."""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not request.is_json:
                logger.warning("Received non-JSON request")
                return jsonify({"error": "Content-Type must be application/json"}), 415
            
            data = request.get_json()
            logger.debug(f"Received payload: {data}")
            
            missing_fields = [field for field in required_fields if field not in data]
            
            if missing_fields:
                logger.warning(f"Missing required fields: {missing_fields}")
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

        # Création de l'utilisateur
        user_result = KeygenAPI.create_user(
            data['first_name'],
            data['last_name'],
            data['email']
        )
        user_id = user_result['data']['id']

        # Création de la licence trial
        license_result = KeygenAPI.create_license(user_id, 'trial')
        
        # Création du token d'activation
        activation_token = KeygenAPI.create_activation_token(user_id)
        
        # Envoi de l'email d'activation
        send_activation_email(data['email'], activation_token)
        
        return jsonify({
            "message": "User registered successfully. Please check your email for activation instructions.",
            "userId": user_id,
            "licenseId": license_result['data']['id']
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
    logger.warning(f"404 Error: {request.url}")
    return jsonify({"error": "Resource not found"}), 404

@app.errorhandler(500)
def internal_error(error):
    logger.error(f"500 Error: {str(error)}")
    return jsonify({"error": "Internal server error"}), 500

# Middleware pour logger toutes les requêtes
@app.before_request
def log_request_info():
    logger.debug('Headers: %s', request.headers)
    logger.debug('Body: %s', request.get_data())

# Middleware pour logger toutes les réponses
@app.after_request
def log_response_info(response):
    logger.debug('Response status: %s', response.status)
    return response

if __name__ == '__main__':
    # Validation de la configuration au démarrage
    validate_smtp_config()
    
    logger.info("Starting Flask application")
    app.run(host='0.0.0.0', port=5000)