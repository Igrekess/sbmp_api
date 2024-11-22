from flask import Flask, request, jsonify, url_for
import requests
import smtplib
from email.mime.text import MIMEText
import os
from functools import wraps
import logging
import re

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
    """Valide la configuration SMTP."""
    required_configs = ['SMTP_SERVER', 'SMTP_PORT', 'EMAIL_USER', 'EMAIL_PASSWORD']
    missing = [config for config in required_configs if not getattr(Config, config)]
    if missing:
        raise ValueError(f"Missing SMTP configuration: {', '.join(missing)}")

def test_smtp_connection():
    """Test la connexion SMTP avant d'envoyer des emails."""
    try:
        with smtplib.SMTP(Config.SMTP_SERVER, Config.SMTP_PORT, timeout=5) as server:
            server.starttls()
            server.login(Config.EMAIL_USER, Config.EMAIL_PASSWORD)
            return True
    except smtplib.SMTPAuthenticationError:
        logger.error("SMTP Authentication failed. Please check credentials.")
        return False
    except smtplib.SMTPException as e:
        logger.error(f"SMTP Error: {str(e)}")
        return False
    except Exception as e:
        logger.error(f"Unexpected SMTP error: {str(e)}")
        return False

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
                    error_message = error_data.get('errors', [{'detail': 'Unknown error'}])[0]['detail']
                except ValueError:
                    pass
            logger.error(f"API Request failed: {error_message}")
            raise KeygenError(error_message)

    @staticmethod
    def get_policy_id(license_type):
        return Config.TRIAL_POLICY_ID if license_type.lower() == 'trial' else Config.STANDALONE_POLICY_ID

    @staticmethod
    def create_user(first_name, last_name, email):
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
        
        try:
            response = requests.post(
                url=url,
                json=payload,
                headers=KeygenAPI.get_headers()
            )
            
            logger.debug(f"API Response Status: {response.status_code}")
            logger.debug(f"API Response Headers: {response.headers}")
            logger.debug(f"API Response Content: {response.text}")
            
            response.raise_for_status()
            user_data = response.json()
            
            # Récupérer l'UUID de l'utilisateur
            user_id = user_data['data']['id']
            logger.info(f"User ID: {user_id}")
            
            # Créer une licence d'essai pour l'utilisateur
            license_data = KeygenAPI.create_license(user_id, 'trial')
            
            return {
                "user": user_data,
                "license": license_data
            }
        
        except requests.exceptions.RequestException as e:
            logger.error(f"Error creating user: {e}")
            return None

    @staticmethod
    def create_license(user_id, license_type):
        logger.info(f"Creating {license_type} license for user {user_id}")
        url = f"{KeygenAPI.BASE_URL}/{Config.ACCOUNT_ID}/licenses"
        payload = {
            "data": {
                "type": "licenses",
                "attributes": {
                    "name": f"License for {user_id}",
                    "expiry": "30d"  # Exemple pour une licence d'essai de 30 jours
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
        
        try:
            response = requests.post(
                url=url,
                json=payload,
                headers=KeygenAPI.get_headers()
            )
            
            logger.debug(f"API Response Status: {response.status_code}")
            logger.debug(f"API Response Headers: {response.headers}")
            logger.debug(f"API Response Content: {response.text}")
            
            response.raise_for_status()
            return response.json()
        
        except requests.exceptions.RequestException as e:
            logger.error(f"Error creating license: {e}")
            return None

def send_license_email(email, license_key, is_trial=True):
    """Envoie l'email contenant le numéro de licence à l'utilisateur."""
    try:
        validate_smtp_config()
        
        # Test de connexion SMTP
        if not test_smtp_connection():
            raise ValueError("SMTP connection test failed")
        
        subject = "Your License Key"
        body = f"""
        Welcome!
        
        Your license key is: {license_key}
        
        {"This license is valid for 30 days." if is_trial else "This is a permanent license."}
        
        If you have any questions, please contact support.
        """
        
        msg = MIMEText(body)
        msg['Subject'] = subject
        msg['From'] = Config.EMAIL_USER
        msg['To'] = email

        with smtplib.SMTP(Config.SMTP_SERVER, Config.SMTP_PORT) as server:
            server.ehlo()  # Ajout explicite de EHLO
            server.starttls()
            server.ehlo()  # Répéter EHLO après TLS
            
            logger.debug(f"Attempting SMTP login with user: {Config.EMAIL_USER}")
            server.login(Config.EMAIL_USER, Config.EMAIL_PASSWORD)
            
            logger.debug(f"Sending email to: {email}")
            server.sendmail(Config.EMAIL_USER, email, msg.as_string())
            logger.info(f"License email sent successfully to {email}")
            
    except smtplib.SMTPAuthenticationError:
        error_msg = "SMTP Authentication failed. Please check credentials."
        logger.error(error_msg)
        raise ValueError(error_msg)
        
    except smtplib.SMTPException as e:
        error_msg = f"SMTP Error: {str(e)}"
        logger.error(error_msg)
        raise ValueError(error_msg)
        
    except Exception as e:
        error_msg = f"Failed to send license email: {str(e)}"
        logger.error(error_msg)
        raise ValueError(error_msg)

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
        user_id = user_result['user']['data']['id']

        # Création de la licence trial
        license_result = KeygenAPI.create_license(user_id, 'trial')
        license_key = license_result['data']['attributes']['key']
        
        try:
            # Envoi de l'email
            send_license_email(data['email'], license_key, is_trial=True)
        except ValueError as email_error:
            # En cas d'erreur d'envoi d'email, on continue mais on log l'erreur
            logger.warning(f"User created but email failed: {str(email_error)}")
            return jsonify({
                "message": "User registered successfully but email delivery failed. Please contact support.",
                "userId": user_id,
                "licenseKey": license_key
            }), 201
        
        return jsonify({
            "message": "User registered successfully. Please check your email for your license key.",
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

if __name__ == '__main__':
    app.run(debug=True)