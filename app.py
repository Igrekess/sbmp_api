from flask import Flask, request, jsonify
import requests
import smtplib
from email.mime.text import MIMEText
import os
from functools import wraps
import logging

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

class KeygenAPI:
    BASE_URL = "https://api.keygen.sh/v1/accounts"
    
    @staticmethod
    def get_headers():
        return {
            "Authorization": f"Bearer {Config.PRODUCT_TOKEN}",
            "Content-Type": "application/vnd.api+json",
            "Accept": "application/vnd.api+json"
        }

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
                    "email": email,
                    "status": "INACTIVE"
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
            logger.debug(f"API Response Headers: {dict(response.headers)}")
            logger.debug(f"API Response Content: {response.text}")
            
            response.raise_for_status()
            response_data = response.json()
            return response_data["data"]["id"]
            
        except requests.exceptions.RequestException as e:
            logger.error(f"API request failed: {str(e)}")
            if hasattr(e, 'response') and e.response is not None:
                logger.error(f"Response status: {e.response.status_code}")
                logger.error(f"Response content: {e.response.text}")
            raise ValueError(f"Failed to create user: {str(e)}")

    @staticmethod
    def create_license(user_id, license_type, name):
        logger.info(f"Creating {license_type} license for user {user_id}")
        policy_id = KeygenAPI.get_policy_id(license_type)
        url = f"{KeygenAPI.BASE_URL}/{Config.ACCOUNT_ID}/licenses"
        payload = {
            "data": {
                "type": "licenses",
                "attributes": {
                    "name": name
                },
                "relationships": {
                    "policy": {
                        "data": {
                            "type": "policies",
                            "id": policy_id
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
            logger.debug(f"API Response Headers: {dict(response.headers)}")
            logger.debug(f"API Response Content: {response.text}")
            
            response.raise_for_status()
            return response.json()["data"]["id"]
            
        except requests.exceptions.RequestException as e:
            logger.error(f"API request failed: {str(e)}")
            if hasattr(e, 'response') and e.response is not None:
                logger.error(f"Response status: {e.response.status_code}")
                logger.error(f"Response content: {e.response.text}")
            raise ValueError(f"Failed to create license: {str(e)}")

    @staticmethod
    def create_activation_token(user_id):
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
        
        try:
            response = requests.post(
                url=url,
                json=payload,
                headers=KeygenAPI.get_headers()
            )
            
            logger.debug(f"API Response Status: {response.status_code}")
            logger.debug(f"API Response Headers: {dict(response.headers)}")
            logger.debug(f"API Response Content: {response.text}")
            
            response.raise_for_status()
            return response.json()["data"]["attributes"]["token"]
            
        except requests.exceptions.RequestException as e:
            logger.error(f"API request failed: {str(e)}")
            if hasattr(e, 'response') and e.response is not None:
                logger.error(f"Response status: {e.response.status_code}")
                logger.error(f"Response content: {e.response.text}")
            raise ValueError(f"Failed to create activation token: {str(e)}")

    @staticmethod
    def validate_and_activate_user(token):
        logger.info(f"Validating and activating user with token")
        url = f"{KeygenAPI.BASE_URL}/{Config.ACCOUNT_ID}/tokens/{token}/actions/validate"
        
        try:
            response = requests.post(url, headers=KeygenAPI.get_headers())
            
            logger.debug(f"API Response Status: {response.status_code}")
            logger.debug(f"API Response Headers: {dict(response.headers)}")
            logger.debug(f"API Response Content: {response.text}")
            
            response.raise_for_status()
            response_data = response.json()
            
            if not response_data.get("meta", {}).get("valid"):
                raise ValueError("Invalid activation token")
                
            user_id = response_data["data"]["relationships"]["user"]["data"]["id"]
            KeygenAPI.update_user_status(user_id, "ACTIVE")
            return user_id
            
        except requests.exceptions.RequestException as e:
            logger.error(f"API request failed: {str(e)}")
            if hasattr(e, 'response') and e.response is not None:
                logger.error(f"Response status: {e.response.status_code}")
                logger.error(f"Response content: {e.response.text}")
            raise ValueError(f"Failed to validate token: {str(e)}")

    @staticmethod
    def validate_license(email, license_key, fingerprint):
        logger.info(f"Validating license for {email} with fingerprint {fingerprint}")
        url = f"{KeygenAPI.BASE_URL}/{Config.ACCOUNT_ID}/licenses/{license_key}/validate"
        
        try:
            response = requests.get(
                url=url,
                headers=KeygenAPI.get_headers()
            )
            
            logger.debug(f"API Response Status: {response.status_code}")
            logger.debug(f"API Response Headers: {dict(response.headers)}")
            logger.debug(f"API Response Content: {response.text}")
            
            response.raise_for_status()
            license_data = response.json()
            
            if not license_data.get("meta", {}).get("valid"):
                raise ValueError("Invalid license")

            user_id = license_data.get("data", {}).get("relationships", {}).get("user", {}).get("data", {}).get("id")
            if not user_id:
                raise ValueError("User information not found in license data")

            # Get user information
            user_url = f"{KeygenAPI.BASE_URL}/{Config.ACCOUNT_ID}/users/{user_id}"
            user_response = requests.get(user_url, headers=KeygenAPI.get_headers())
            user_response.raise_for_status()
            user_data = user_response.json()

            if user_data.get("data", {}).get("attributes", {}).get("email") != email:
                raise ValueError("Email does not match license")

            # Get machines information
            machines_url = f"{KeygenAPI.BASE_URL}/{Config.ACCOUNT_ID}/licenses/{license_key}/machines"
            machines_response = requests.get(machines_url, headers=KeygenAPI.get_headers())
            machines_response.raise_for_status()
            machines = machines_response.json().get("data", [])

            # Si aucune machine n'est enregistrée, on enregistre celle-ci
            if not machines:
                try:
                    KeygenAPI.create_machine(license_key, fingerprint)
                except Exception as e:
                    logger.error(f"Failed to register new machine: {str(e)}")
                    raise ValueError(f"Could not register new machine: {str(e)}")
            else:
                fingerprint_valid = any(
                    machine.get("attributes", {}).get("fingerprint") == fingerprint 
                    for machine in machines
                )
                if not fingerprint_valid:
                    try:
                        KeygenAPI.create_machine(license_key, fingerprint)
                    except Exception as e:
                        logger.error(f"Failed to register new machine: {str(e)}")
                        raise ValueError(f"Could not register new machine: {str(e)}")

            return {
                "valid": True,
                "userId": user_id,
                "licenseId": license_key,
                "status": license_data.get("data", {}).get("attributes", {}).get("status")
            }

        except requests.exceptions.RequestException as e:
            logger.error(f"API request failed: {str(e)}")
            if hasattr(e, 'response') and e.response is not None:
                logger.error(f"Response status: {e.response.status_code}")
                logger.error(f"Response content: {e.response.text}")
            raise ValueError(f"Failed to validate license: {str(e)}")

def send_activation_email(email, token):
    logger.info(f"Sending activation email to {email}")
    try:
        msg = MIMEText(f"""
        Welcome! Please activate your account by clicking the following link:
        {Config.FRONTEND_URL}/activate?token={token}
        
        This link will expire in 24 hours.
        """)
        
        msg['Subject'] = 'Account Activation'
        msg['From'] = Config.EMAIL_USER
        msg['To'] = email

        with smtplib.SMTP(Config.SMTP_SERVER, Config.SMTP_PORT) as server:
            server.starttls()
            server.login(Config.EMAIL_USER, Config.EMAIL_PASSWORD)
            server.send_message(msg)
            
        logger.info("Activation email sent successfully")
            
    except Exception as e:
        logger.error(f"Failed to send activation email: {str(e)}")
        raise

def validate_json_payload(*required_fields):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not request.is_json:
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

@app.route('/validate-license', methods=['POST'])
@validate_json_payload('email', 'licenseKey', 'fingerprint')
def validate_license():
    try:
        data = request.get_json()
        logger.info(f"License validation request received for {data['email']}")
        
        validation_result = KeygenAPI.validate_license(
            data['email'],
            data['licenseKey'],
            data['fingerprint']
        )
        
        logger.info("License validation successful")
        return jsonify(validation_result), 200
        
    except ValueError as e:
        logger.warning(f"License validation failed: {str(e)}")
        return jsonify({"error": str(e)}), 400
    except Exception as e:
        logger.error(f"Unexpected error during license validation: {str(e)}")
        return jsonify({"error": "An unexpected error occurred"}), 500

@app.route('/create', methods=['POST'])
@validate_json_payload('first_name', 'last_name', 'email', 'license_type')
def create():
    try:
        data = request.get_json()
        logger.info(f"User creation request received for {data['email']}")
        
        # Validation des données
        if not all([data['first_name'], data['last_name'], data['email'], data['license_type']]):
            raise ValueError("All fields must not be empty")
            
        # Normalisation du type de licence
        license_type = data['license_type'].lower()
        if license_type not in ['trial', 'standalone']:
            raise ValueError("Invalid license type. Must be 'trial' or 'standalone'")
        
        # Création de l'utilisateur
        user_id = KeygenAPI.create_user(
            data['first_name'],
            data['last_name'],
            data['email']
        )
        logger.info(f"User created with ID: {user_id}")
        
        # Création de la licence
        license_name = f"License for {data['first_name']} {data['last_name']}"
        license_id = KeygenAPI.create_license(
            user_id,
            license_type,
            license_name
        )
        logger.info(f"License created with ID: {license_id}")
        
        # Création du token d'activation
        activation_token = KeygenAPI.create_activation_token(user_id)
        logger.info("Activation token created")
        
        # Envoi de l'email d'activation
        try:
            send_activation_email(data['email'], activation_token)
            logger.info("Activation email sent")
        except Exception as e:
            logger.warning(f"Failed to send activation email: {str(e)}")
            # On continue même si l'envoi de l'email échoue
        
        return jsonify({
            "message": "User created successfully",
            "userId": user_id,
            "lic
