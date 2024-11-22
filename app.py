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
            "Content-Type": "application/vnd.api+json"
        }

    @staticmethod
    def get_policy_id(license_type):
        return Config.TRIAL_POLICY_ID if license_type.lower() == 'trial' else Config.STANDALONE_POLICY_ID

    @staticmethod
    def make_request(method, url, json=None):
        """Méthode utilitaire pour faire des requêtes API avec gestion d'erreur"""
        logger.debug(f"Making {method} request to {url}")
        if json:
            logger.debug(f"Request payload: {json}")
            
        try:
            response = requests.request(
                method=method,
                url=url,
                json=json,
                headers=KeygenAPI.get_headers()
            )
            response.raise_for_status()
            
            try:
                data = response.json()
                logger.debug(f"Response data: {data}")
                return data
            except ValueError as e:
                logger.error(f"Failed to parse JSON response: {response.text}")
                raise ValueError(f"Invalid API response format: {str(e)}")
                
        except requests.exceptions.RequestException as e:
            logger.error(f"API request failed: {str(e)}")
            if hasattr(e, 'response') and e.response is not None:
                logger.error(f"Response content: {e.response.text}")
            raise

    @staticmethod
    def update_user_status(user_id, status):
        logger.info(f"Updating user {user_id} status to {status}")
        url = f"{KeygenAPI.BASE_URL}/{Config.ACCOUNT_ID}/users/{user_id}"
        payload = {
            "data": {
                "type": "users",
                "id": user_id,
                "attributes": {
                    "status": status
                }
            }
        }
        
        response = KeygenAPI.make_request("PATCH", url, payload)
        return response["data"]["id"]

    @staticmethod
    def create_user(first_name, last_name, email):
        logger.info(f"Creating user for {email}")
        url = f"{KeygenAPI.BASE_URL}/{Config.ACCOUNT_ID}/users"
        payload = {
            "data": {
                "type": "users",
                "attributes": {
                    "firstName": first_name,
                    "lastName": last_name,
                    "email": email,
                    "status": "INACTIVE"
                }
            }
        }
        
        response = KeygenAPI.make_request("POST", url, payload)
        return response["data"]["id"]

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
        
        response = KeygenAPI.make_request("POST", url, payload)
        return response["data"]["id"]

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
        
        response = KeygenAPI.make_request("POST", url, payload)
        return response["data"]["attributes"]["token"]

    @staticmethod
    def validate_and_activate_user(token):
        logger.info(f"Validating and activating user with token")
        url = f"{KeygenAPI.BASE_URL}/{Config.ACCOUNT_ID}/tokens/{token}/actions/validate"
        response = KeygenAPI.make_request("POST", url)
        
        if not response.get("meta", {}).get("valid"):
            raise ValueError("Invalid activation token")
            
        user_id = response["data"]["relationships"]["user"]["data"]["id"]
        KeygenAPI.update_user_status(user_id, "ACTIVE")
        return user_id

    @staticmethod
    def create_machine(license_id, fingerprint):
        logger.info(f"Creating machine for license {license_id} with fingerprint {fingerprint}")
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
        
        response = KeygenAPI.make_request("POST", url, payload)
        return response["data"]["id"]

    @staticmethod
    def validate_license(email, license_key, fingerprint):
        logger.info(f"Validating license for {email} with fingerprint {fingerprint}")
        try:
            # Validate license
            license_url = f"{KeygenAPI.BASE_URL}/{Config.ACCOUNT_ID}/licenses/{license_key}/validate"
            license_data = KeygenAPI.make_request("GET", license_url)

            if not license_data.get("meta", {}).get("valid"):
                raise ValueError("Invalid license")

            # Validate user
            user_id = license_data.get("data", {}).get("relationships", {}).get("user", {}).get("data", {}).get("id")
            if not user_id:
                raise ValueError("User information not found in license data")

            user_url = f"{KeygenAPI.BASE_URL}/{Config.ACCOUNT_ID}/users/{user_id}"
            user_data = KeygenAPI.make_request("GET", user_url)

            user_email = user_data.get("data", {}).get("attributes", {}).get("email")
            if not user_email or user_email != email:
                raise ValueError("Email does not match license")

            # Validate machine fingerprint
            machines_url = f"{KeygenAPI.BASE_URL}/{Config.ACCOUNT_ID}/licenses/{license_key}/machines"
            machines_data = KeygenAPI.make_request("GET", machines_url)
            machines = machines_data.get("data", [])
            
            if not machines:
                logger.info("No machines registered, registering new machine")
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
                    logger.info("Invalid fingerprint, attempting to register new machine")
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

        except Exception as e:
            logger.error(f"License validation failed: {str(e)}")
            raise

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
        logger.debug(f"Validation result: {validation_result}")
        return jsonify(validation_result), 200
        
    except ValueError as e:
        logger.warning(f"License validation failed: {str(e)}")
        return jsonify({"error": str(e)}), 400
    except Exception as e:
        logger.error(f"Unexpected error during license validation: {str(e)}")
        return jsonify({"error": "An unexpected error occurred"}), 500

@app.route('/create-user', methods=['POST'])
@validate_json_payload('firstName', 'lastName', 'email')
def create_user():
    try:
        data = request.get_json()
        logger.info(f"User creation request received for {data['email']}")
        
        user_id = KeygenAPI.create_user(
            data['firstName'],
            data['lastName'],
            data['email']
        )
        
        license_name = f"License for {data['firstName']} {data['lastName']}"
        license_id = KeygenAPI.create_license(user_id, 'trial', license_name)
        
        activation_token = KeygenAPI.create_activation_token(user_id)
        send_activation_email(data['email'], activation_token)

        logger.info(f"User created successfully: {user_id}")
        return jsonify({
            "message": "User created successfully",
            "userId": user_id,
            "licenseId": license_id,
            "activationToken": activation_token
        }), 201

    except Exception as e:
        logger.error(f"Failed to create user: {str(e)}")
        return jsonify({"error": "Failed to create user"}), 500

@app.route('/activate', methods=['POST'])
@validate_json_payload('token')
def activate_user():
    try:
        token = request.get_json()['token']
        logger.info("User activation request received")
        
        user_id = KeygenAPI.validate_and_activate_user(token)
        
        logger.info(f"User {user_id} activated successfully")
        return jsonify({
            "message": "User activated successfully",
            "userId": user_id
        }), 200
        
    except ValueError as e:
        logger.warning(f"User activation failed: {str(e)}")
        return jsonify({"error": str(e)}), 400
    except Exception as e:
        logger.error(f"Unexpected error during user activation: {str(e)}")
        return jsonify({"error": "Failed to activate user"}), 500

if __name__ == '__main__':
    logger.info("Starting Flask application")
    app.run(host='0.0.0.0', port=5000)
