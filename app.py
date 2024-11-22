from flask import Flask, request, jsonify
import requests
import smtplib
from email.mime.text import MIMEText
import os
from functools import wraps

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
    def update_user_status(user_id, status):
        api_url = f"{KeygenAPI.BASE_URL}/{Config.ACCOUNT_ID}/users/{user_id}"
        payload = {
            "data": {
                "type": "users",
                "id": user_id,
                "attributes": {
                    "status": status
                }
            }
        }
        
        response = requests.patch(api_url, json=payload, headers=KeygenAPI.get_headers())
        response.raise_for_status()
        return response.json()["data"]["id"]

    @staticmethod
    def create_user(first_name, last_name, email):
        api_url = f"{KeygenAPI.BASE_URL}/{Config.ACCOUNT_ID}/users"
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
        
        response = requests.post(api_url, json=payload, headers=KeygenAPI.get_headers())
        response.raise_for_status()
        return response.json()["data"]["id"]

    @staticmethod
    def create_license(user_id, license_type, name):
        policy_id = KeygenAPI.get_policy_id(license_type)
        api_url = f"{KeygenAPI.BASE_URL}/{Config.ACCOUNT_ID}/licenses"
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
        
        response = requests.post(api_url, json=payload, headers=KeygenAPI.get_headers())
        response.raise_for_status()
        return response.json()["data"]["id"]

    @staticmethod
    def create_activation_token(user_id):
        api_url = f"{KeygenAPI.BASE_URL}/{Config.ACCOUNT_ID}/tokens"
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
        
        response = requests.post(api_url, json=payload, headers=KeygenAPI.get_headers())
        response.raise_for_status()
        return response.json()["data"]["attributes"]["token"]

    @staticmethod
    def validate_and_activate_user(token):
        api_url = f"{KeygenAPI.BASE_URL}/{Config.ACCOUNT_ID}/tokens/{token}/actions/validate"
        response = requests.post(api_url, headers=KeygenAPI.get_headers())
        response.raise_for_status()
        
        token_data = response.json()
        if not token_data["meta"]["valid"]:
            raise ValueError("Invalid activation token")
            
        user_id = token_data["data"]["relationships"]["user"]["data"]["id"]
        KeygenAPI.update_user_status(user_id, "ACTIVE")
        return user_id

    @staticmethod
    def create_machine(license_id, fingerprint):
        api_url = f"{KeygenAPI.BASE_URL}/{Config.ACCOUNT_ID}/machines"
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
        
        response = requests.post(api_url, json=payload, headers=KeygenAPI.get_headers())
        response.raise_for_status()
        return response.json()["data"]["id"]

    @staticmethod
    def validate_license(email, license_key, fingerprint):
        try:
            # Validate license
            license_url = f"{KeygenAPI.BASE_URL}/{Config.ACCOUNT_ID}/licenses/{license_key}/validate"
            license_response = requests.get(license_url, headers=KeygenAPI.get_headers())
            license_response.raise_for_status()
            license_data = license_response.json()

            if not license_data["meta"]["valid"]:
                raise ValueError("Invalid license")

            # Validate user
            user_id = license_data["data"]["relationships"]["user"]["data"]["id"]
            user_url = f"{KeygenAPI.BASE_URL}/{Config.ACCOUNT_ID}/users/{user_id}"
            user_response = requests.get(user_url, headers=KeygenAPI.get_headers())
            user_response.raise_for_status()
            user_data = user_response.json()

            if user_data["data"]["attributes"]["email"] != email:
                raise ValueError("Email does not match license")

            # Validate machine fingerprint
            machines_url = f"{KeygenAPI.BASE_URL}/{Config.ACCOUNT_ID}/licenses/{license_key}/machines"
            machines_response = requests.get(machines_url, headers=KeygenAPI.get_headers())
            machines_response.raise_for_status()
            machines = machines_response.json()["data"]

            fingerprint_valid = any(
                machine["attributes"]["fingerprint"] == fingerprint 
                for machine in machines
            )

            if not fingerprint_valid and machines:  # Only check if machines exist
                raise ValueError("Invalid machine fingerprint")

            return {
                "valid": True,
                "userId": user_id,
                "licenseId": license_key,
                "status": license_data["data"]["attributes"]["status"]
            }

        except requests.exceptions.RequestException as e:
            raise ValueError(f"API request failed: {str(e)}")

def send_activation_email(email, token):
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
        print(f"Failed to send activation email: {str(e)}")
        raise

# Route decorators and error handling
def validate_json_payload(*required_fields):
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

@app.route('/validate-license', methods=['POST'])
@validate_json_payload('email', 'licenseKey', 'fingerprint')
def validate_license():
    try:
        data = request.get_json()
        validation_result = KeygenAPI.validate_license(
            data['email'],
            data['licenseKey'],
            data['fingerprint']
        )
        return jsonify(validation_result), 200
    except ValueError as e:
        return jsonify({"error": str(e)}), 400
    except Exception as e:
        return jsonify({"error": "An unexpected error occurred"}), 500

@app.route('/create-user', methods=['POST'])
@validate_json_payload('firstName', 'lastName', 'email')
def create_user():
    try:
        data = request.get_json()
        user_id = KeygenAPI.create_user(
            data['firstName'],
            data['lastName'],
            data['email']
        )
        
        license_name = f"License for {data['firstName']} {data['lastName']}"
        license_id = KeygenAPI.create_license(user_id, 'trial', license_name)
        
        activation_token = KeygenAPI.create_activation_token(user_id)
        send_activation_email(data['email'], activation_token)

        return jsonify({
            "message": "User created successfully",
            "userId": user_id,
            "licenseId": license_id,
            "activationToken": activation_token
        }), 201

    except Exception as e:
        print(f"Error creating user: {str(e)}")
        return jsonify({"error": "Failed to create user"}), 500

@app.route('/activate', methods=['POST'])
@validate_json_payload('token')
def activate_user():
    try:
        token = request.get_json()['token']
        user_id = KeygenAPI.validate_and_activate_user(token)
        return jsonify({
            "message": "User activated successfully",
            "userId": user_id
        }), 200
    except ValueError as e:
        return jsonify({"error": str(e)}), 400
    except Exception as e:
        return jsonify({"error": "Failed to activate user"}), 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)