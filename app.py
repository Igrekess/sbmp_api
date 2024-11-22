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
    @staticmethod
    def get_policy_id(license_type):
        return Config.TRIAL_POLICY_ID if license_type.lower() == 'trial' else Config.STANDALONE_POLICY_ID

    @staticmethod
    def create_user(first_name, last_name, email):
        api_url = f"https://api.keygen.sh/v1/accounts/{Config.ACCOUNT_ID}/users"
        headers = {
            "Authorization": f"Bearer {Config.PRODUCT_TOKEN}",
            "Content-Type": "application/json"
        }
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
        
        response = requests.post(api_url, json=payload, headers=headers)
        response.raise_for_status()
        return response.json()["data"]["id"]

    @staticmethod
    def create_license(user_id, license_type, name):
        policy_id = KeygenAPI.get_policy_id(license_type)
        api_url = f"https://api.keygen.sh/v1/accounts/{Config.ACCOUNT_ID}/licenses"
        headers = {
            "Authorization": f"Bearer {Config.PRODUCT_TOKEN}",
            "Content-Type": "application/json"
        }
        payload = {
            "data": {
                "type": "licenses",
                "attributes": {"name": name},
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
        
        response = requests.post(api_url, json=payload, headers=headers)
        response.raise_for_status()
        return response.json()["data"]["id"]

    @staticmethod
    def create_activation_token(user_id):
        # Implémentation de la création du token d'activation
        pass

    @staticmethod
    def validate_and_activate_user(token):
        # Implémentation de la validation et de l'activation de l'utilisateur
        pass

    @staticmethod
    def create_machine(license_id, fingerprint):
        response = requests.post(
            f"https://api.keygen.sh/v1/accounts/{Config.ACCOUNT_ID}/machines",
            json={
                "data": {
                    "type": "machines",
                    "attributes": {"fingerprint": fingerprint},
                    "relationships": {
                        "license": {
                            "data": {"type": "licenses", "id": license_id}
                        }
                    }
                }
            },
            headers={
                "Authorization": f"Bearer {Config.PRODUCT_TOKEN}",
                "Content-Type": "application/json"
            }
        )
        response.raise_for_status()
        return response.json()["data"]["id"]

    @staticmethod
    def validate_license(email, license_key, fingerprint):
        # Vérifier la licence
        license_response = requests.get(
            f"https://api.keygen.sh/v1/accounts/{Config.ACCOUNT_ID}/licenses/{license_key}/validate",
            headers={
                "Authorization": f"Bearer {Config.PRODUCT_TOKEN}",
                "Content-Type": "application/json"
            }
        )
        license_response.raise_for_status()
        license_data = license_response.json()

        if not license_data["meta"]["valid"]:
            raise ValueError("Invalid license")

        # Vérifier l'utilisateur
        user_id = license_data["data"]["relationships"]["user"]["data"]["id"]
        user_response = requests.get(
            f"https://api.keygen.sh/v1/accounts/{Config.ACCOUNT_ID}/users/{user_id}",
            headers={
                "Authorization": f"Bearer {Config.PRODUCT_TOKEN}",
                "Content-Type": "application/json"
            }
        )
        user_response.raise_for_status()
        user_data = user_response.json()

        if user_data["data"]["attributes"]["email"] != email:
            raise ValueError("Email does not match license")

        # Vérifier le fingerprint
        machines_response = requests.get(
            f"https://api.keygen.sh/v1/accounts/{Config.ACCOUNT_ID}/licenses/{license_key}/machines",
            headers={
                "Authorization": f"Bearer {Config.PRODUCT_TOKEN}",
                "Content-Type": "application/json"
            }
        )
        machines_response.raise_for_status()
        machines = machines_response.json()["data"]

        fingerprint_valid = any(
            machine["attributes"]["fingerprint"] == fingerprint 
            for machine in machines
        )

        if not fingerprint_valid:
            raise ValueError("Invalid machine fingerprint")

        return {
            "valid": True,
            "userId": user_id,
            "licenseId": license_key,
            "status": license_data["data"]["attributes"]["status"]
        }

def send_activation_email(email, token):
    # Implémentation de l'envoi de l'email d'activation
    pass

@app.route('/validate-license', methods=['POST'])
def validate_license():
    data = request.json
    required_fields = ['email', 'licenseKey', 'fingerprint']
    
    if not all(field in data for field in required_fields):
        return jsonify({"error": "Missing required fields"}), 400

    try:
        validation_result = KeygenAPI.validate_license(
            data['email'],
            data['licenseKey'],
            data['fingerprint']
        )
        return jsonify(validation_result), 200
    except ValueError as e:
        return jsonify({"error": str(e)}), 400
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/create-user', methods=['POST'])
def create_user():
    data = request.json
    required_fields = ['firstName', 'lastName', 'email']
    
    if not all(field in data for field in required_fields):
        return jsonify({"error": "Missing required fields"}), 400

    try:
        user_id = KeygenAPI.create_user(
            data['firstName'],
            data['lastName'],
            data['email']
        )
        
        license_type = 'trial'
        license_name = f"License for {data['firstName']} {data['lastName']}"

        license_id = KeygenAPI.create_license(
            user_id,
            license_type,
            license_name
        )

        activation_token = KeygenAPI.create_activation_token(user_id)
        send_activation_email(data['email'], activation_token)

        return jsonify({
            "message": "User created successfully",
            "userId": user_id,
            "licenseId": license_id,
            "activationToken": activation_token
        }), 201

    except Exception as e:
        # Log the full error for debugging
        print("Error:", str(e))
        return jsonify({"error": str(e)}), 500

@app.route('/activate', methods=['POST'])
def activate_user():
    token = request.json.get('token')
    
    if not token:
        return jsonify({"error": "Token is required"}), 400

    try:
        user_id = KeygenAPI.validate_and_activate_user(token)
        return jsonify({
            "message": "User activated successfully",
            "userId": user_id
        }), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/create', methods=['POST'])
def create():
    data = request.json
    first_name = data.get('first_name')
    last_name = data.get('last_name')
    email = data.get('email')
    license_type = data.get('license_type')
    license_name = data.get('license_name')

    try:
        user_id = KeygenAPI.create_user(first_name, last_name, email)
        license_id = KeygenAPI.create_license(user_id, license_type, license_name)
        activation_token = KeygenAPI.create_activation_token(user_id)
        send_activation_email(email, activation_token)
        return jsonify({
            "message": "User created successfully",
            "userId": user_id,
            "licenseId": license_id,
            "activationToken": activation_token
        }), 201
    except Exception as e:
        print("Error:", str(e))
        return jsonify({"error": str(e)}), 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)