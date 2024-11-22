from flask import Flask, request, jsonify, url_for
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
            "Accept": "application/vnd.api+json",
            "Content-Type": "application/vnd.api+json"
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

def send_license_email(email, license_key):
    """Envoie l'email contenant le numéro de licence à l'utilisateur."""
    try:
        validate_smtp_config()
        
        subject = "Your License Key"
        body = f"""
        Welcome!
        
        Your license key is: {license_key}
        
        This license is valid for 30 days.
        """
        
        msg = MIMEText(body)
        msg['Subject'] = subject
        msg['From'] = Config.EMAIL_USER
        msg['To'] = email

        with smtplib.SMTP(Config.SMTP_SERVER, Config.SMTP_PORT) as server:
            server.starttls()
            server.login(Config.EMAIL_USER, Config.EMAIL_PASSWORD)
            server.sendmail(Config.EMAIL_USER, email, msg.as_string())
            logger.info(f"License email sent to {email}")
    except Exception as e:
        logger.error(f"Failed to send license email: {e}")

@app.route('/register', methods=['POST'])
def register():
    data = request.json
    first_name = data.get('first_name')
    last_name = data.get('last_name')
    email = data.get('email')
    
    result = KeygenAPI.create_user(first_name, last_name, email)
    if result:
        license_key = result['license']['data']['attributes']['key']
        send_license_email(email, license_key)
        return jsonify({"message": "User created. Please check your email for your license key."}), 201
    else:
        return jsonify({"message": "Failed to create user."}), 400

if __name__ == '__main__':
    app.run(debug=True)