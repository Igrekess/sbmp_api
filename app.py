from flask import Flask, request, jsonify
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_jwt_extended import JWTManager
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

# Configuration du JWT
app.config['JWT_SECRET_KEY'] = os.getenv('JWT_SECRET_KEY', 'your-secret-key')  # À changer en production
jwt = JWTManager(app)

# Configuration du Limiter
limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["1000 per day"]
)

# Headers de sécurité
@app.after_request
def add_security_headers(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Content-Security-Policy'] = "default-src 'self'"
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    return response

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
    def create_license(user_id, policy_id, first_name, last_name, license_type=None):
        """Crée une nouvelle licence
        
        Args:
            user_id (str): ID utilisateur
            policy_id (str): ID de la politique de licence (obligatoire)
            first_name (str): Prénom
            last_name (str): Nom
            license_type (str, optional): Type de licence pour définir le nom
        """
        if not policy_id:
            raise KeygenError("Policy ID cannot be null")
            
        url = f"https://api.keygen.sh/v1/accounts/{Config.ACCOUNT_ID}/licenses"
        
        headers = {
            "Authorization": f"Bearer {Config.PRODUCT_TOKEN}",
            "Content-Type": "application/json"
        }
        
        # Vérification que policy_id existe dans les mappings
        valid_policies = [
            Config.TRIAL_POLICY_ID,
            Config.STANDALONE_POLICY_ID,
            Config.ENTERPRISE6_POLICY_ID,
            Config.ENTERPRISE10_POLICY_ID,
            Config.ENTERPRISE20_POLICY_ID
        ]
        
        if policy_id not in valid_policies:
            raise KeygenError(f"Invalid policy ID: {policy_id}")
        
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

        # Ajouter le nom de la licence si license_type est fourni
        if license_type:
            payload["data"]["attributes"]["name"] = f"Storyboard Maker Pro {license_type.capitalize()} Version"
        
        logger.debug(f"Creating license with payload: {payload}")
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
        """Valide une licence et enregistre le fingerprint si nécessaire"""
        url = f"https://api.keygen.sh/v1/accounts/{Config.ACCOUNT_ID}/licenses/actions/validate-key"
        
        headers = {
            "Authorization": f"Bearer {Config.PRODUCT_TOKEN}",
            "Content-Type": "application/json"
        }
        
        payload = {
            "meta": {
                "key": license_key,
                "scope": {
                    "user": email,
                    "fingerprint": fingerprint
                }
            }
        }
        
        try:
            response = requests.post(url, json=payload, headers=headers)
            response_data = response.json()
            
            if response.status_code == 200:
                meta_data = response_data.get('meta', {})
                license_data = response_data.get('data', {})
                attributes = license_data.get('attributes', {})
                
                # Vérifier si le fingerprint n'est pas enregistré
                if meta_data.get('code') == 'NO_MACHINES':
                    license_id = license_data.get('id')
                    machine_result = KeygenAPI.create_machine(license_id, fingerprint)
                    if machine_result:
                        return KeygenAPI.validate_license(license_key, fingerprint, email)
                
                is_valid = meta_data.get('valid', False)
                if is_valid:
                    policy_id = license_data.get('relationships', {}).get('policy', {}).get('data', {}).get('id')
                    policy_mapping = {
                        Config.TRIAL_POLICY_ID: {'type': 'trial', 'max_machines': 1},
                        Config.STANDALONE_POLICY_ID: {'type': 'standalone', 'max_machines': 2},
                        Config.ENTERPRISE6_POLICY_ID: {'type': 'enterprise6', 'max_machines': 6},
                        Config.ENTERPRISE10_POLICY_ID: {'type': 'enterprise10', 'max_machines': 10},
                        Config.ENTERPRISE20_POLICY_ID: {'type': 'enterprise20', 'max_machines': 20}
                    }
                    
                    license_info = policy_mapping.get(policy_id, {'type': 'unknown', 'max_machines': 0})
                    max_machines = attributes.get('maxMachines', license_info['max_machines'])
                    machines_count = license_data.get('relationships', {}).get('machines', {}).get('meta', {}).get('count', 0)
                    
                    return {
                        "success": True,
                        "licenseType": attributes.get('name', license_info['type']),  # Utiliser le nom de la licence
                        "status": attributes.get('status', 'unknown'),
                        "expiry": attributes.get('expiry', 'N/A'),
                        "machinesRemaining": max(0, max_machines - machines_count)
                    }
                else:
                    return {
                        "success": False,
                        "error": meta_data.get('detail', 'Validation failed')
                    }
                    
        except Exception as e:
            logger.error(f"License validation request failed: {str(e)}")
            return {
                "success": False, 
                "error": "Validation request failed",
                "status": "error",
                "expiry": "N/A",
                "machinesRemaining": 0
            }

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

    @staticmethod
    def get_machines_for_license_key(license_key):
        """Récupère la liste des machines associées à une licence"""
        try:
            # D'abord récupérer l'ID de la licence
            license_id = KeygenAPI.get_license_id_by_key(license_key)
            if not license_id:
                return {"success": False, "error": "License not found"}

            url = f"{KeygenAPI.BASE_URL}/{Config.ACCOUNT_ID}/machines"
            params = {'filter[license]': license_id}
            
            response = requests.get(
                url=url,
                params=params,
                headers=KeygenAPI.get_headers()
            )
            
            if response.status_code == 200:
                machines_data = response.json().get('data', [])
                machines = [{
                    'id': machine['id'],
                    'fingerprint': machine['attributes']['fingerprint'],
                    'platform': machine['attributes']['platform'],
                    'last_validated': machine['attributes'].get('lastValidated', 'Never')
                } for machine in machines_data]
                
                return {
                    "success": True,
                    "machines": machines
                }
            else:
                return {"success": False, "error": "Failed to fetch machines"}
                
        except Exception as e:
            logger.error(f"Error fetching machines: {str(e)}")
            return {"success": False, "error": str(e)}

    @staticmethod
    def delete_machines(license_key, machine_ids):
        """Supprime les machines spécifiées d'une licence"""
        try:
            for machine_id in machine_ids:
                url = f"{KeygenAPI.BASE_URL}/{Config.ACCOUNT_ID}/machines/{machine_id}"
                
                response = requests.delete(
                    url=url,
                    headers=KeygenAPI.get_headers()
                )
                
                if response.status_code != 204:
                    logger.error(f"Failed to delete machine {machine_id}")
                    return {"success": False, "error": f"Failed to delete machine {machine_id}"}
            
            return {"success": True}
                
        except Exception as e:
            logger.error(f"Error deleting machines: {str(e)}")
            return {"success": False, "error": str(e)}

def send_license_email(email, license_key, first_name, license_type='trial'):
    """Envoie un email avec la clé de licence
    
    Args:
        email (str): Email du destinataire
        license_key (str): Clé de licence
        first_name (str): Prénom du destinataire
        license_type (str): Type de licence (nom complet du produit)
    """
    if not validate_smtp_config():
        logger.warning("SMTP not configured correctly. Skipping email sending.")
        return False
    
    try:
        # Mapping des produits vers les types de licence
        license_type_mapping = {
            'StoryboardMaker Pro Trial': {
                'title': 'Your StoryboardMaker Pro Trial License',
                'duration': '30 days trial period',
                'features': 'full access to explore all premium features',
                'machines': '1 machine'
            },
            'StoryboardMaker Pro Standalone': {
                'title': 'Your StoryboardMaker Pro Standalone License',
                'duration': 'perpetual license',
                'features': 'full access to all premium features',
                'machines': '2 machines'
            },
            'StoryboardMaker Pro Enterprise 6': {
                'title': 'Your StoryboardMaker Pro Enterprise 6 License',
                'duration': 'perpetual license',
                'features': 'full enterprise features',
                'machines': '6 machines'
            },
            'StoryboardMaker Pro Enterprise 10': {
                'title': 'Your StoryboardMaker Pro Enterprise 10 License',
                'duration': 'perpetual license',
                'features': 'full enterprise features',
                'machines': '10 machines'
            },
            'StoryboardMaker Pro Enterprise 20': {
                'title': 'Your StoryboardMaker Pro Enterprise 20 License',
                'duration': 'perpetual license',
                'features': 'full enterprise features',
                'machines': '20 machines'
            }
        }
        
        # Récupérer les informations de licence
        license_info = license_type_mapping.get(license_type, license_type_mapping['StoryboardMaker Pro Trial'])
        
        subject = license_info['title']
        body = f"""
Dear {first_name},

Thank you for choosing StoryboardMaker Pro! I'm excited to have you join the growing community of photo DITs, photographers, and creative teams using this tool to streamline their workflow.

Here's your license key to get started:

    {license_key}

You have received a {license_info['duration']} with {license_info['features']}.
This license can be activated on {license_info['machines']}.

Getting Started:
   1. Launch Capture One
   2. Start Storyboard Maker Pro Create or Setup
   3. Enter your mail and paste your license key
   4. Start creating layouts, boards, or storyboards directly from Capture One!

Need Help?
If you have any questions or need assistance, feel free to contact me at support@dityan.com

{'Make the most of your trial period!' if 'Trial' in license_type else 'Thank you for your purchase!'}

Best regards,
Yan Senez
Creator of StoryboardMaker Pro
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
        
        # Vérifier le type de license
        valid_license_types = ['trial', 'standalone', 'enterprise6', 'enterprise10', 'enterprise20']
        if data['license_type'] not in valid_license_types:
            return jsonify({"success": False, "error": f"Invalid license type: {data['license_type']}"}), HTTPStatus.BAD_REQUEST
        
        # Déterminer policy_id
        policy_id = getattr(Config, f"{data['license_type'].upper()}_POLICY_ID")
        
        # Créer licence avec fingerprint
        license_result = KeygenAPI.create_license(
            user_id=user_id,
            policy_id=policy_id,
            first_name=data['first_name'],
            last_name=data['last_name'],
            license_type=data['license_type']
        )
        
        # Enregistrer la machine
        license_id = license_result['data']['id']
        KeygenAPI.create_machine(license_id, data['fingerprint'])
        
        # Envoyer email
        license_key = license_result['data']['attributes']['key']
        if send_license_email(data['email'], license_key, data['first_name'], data['license_type']):    
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

@app.route('/machines/<license_key>', methods=['GET'])
def get_machines(license_key):
    """Liste les machines associées à une licence"""
    try:
        result = KeygenAPI.get_machines_for_license_key(license_key)
        return jsonify(result), HTTPStatus.OK if result["success"] else HTTPStatus.BAD_REQUEST
    except Exception as e:
        logger.error(f"Error in get_machines: {str(e)}")
        return jsonify({"success": False, "error": str(e)}), HTTPStatus.INTERNAL_SERVER_ERROR

@app.route('/machines', methods=['DELETE'])
@validate_json_payload('license_key', 'machine_ids')
def delete_machines():
    """Supprime les machines sélectionnées"""
    try:
        data = request.get_json()
        result = KeygenAPI.delete_machines(data['license_key'], data['machine_ids'])
        return jsonify(result), HTTPStatus.OK if result["success"] else HTTPStatus.BAD_REQUEST
    except Exception as e:
        logger.error(f"Error in delete_machines: {str(e)}")
        return jsonify({"success": False, "error": str(e)}), HTTPStatus.INTERNAL_SERVER_ERROR

# Nouvelle route pour recevoir les webhooks PayPal
@app.route('/paypal-webhook', methods=['POST'])
def handle_paypal_webhook():
    try:
        # Vérifier l'authenticité de la requête PayPal
        payload = request.get_json()
        logger.info("PayPal webhook received")
        
        paypal_auth = verify_paypal_signature(request.headers, payload)
        if not paypal_auth:
            return jsonify({"success": False, "error": "Invalid PayPal signature"}), HTTPStatus.UNAUTHORIZED
        
        # Extraire les informations de la transaction
        payment_data = extract_payment_data(payload)
        
        # Mapping des produits vers les policy IDs
        policy_mapping = {
            'StoryboardMaker Pro Trial': Config.TRIAL_POLICY_ID,
            'StoryboardMaker Pro Standalone': Config.STANDALONE_POLICY_ID,
            'StoryboardMaker Pro Enterprise 6': Config.ENTERPRISE6_POLICY_ID, 
            'StoryboardMaker Pro Enterprise 10': Config.ENTERPRISE10_POLICY_ID,
            'StoryboardMaker Pro Enterprise 20': Config.ENTERPRISE20_POLICY_ID
        }
        
        logger.info(f"Processing payment for item: {payment_data['item_name']}")
        
        # Récupérer le policy_id correspondant
        policy_id = policy_mapping.get(payment_data['item_name'])
        if not policy_id:
            logger.error(f"Unknown product name: {payment_data['item_name']}")
            return jsonify({"success": False, "error": "Invalid product"}), HTTPStatus.BAD_REQUEST
        
        # Créer l'utilisateur dans Keygen
        user_result = KeygenAPI.create_user(
            payment_data['first_name'],
            payment_data['last_name'],
            payment_data['email']
        )
        
        # Créer la licence
        license_result = KeygenAPI.create_license(
            user_id=user_result['data']['id'],
            policy_id=policy_id,
            first_name=payment_data['first_name'],
            last_name=payment_data['last_name']
        )
        
        # Envoyer l'email avec la clé de licence en utilisant le nom complet du produit
        license_key = license_result['data']['attributes']['key']
        send_result = send_license_email(
            payment_data['email'],
            license_key,
            payment_data['first_name'],
            payment_data['item_name']  # Utiliser le nom complet du produit
        )
        
        if send_result:
            logger.info(f"License email sent successfully to {payment_data['email']}")
            return jsonify({"success": True}), HTTPStatus.CREATED
        else:
            logger.error("Failed to send license email")
            return jsonify({"success": False, "error": "Email sending failed"}), HTTPStatus.INTERNAL_SERVER_ERROR
            
    except Exception as e:
        logger.error(f"PayPal webhook error: {str(e)}")
        return jsonify({"success": False, "error": str(e)}), HTTPStatus.INTERNAL_SERVER_ERROR

def verify_paypal_signature(headers, payload):
    """Vérifie la signature du webhook PayPal"""
    # Implémentation de la vérification de la signature PayPal
    pass

def extract_payment_data(payload):
    """Extrait les informations pertinentes du payload PayPal"""
    return {
        'product_id': payload['resource']['custom_id'],
        'email': payload['resource']['payer']['email_address'],
        'first_name': payload['resource']['payer']['name']['given_name'],
        'last_name': payload['resource']['payer']['name']['surname']
    }

@app.route('/test-ipn', methods=['POST'])
def test_ipn():
    logger.info("Test IPN endpoint hit")
    try:
        logger.info("Starting test IPN process")
        
        # Simuler une notification PayPal
        test_payload = {
            'payment_status': 'Completed',
            'payer_email': 'sacha.rovinski.fb@gmail.com',
            'first_name': 'Sachyan',
            'last_name': 'Ryvysy',
            'item_name': 'StoryboardMaker Pro Enterprise 20',  # Nom exact du produit
            'mc_gross': '299.00',
            'mc_currency': 'EUR'
        }
        
        # Récupérer le policy_id correspondant
        policy_mapping = {
            'StoryboardMaker Pro Trial': Config.TRIAL_POLICY_ID,
            'StoryboardMaker Pro Standalone': Config.STANDALONE_POLICY_ID,
            'StoryboardMaker Pro Enterprise 6': Config.ENTERPRISE6_POLICY_ID, 
            'StoryboardMaker Pro Enterprise 10': Config.ENTERPRISE10_POLICY_ID,
            'StoryboardMaker Pro Enterprise 20': Config.ENTERPRISE20_POLICY_ID
        }
        
        policy_id = policy_mapping.get(test_payload['item_name'])
        if not policy_id:
            raise ValueError(f"Invalid product name: {test_payload['item_name']}")
            
        # Créer l'utilisateur
        user_result = KeygenAPI.create_user(
            first_name=test_payload['first_name'],
            last_name=test_payload['last_name'],
            email=test_payload['payer_email']
        )
        logger.info(f"User created: {user_result}")
        
        # Créer la licence
        license_result = KeygenAPI.create_license(
            user_id=user_result['data']['id'],
            policy_id=policy_id,
            first_name=test_payload['first_name'],
            last_name=test_payload['last_name']
        )
        logger.info(f"License created: {license_result}")
        
        # Envoyer l'email avec le nom complet du produit
        license_key = license_result['data']['attributes']['key']
        send_result = send_license_email(
            test_payload['payer_email'],
            license_key,
            test_payload['first_name'],
            test_payload['item_name']  # Utiliser le nom complet du produit
        )
        logger.info(f"Email sent: {send_result}")
        
        return jsonify({
            "success": True,
            "message": "Test IPN processed successfully",
            "license_key": license_key,
            "license_type": test_payload['item_name']
        })
        
    except Exception as e:
        logger.error(f"Test IPN error: {str(e)}", exc_info=True)
        return jsonify({
            "success": False,
            "error": str(e)
        }), 500

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