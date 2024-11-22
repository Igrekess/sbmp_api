# Flask API pour la Gestion des Licences Keygen

## Configuration

### Variables d'Environnement Requises
```env
KEYGEN_ACCOUNT_ID=
KEYGEN_PRODUCT_TOKEN=
KEYGEN_TRIAL_POLICY_ID=
KEYGEN_STANDALONE_POLICY_ID=
SMTP_SERVER=
SMTP_PORT=
EMAIL_USER=
EMAIL_PASSWORD=
FRONTEND_URL=
```

## Endpoints

### 1. Création d'Utilisateur
`POST /create-user`

Crée un nouvel utilisateur avec une licence et une machine associée.

**Payload:**
```json
{
  "firstName": "string",
  "lastName": "string",
  "email": "string",
  "licenseType": "trial|standalone",
  "fingerprint": "string"
}
```

**Réponse:**
```json
{
  "message": "User created successfully",
  "userId": "string",
  "licenseId": "string",
  "machineId": "string",
  "activationToken": "string"
}
```

### 2. Activation d'Utilisateur
`POST /activate`

Active un compte utilisateur avec un token.

**Payload:**
```json
{
  "token": "string"
}
```

**Réponse:**
```json
{
  "message": "User activated successfully",
  "userId": "string"
}
```

### 3. Validation de Licence
`POST /validate-license`

Vérifie la validité d'une licence.

**Payload:**
```json
{
  "email": "string",
  "licenseKey": "string",
  "fingerprint": "string"
}
```

**Réponse:**
```json
{
  "valid": true,
  "userId": "string",
  "licenseId": "string",
  "status": "string"
}
```

## Gestion des Erreurs

Toutes les erreurs renvoient un objet JSON avec une clé `error`:
```json
{
  "error": "Description de l'erreur"
}
```

Codes d'erreur:
- 400: Données manquantes ou invalides
- 401: Non autorisé
- 500: Erreur serveur

## Installation

```bash
pip install -r requirements.txt
python app.py
```
