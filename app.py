import os
from flask import Flask, request, jsonify, redirect, url_for, session
from flask_jwt_extended import (
    JWTManager,
    create_access_token,
    jwt_required,
    get_jwt_identity
)
from flask_cors import CORS
from flask_sqlalchemy import SQLAlchemy
from werkzeug.middleware.proxy_fix import ProxyFix
from googleapiclient.discovery import build
from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from flask_migrate import Migrate
from sqlalchemy import text
import datetime

from models import User, db
from google_auth_oauthlib.flow import Flow
from list_subscriptions import get_subscriptions, unsubscribe_from_message

# Initialize the app
app = Flask(__name__)
# Set the JWT secret key and other configurations from environment variables
app.config['JWT_SECRET_KEY'] = os.getenv("JWT_SECRET_KEY")
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv("DATABASE_URL")
app.config['SECRET_KEY'] = os.getenv("SECRET_KEY")   # For Flask session signing
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
# Cookie settings in production with HTTPS use:
app.config.update(
    SESSION_COOKIE_SAMESITE="None",
    SESSION_COOKIE_SECURE=True,
)

# Set up proxy fix so Flask correctly detects HTTPS behind reverse proxies
app.wsgi_app = ProxyFix(app.wsgi_app, x_proto=1, x_host=1)

# Initialize JWT and database
jwt = JWTManager(app)
db.init_app(app)
migrate = Migrate(app, db)

# For local testing
# with app.app_context():
#     db.create_all()

# Set up CORS – ensure the FRONTEND_URL environment variable is set to your production front-end origin
CORS(app, supports_credentials=True, origins=[os.getenv("FRONTEND_URL")])

PORT = int(os.environ.get("PORT", 5000))

GOOGLE_SCOPES = [
    'https://www.googleapis.com/auth/userinfo.email',
    'https://www.googleapis.com/auth/gmail.readonly',
    'openid',
    'https://www.googleapis.com/auth/gmail.modify'
]

# @app.route("/test-db")
# def test_db():
#     try:
#         result = db.session.execute(text("SELECT 1;"))
#         row = result.fetchone()  # Fetch result
#         return f"Database connected successfully! Query result: {row[0]}"
#     except Exception as e:
#         return f"Database error: {str(e)}"

# -------------------------------
# OAuth Login Endpoint
# -------------------------------
@app.route('/login')
def login():
    flow = Flow.from_client_config(
        {
            "web": {
                "client_id": os.getenv("GOOGLE_CLIENT_ID"),
                "client_secret": os.getenv("GOOGLE_CLIENT_SECRET"),
                "redirect_uris": [os.getenv("GOOGLE_REDIRECT_URI")],
                "auth_uri": "https://accounts.google.com/o/oauth2/auth",
                "token_uri": "https://oauth2.googleapis.com/token"
            }
        },
        scopes=GOOGLE_SCOPES
    )
    flow.redirect_uri = os.getenv("GOOGLE_REDIRECT_URI")

    authorization_url, state = flow.authorization_url(
        access_type='offline',
        include_granted_scopes='true',
        prompt='consent'
    )

    # Store the state in the session for validation on callback.
    session['state'] = state

    return redirect(authorization_url)


# -------------------------------
# OAuth Callback Endpoint
# -------------------------------
@app.route('/oauth/callback')
def oauth_callback():
    state = session.get('state')
    if not state:
        return "State missing in session.", 400

    flow = Flow.from_client_config(
        {
            "web": {
                "client_id": os.getenv("GOOGLE_CLIENT_ID"),
                "client_secret": os.getenv("GOOGLE_CLIENT_SECRET"),
                "redirect_uris": [os.getenv("GOOGLE_REDIRECT_URI")],
                "auth_uri": "https://accounts.google.com/o/oauth2/auth",
                "token_uri": "https://oauth2.googleapis.com/token"
            }
        },
        scopes=GOOGLE_SCOPES,
        state=state
    )
    flow.redirect_uri = os.getenv("GOOGLE_REDIRECT_URI")

    # Exchange the auth code for tokens
    flow.fetch_token(authorization_response=request.url)
    creds = flow.credentials

    # Retrieve user info from Google
    oauth_service = build('oauth2', 'v2', credentials=creds)
    user_info = oauth_service.userinfo().get().execute()
    email = user_info['email']

    # Find or create user in the database
    existing_user = User.query.filter_by(email=email).first()
    if not existing_user:
        existing_user = User(email=email)
        db.session.add(existing_user)
    existing_user.access_token = creds.token
    existing_user.refresh_token = creds.refresh_token
    existing_user.token_expiry = creds.expiry
    db.session.commit()

    # Generate a JWT for the authenticated user. Convert user id to string.
    access_token = create_access_token(identity=str(existing_user.id))
    FRONTEND_DASHBOARD_URL = os.getenv("FRONTEND_DASHBOARD_URL")
    
    # Clear the state from session as it's no longer needed
    session.pop('state', None)
    # Redirect to the front-end dashboard with the JWT as a query parameter
    return redirect(f"{FRONTEND_DASHBOARD_URL}?token={access_token}")


# -------------------------------
# Protected Endpoints
# -------------------------------

# Local testing debug logging
# @jwt.invalid_token_loader
# def invalid_token_callback(error_string):
#     return jsonify({"msg": "Invalid token: " + error_string}), 422

@app.route('/subscriptions', methods=['GET'])
@jwt_required()
def subscriptions():
    current_user_id = get_jwt_identity()
    user = User.query.get(current_user_id)
    if not user:
        return jsonify({'error': 'User not found'}), 401

    # Build Credentials from stored tokens
    creds = Credentials(
        token=user.access_token,
        refresh_token=user.refresh_token,
        token_uri="https://oauth2.googleapis.com/token",
        client_id=os.getenv("GOOGLE_CLIENT_ID"),
        client_secret=os.getenv("GOOGLE_CLIENT_SECRET"),
        scopes=GOOGLE_SCOPES
    )
    # Refresh if expired
    if creds.expired and creds.refresh_token:
        creds.refresh(Request())
        user.access_token = creds.token
        user.token_expiry = creds.expiry
        db.session.commit()

    results = get_subscriptions(creds, max_results=50)
    return jsonify(results)

@app.route('/unsubscribe', methods=['POST'])
@jwt_required()
def unsubscribe():
    current_user_id = get_jwt_identity()
    user = User.query.get(current_user_id)
    if not user:
        return jsonify({'error': 'User not found'}), 401

    creds = Credentials(
        token=user.access_token,
        refresh_token=user.refresh_token,
        token_uri="https://oauth2.googleapis.com/token",
        client_id=os.getenv("GOOGLE_CLIENT_ID"),
        client_secret=os.getenv("GOOGLE_CLIENT_SECRET"),
        scopes=GOOGLE_SCOPES
    )
    if creds.expired and creds.refresh_token:
        creds.refresh(Request())
        user.access_token = creds.token
        user.token_expiry = creds.expiry
        db.session.commit()

    body = request.json
    message_id = body.get('message_id')
    if not message_id:
        return jsonify({'status': 'error', 'message': 'No message_id provided'}), 400

    result = unsubscribe_from_message(creds, message_id)
    if result is True:
        return jsonify({'status': 'success', 'unsubscribed_id': message_id})
    elif isinstance(result, dict) and result.get("status") == "manual":
        return jsonify({
            'status': 'manual',
            'message': f'Manual confirmation required for message {message_id}',
            'confirmation_url': result.get("confirmation_url")
        }), 200
    elif result == "manual":
        return jsonify({
            'status': 'manual',
            'message': f'Manual confirmation required for message {message_id}'
        }), 200
    else:
        return jsonify({'status': 'failure', 'message': f'Failed to unsubscribe message {message_id}'}), 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=PORT)
