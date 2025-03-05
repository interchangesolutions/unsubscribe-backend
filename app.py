import os
from flask import Flask, request, jsonify, session, redirect, url_for
from flask_cors import CORS
from flask_sqlalchemy import SQLAlchemy
from googleapiclient.discovery import build
from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from flask_migrate import Migrate
import datetime

from models import User, db
from google_auth_oauthlib.flow import Flow
from list_subscriptions import get_subscriptions, unsubscribe_from_message

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv("DATABASE_URL")
app.config['SECRET_KEY'] = os.getenv("SECRET_KEY")
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
# db.init_app(app)

db = SQLAlchemy(app)
migrate = Migrate(app, db)

# On first run or migration:
# with app.app_context():
#     db.create_all()

CORS(app)  # enable cross-origin requests from Netlify domain

PORT = int(os.environ.get("PORT", 5000))

GOOGLE_SCOPES = [
    'https://www.googleapis.com/auth/userinfo.email',
    'https://www.googleapis.com/auth/gmail.readonly',
    'openid',
    'https://www.googleapis.com/auth/gmail.modify'
]

@app.route("/test-db")
def test_db():
    try:
        result = db.session.execute("SELECT 1;")
        return "Database connected successfully!"
    except Exception as e:
        return f"Database error: {str(e)}"

@app.route('/login')
def login():
    flow = Flow.from_client_config(
        {
            "web": {
                "client_id": os.environ.get("GOOGLE_CLIENT_ID"),
                "client_secret": os.environ.get("GOOGLE_CLIENT_SECRET"),
                "redirect_uris": [os.environ.get("GOOGLE_REDIRECT_URI")],
                "auth_uri": "https://accounts.google.com/o/oauth2/auth",
                "token_uri": "https://oauth2.googleapis.com/token"
            }
        },
        scopes=GOOGLE_SCOPES
    )
    flow.redirect_uri = os.environ.get("GOOGLE_REDIRECT_URI")

    authorization_url, state = flow.authorization_url(
        access_type='offline',
        include_granted_scopes='true',
        prompt='consent'
    )
    session['state'] = state
    return redirect(authorization_url)

@app.route('/oauth/callback')
def oauth_callback():
    state = session.get('state', None)
    if not state:
        return "State missing in session.", 400

    flow = Flow.from_client_config(
        {
            "web": {
                "client_id": os.environ.get("GOOGLE_CLIENT_ID"),
                "client_secret": os.environ.get("GOOGLE_CLIENT_SECRET"),
                "redirect_uris": [os.environ.get("GOOGLE_REDIRECT_URI")],
                "auth_uri": "https://accounts.google.com/o/oauth2/auth",
                "token_uri": "https://oauth2.googleapis.com/token"
            }
        },
        scopes=GOOGLE_SCOPES,
        state=state
    )
    flow.redirect_uri = os.environ.get("GOOGLE_REDIRECT_URI")

    # Exchange the auth code for tokens
    authorization_response = request.url
    flow.fetch_token(authorization_response=authorization_response)

    creds = flow.credentials
    # Now you have access_token, refresh_token, expiry, etc.
    # Next, get the user’s Google profile (email, etc.)
    from googleapiclient.discovery import build
    oauth_service = build('oauth2', 'v2', credentials=creds)
    user_info = oauth_service.userinfo().get().execute()
    email = user_info['email']

    # Check if user exists in DB
    existing_user = User.query.filter_by(email=email).first()
    if not existing_user:
        existing_user = User(email=email)
        db.session.add(existing_user)
    
    existing_user.access_token = creds.token
    existing_user.refresh_token = creds.refresh_token
    existing_user.token_expiry = creds.expiry
    db.session.commit()

    # Log the user in by storing user_id in session
    session['user_id'] = existing_user.id

    # Redirect to some dashboard or home page
    return redirect(url_for('subscriptions'))

@app.route('/subscriptions', methods=['GET'])
def subscriptions():
    if 'user_id' not in session:
        return jsonify({'error': 'Not logged in'}), 401

    user = User.query.get(session['user_id'])
    if not user:
        return jsonify({'error': 'User not found'}), 401

    # Build Credentials object from DB-stored tokens
    creds = Credentials(
        token=user.access_token,
        refresh_token=user.refresh_token,
        token_uri="https://oauth2.googleapis.com/token",
        client_id=os.environ.get("GOOGLE_CLIENT_ID"),
        client_secret=os.environ.get("GOOGLE_CLIENT_SECRET"),
        scopes=GOOGLE_SCOPES
    )

    # Refresh if expired
    if creds.expired and creds.refresh_token:
        creds.refresh(Request())
        user.access_token = creds.token
        user.token_expiry = creds.expiry
        db.session.commit()

    # Now pass creds to our multi-user function
    results = get_subscriptions(creds, max_results=50)
    return jsonify(results)

@app.route('/unsubscribe', methods=['POST'])
def unsubscribe():
    if 'user_id' not in session:
        return jsonify({'error': 'Not logged in'}), 401

    user = User.query.get(session['user_id'])
    if not user:
        return jsonify({'error': 'User not found'}), 401

    creds = Credentials(
        token=user.access_token,
        refresh_token=user.refresh_token,
        token_uri="https://oauth2.googleapis.com/token",
        client_id=os.environ.get("GOOGLE_CLIENT_ID"),
        client_secret=os.environ.get("GOOGLE_CLIENT_SECRET"),
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

    success = unsubscribe_from_message(creds, message_id)
    if success:
        return jsonify({'status': 'success', 'unsubscribed_id': message_id})
    else:
        return jsonify({'status': 'failure', 'message_id': message_id}), 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=PORT)