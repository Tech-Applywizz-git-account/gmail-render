from flask import Flask, render_template, session, redirect, url_for, request, flash
from googleapiclient.discovery import build
from google.oauth2.credentials import Credentials
import os.path
import base64
from google.auth.transport.requests import Request
from google_auth_oauthlib.flow import Flow
import uuid
import os
from dotenv import load_dotenv
import json
from datetime import datetime
from supabase import create_client, Client

# Load environment variables
load_dotenv()

# Enable OAuthlib's HTTP support for development
os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'your-secret-key-change-this-in-production')

# Print environment variables for debugging (remove in production)
print("GOOGLE_CLIENT_ID:", os.environ.get('GOOGLE_CLIENT_ID'))
print("GOOGLE_PROJECT_ID:", os.environ.get('GOOGLE_PROJECT_ID'))

# Permission scope
SCOPES = ['https://www.googleapis.com/auth/gmail.readonly']

# Supabase Configuration
SUPABASE_URL = os.environ.get('SUPABASE_URL')
SUPABASE_KEY = os.environ.get('SUPABASE_KEY')
supabase: Client = create_client(SUPABASE_URL, SUPABASE_KEY) if SUPABASE_URL and SUPABASE_KEY else None

# Create credentials dictionary from environment variables
def get_credentials_dict():
    client_id = os.environ.get("GOOGLE_CLIENT_ID")
    project_id = os.environ.get("GOOGLE_PROJECT_ID")
    client_secret = os.environ.get("GOOGLE_CLIENT_SECRET")
    
    # Check if credentials are set
    if not client_id or not project_id or not client_secret:
        raise ValueError("Google OAuth credentials not found in environment variables")
    
    return {
        "installed": {
            "client_id": client_id,
            "project_id": project_id,
            "auth_uri": "https://accounts.google.com/o/oauth2/auth",
            "token_uri": "https://oauth2.googleapis.com/token",
            "auth_provider_x509_cert_url": "https://www.googleapis.com/oauth2/v1/certs",
            "client_secret": client_secret,
            "redirect_uris": ["http://localhost:5000/callback"]
        }
    }

# Store flows in memory (in production, use Redis or database)
flows = {}

# Function to track user login in Supabase
def track_user_login(email):
    if not supabase:
        print("Supabase client not configured")
        return False
    
    try:
        # Check if user already exists
        response = supabase.table("user_tracking").select("*").eq("email", email).execute()
        
        if response.data:
            # Update existing user
            supabase.table("user_tracking").update({
                "last_login": datetime.now().isoformat(),
                "login_count": response.data[0]["login_count"] + 1,
                "updated_at": datetime.now().isoformat()
            }).eq("email", email).execute()
        else:
            # Insert new user
            supabase.table("user_tracking").insert({
                "email": email,
                "first_login": datetime.now().isoformat(),
                "last_login": datetime.now().isoformat(),
                "login_count": 1
            }).execute()
            
        return True
    except Exception as e:
        print(f"Error tracking user in Supabase: {e}")
        return False

# Function to get user tracking data from Supabase
def get_user_tracking_data():
    if not supabase:
        print("Supabase client not configured")
        return {"users": []}
    
    try:
        response = supabase.table("user_tracking").select("*").execute()
        return {"users": response.data}
    except Exception as e:
        print(f"Error reading user tracking data from Supabase: {e}")
        return {"users": []}

# Function to save emails to Supabase
def save_emails_to_supabase(user_email, emails):
    if not supabase:
        print("Supabase client not configured")
        return False
    
    try:
        # Save emails as JSON in Supabase
        supabase.table("user_emails").insert({
            "user_email": user_email,
            "email_data": emails
        }).execute()
        
        print(f"Saved {len(emails)} emails to Supabase for user {user_email}")
        return True
    except Exception as e:
        print(f"Error saving emails to Supabase: {e}")
        return False

# Function to authenticate and get Gmail service for current user
def get_gmail_service():
    if 'user_id' not in session:
        return None
        
    creds = None
    
    # For Vercel deployment, we'll use session-based token storage
    # In a production environment, you should use a database
    if 'gmail_token' in session:
        # Convert session data back to dictionary if it's a string
        token_data = session['gmail_token']
        if isinstance(token_data, str):
            token_data = json.loads(token_data)
        creds = Credentials.from_authorized_user_info(token_data, SCOPES)
    
    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            creds.refresh(Request())
            # Save refreshed credentials to session as JSON string
            session['gmail_token'] = creds.to_json()
        else:
            return None  # Need to re-authenticate
            
    service = build('gmail', 'v1', credentials=creds)
    return service

# Function to fetch email details
def get_emails():
    service = get_gmail_service()
    if not service:
        return []
        
    results = service.users().messages().list(userId='me', labelIds=['INBOX'], maxResults=100).execute()
    messages = results.get('messages', [])
    emails = []

    if not messages:
        return []

    for msg in messages:
        msg_id = msg['id']
        email = service.users().messages().get(userId='me', id=msg_id).execute()
        headers = email['payload']['headers']
        subject = next((h['value'] for h in headers if h['name'] == 'Subject'), "(No Subject)")
        snippet = email.get('snippet', "(No Snippet)")
        
        # Get sender email
        sender = next((h['value'] for h in headers if h['name'] == 'From'), "Unknown")

        # Extracting the email body (Plain text or HTML)
        body_content = ""
        parts = email['payload'].get('parts', [])
        for part in parts:
            mime_type = part['mimeType']
            if mime_type == 'text/plain':
                body_content = part['body']['data']
                body_content = base64.urlsafe_b64decode(body_content).decode('utf-8')
                break
            elif mime_type == 'text/html':
                body_content = part['body']['data']
                body_content = base64.urlsafe_b64decode(body_content).decode('utf-8')

        emails.append({
            "id": msg_id,
            "subject": subject, 
            "snippet": snippet, 
            "body": body_content,
            "sender": sender,
            "timestamp": email.get('internalDate', '')
        })

    return emails

# Dedicated login page route
@app.route('/login-page')
def login_page():
    # If already logged in, redirect to dashboard
    if 'user_id' in session:
        return redirect(url_for('index'))
    
    error = request.args.get('error')
    return render_template('login.html', error=error)

# Login route
@app.route('/login')
def login():
    # Create a unique user ID for this session
    user_id = str(uuid.uuid4())
    session['user_id'] = user_id
    
    try:
        # Create OAuth flow using environment variables
        flow = Flow.from_client_config(
            get_credentials_dict(),
            scopes=SCOPES
        )
        
        # Set the redirect URI
        flow.redirect_uri = url_for('callback', _external=True)
        
        # Store flow for this user
        flows[user_id] = flow
        
        # Generate authorization URL
        auth_url, _ = flow.authorization_url(prompt='consent')
        
        return redirect(auth_url)
        
    except ValueError as e:
        return redirect(url_for('login_page', error=str(e)))
    except Exception as e:
        return redirect(url_for('login_page', error=f"OAuth configuration error: {str(e)}"))

# OAuth callback route
@app.route('/callback')
def callback():
    user_id = session.get('user_id')
    if not user_id or user_id not in flows:
        return redirect(url_for('login_page', error='Session expired. Please try again.'))
    
    flow = flows[user_id]
    
    try:
        # Exchange authorization code for tokens
        flow.fetch_token(authorization_response=request.url)
        
        # Save credentials to session as JSON string
        creds = flow.credentials
        session['gmail_token'] = creds.to_json()
        
        # Get user's email address
        service = build('gmail', 'v1', credentials=creds)
        profile = service.users().getProfile(userId='me').execute()
        user_email = profile.get('emailAddress', 'unknown')
        
        # Track user login
        track_user_login(user_email)
        
        # Clean up flow
        del flows[user_id]
        
        return redirect(url_for('index'))
        
    except Exception as e:
        # Handle OAuth errors
        del flows[user_id]
        error_msg = f"Authentication failed: {str(e)}"
        return redirect(url_for('login_page', error=error_msg))

# Logout route
@app.route('/logout')
def logout():
    # Clear session
    session.clear()
    
    return redirect(url_for('login_page'))

# Admin route to view user tracking data
@app.route('/admin')
def admin():
    tracking_data = get_user_tracking_data()
    return render_template('admin.html', users=tracking_data["users"])

# Flask route to render the emails on the dashboard
@app.route('/')
def index():
    # If not logged in, redirect to login page
    if 'user_id' not in session:
        return redirect(url_for('login_page'))
    
    emails = get_emails()  # Get emails from Gmail API
    
    # Get user's email to save to Supabase
    if 'gmail_token' in session:
        try:
            token_data = session['gmail_token']
            if isinstance(token_data, str):
                token_data = json.loads(token_data)
            
            if token_data and 'client_id' in token_data:
                # We need to get the user's email from the service
                service = get_gmail_service()
                if service:
                    profile = service.users().getProfile(userId='me').execute()
                    user_email = profile.get('emailAddress', 'unknown')
                    # Save emails to Supabase
                    save_emails_to_supabase(user_email, emails)
        except Exception as e:
            print(f"Error getting user email for Supabase save: {e}")
    
    return render_template('index.html', emails=emails)

# Vercel requires this for the app to work
if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=int(os.environ.get('PORT', 5000)))