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

# Try to import job processor
try:
    from job_processor import process_job_email
    JOB_PROCESSOR_AVAILABLE = True
    print("Job processor module loaded successfully")
except ImportError as e:
    print(f"Warning: job_processor module not found or has import errors: {e}")
    process_job_email = None
    JOB_PROCESSOR_AVAILABLE = False

# Load environment variables
load_dotenv()

# Enable OAuthlib's HTTP support for development
os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'

# Add debugging for Vercel deployment
print("Starting Flask app...")
print("Environment variables:")
print(f"  SECRET_KEY: {'set' if os.environ.get('SECRET_KEY') else 'not set'}")
print(f"  GOOGLE_CLIENT_ID: {'set' if os.environ.get('GOOGLE_CLIENT_ID') else 'not set'}")
print(f"  GOOGLE_PROJECT_ID: {'set' if os.environ.get('GOOGLE_PROJECT_ID') else 'not set'}")
print(f"  GOOGLE_CLIENT_SECRET: {'set' if os.environ.get('GOOGLE_CLIENT_SECRET') else 'not set'}")
print(f"  SUPABASE_URL: {'set' if os.environ.get('SUPABASE_URL') else 'not set'}")

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'your-secret-key-change-this-in-production')

# Custom filter to format timestamps
@app.template_filter('format_timestamp')
def format_timestamp(timestamp_str):
    try:
        # Convert string to integer
        timestamp_ms = int(timestamp_str)
        # Convert milliseconds to seconds
        timestamp_s = timestamp_ms // 1000
        # Convert to datetime object
        dt = datetime.fromtimestamp(timestamp_s)
        # Format as readable string
        return dt.strftime('%Y-%m-%d %H:%M:%S')
    except (ValueError, TypeError):
        return 'Unknown'

# Configure session for Vercel - more permissive settings for testing
app.config['SESSION_COOKIE_SECURE'] = False  # Changed to False for testing
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['PERMANENT_SESSION_LIFETIME'] = 3600  # 1 hour

# Print environment variables for debugging (remove in production)
print("GOOGLE_CLIENT_ID:", os.environ.get('GOOGLE_CLIENT_ID'))
print("GOOGLE_PROJECT_ID:", os.environ.get('GOOGLE_PROJECT_ID'))

# Permission scope
SCOPES = ['https://www.googleapis.com/auth/gmail.readonly']

# Supabase Configuration
SUPABASE_URL = os.environ.get('SUPABASE_URL')
SUPABASE_KEY = os.environ.get('SUPABASE_KEY')
supabase = create_client(SUPABASE_URL, SUPABASE_KEY) if SUPABASE_URL and SUPABASE_KEY else None

# Create credentials dictionary from environment variables
def get_credentials_dict():
    client_id = os.environ.get("GOOGLE_CLIENT_ID")
    project_id = os.environ.get("GOOGLE_PROJECT_ID")
    client_secret = os.environ.get("GOOGLE_CLIENT_SECRET")
    
    print(f"Google OAuth Environment Variables:")
    print(f"  GOOGLE_CLIENT_ID: {client_id}")
    print(f"  GOOGLE_PROJECT_ID: {project_id}")
    print(f"  GOOGLE_CLIENT_SECRET: {'set' if client_secret else 'not set'}")
    
    # Check if credentials are set
    if not client_id or not project_id or not client_secret:
        raise ValueError("Google OAuth credentials not found in environment variables")
    
    # Define redirect URIs for both localhost and Vercel
    redirect_uris = [
        "http://localhost:5000/callback",
        "http://localhost/callback",
        "https://gmail-render.vercel.app/callback"
    ]
    
    credentials = {
        "installed": {
            "client_id": client_id,
            "project_id": project_id,
            "auth_uri": "https://accounts.google.com/o/oauth2/auth",
            "token_uri": "https://oauth2.googleapis.com/token",
            "auth_provider_x509_cert_url": "https://www.googleapis.com/oauth2/v1/certs",
            "client_secret": client_secret,
            "redirect_uris": redirect_uris
        }
    }
    
    print(f"Generated credentials dict: {credentials}")
    return credentials

# Store flows in memory (in production, use Redis or database)
# For Vercel deployment, we'll use state parameter instead
flows = {}

# Function to track user login in Supabase
def track_user_login(email):
    if not supabase:
        print("Supabase client not configured")
        return False
    
    try:
        print(f"Tracking user login for: {email}")
        # Check if user already exists
        response = supabase.table("user_tracking").select("*").eq("email", email).execute()
        print(f"User lookup response: {response.data}")
        
        if response.data:
            # Update existing user
            print("Updating existing user")
            supabase.table("user_tracking").update({
                "last_login": datetime.now().isoformat(),
                "login_count": response.data[0]["login_count"] + 1,
                "updated_at": datetime.now().isoformat()
            }).eq("email", email).execute()
        else:
            # Insert new user
            print("Inserting new user")
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
        print(f"Saving {len(emails)} emails to Supabase for user {user_email}")
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

# Function to fetch stored emails from Supabase
def get_stored_emails_from_supabase(user_email):
    if not supabase:
        print("Supabase client not configured")
        return []
    
    try:
        print(f"Fetching stored emails from Supabase for user {user_email}")
        response = supabase.table("user_emails").select("*").eq("user_email", user_email).execute()
        emails = []
        for record in response.data:
            # Each record contains email_data as a JSON array
            emails.extend(record.get("email_data", []))
        print(f"Fetched {len(emails)} emails from Supabase storage")
        return emails
    except Exception as e:
        print(f"Error fetching stored emails from Supabase: {e}")
        return []

# Function to process all stored emails with LLM
def process_stored_emails_with_llm(user_email):
    if not JOB_PROCESSOR_AVAILABLE or not process_job_email:
        print("Job processor not available")
        return 0
    
    try:
        print(f"Processing stored emails with LLM for user: {user_email}")
        emails = get_stored_emails_from_supabase(user_email)
        print(f"Found {len(emails)} stored emails to process")
        
        processed_count = 0
        for i, email_data in enumerate(emails):
            print(f"Processing stored email {i+1}/{len(emails)}: {email_data.get('subject', 'No Subject')}")
            # Check if this looks like a job-related email
            subject = email_data.get('subject', '').lower()
            job_keywords = ['application', 'job', 'position', 'interview', 'offer', 'rejected', 'hired']
            
            # Process ALL emails with LLM, not just job-related ones
            if process_job_email:
                success = process_job_email(user_email, email_data)
                if success:
                    processed_count += 1
                    print(f"Successfully processed stored email {i+1}")
                else:
                    print(f"Failed to process stored email {i+1}")
                    
        print(f"Processed {processed_count} stored emails with LLM")
        return processed_count
    except Exception as e:
        print(f"Error processing stored emails with LLM: {e}")
        import traceback
        traceback.print_exc()
        return 0

# Function to authenticate and get Gmail service for current user
def get_gmail_service():
    print(f"get_gmail_service called with session: {dict(session)}")
    
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
            try:
                creds.refresh(Request())
                # Save refreshed credentials to session as JSON string
                session['gmail_token'] = creds.to_json()
            except Exception as e:
                print(f"Error refreshing credentials: {e}")
                return None
        else:
            return None  # Need to re-authenticate
            
    service = build('gmail', 'v1', credentials=creds)
    return service

# Function to fetch email details
def get_emails():
    """Fetch emails from the last 24 hours."""
    print("Fetching emails...")
    service = get_gmail_service()
    if not service:
        print("No Gmail service available")
        return []
        
    try:
        print("Calling Gmail API...")
        # Calculate timestamp for 24 hours ago
        import time
        twenty_four_hours_ago = int(time.time() * 1000) - (24 * 60 * 60 * 1000)
        
        # Create query to fetch emails from the last 24 hours
        query = f"after:{twenty_four_hours_ago // 1000}"
        
        # Fetch emails from the last 24 hours (no maxResults limit)
        results = service.users().messages().list(
            userId='me', 
            labelIds=['INBOX'], 
            q=query
        ).execute()
        print(f"API response: {results}")
        messages = results.get('messages', [])
        emails = []

        if not messages:
            print("No messages found")
            # Try without label filter
            results = service.users().messages().list(userId='me', q=query).execute()
            print(f"API response without label filter: {results}")
            messages = results.get('messages', [])
            if not messages:
                return []

        print(f"Found {len(messages)} messages")
        for msg in messages:
            msg_id = None
            try:
                msg_id = msg['id']
                print(f"Fetching email {msg_id}...")
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
                        if 'data' in part.get('body', {}):
                            body_content = part['body']['data']
                            body_content = base64.urlsafe_b64decode(body_content).decode('utf-8')
                        break
                    elif mime_type == 'text/html':
                        if 'data' in part.get('body', {}):
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
            except Exception as e:
                if msg_id:
                    print(f"Error processing email {msg_id}: {e}")
                else:
                    print(f"Error processing email: {e}")
                continue

        print(f"Returning {len(emails)} emails")
        return emails
    except Exception as e:
        print(f"Error fetching emails: {e}")
        import traceback
        traceback.print_exc()
        return []

# Dedicated login page route
@app.route('/login-page')
def login_page():
    print("Login page route called")
    print(f"Session contents: {dict(session)}")
    
    # If already logged in (has gmail_token), redirect to dashboard
    if 'gmail_token' in session:
        print("Gmail token found, redirecting to index")
        return redirect(url_for('index'))
    
    error = request.args.get('error')
    print(f"Displaying login page with error: {error}")
    return render_template('login.html', error=error)

# Login route
@app.route('/login')
def login():
    print("Login route called")
    print(f"Session before login: {dict(session)}")
    print(f"Request URL: {request.url}")
    print(f"Request host: {request.host}")
    print(f"Request scheme: {request.scheme}")
    
    try:
        # Create OAuth flow using environment variables
        credentials_dict = get_credentials_dict()
        flow = Flow.from_client_config(
            credentials_dict,
            scopes=SCOPES
        )
        
        # Set the redirect URI dynamically based on the request
        flow.redirect_uri = url_for('callback', _external=True)
        
        print(f"Flow redirect URI: {flow.redirect_uri}")
        
        # Generate authorization URL with state parameter for security
        state = str(uuid.uuid4())
        auth_url, _ = flow.authorization_url(prompt='consent', state=state)
        
        # Store state in session for verification
        session['oauth_state'] = state
        session['user_id'] = state  # Use the same state as user_id for simplicity
        
        print(f"Session after setting oauth_state: {dict(session)}")
        print(f"Authorization URL: {auth_url}")
        
        return redirect(auth_url)
        
    except ValueError as e:
        print(f"ValueError in login route: {e}")
        return redirect(url_for('login_page', error=str(e)))
    except Exception as e:
        print(f"Exception in login route: {e}")
        import traceback
        traceback.print_exc()
        return redirect(url_for('login_page', error=f"OAuth configuration error: {str(e)}"))

# OAuth callback route
@app.route('/callback')
def callback():
    print("OAuth callback called")
    print(f"Request URL: {request.url}")
    print(f"Request args: {request.args}")
    print(f"Session before processing: {dict(session)}")
    
    # Get state parameter from callback
    state = request.args.get('state')
    session_state = session.get('oauth_state')
    
    print(f"State from callback: {state}")
    print(f"State from session: {session_state}")
    
    # Verify state parameter to prevent CSRF
    if not state or not session_state or state != session_state:
        print("Invalid state parameter")
        return redirect(url_for('login_page', error='Invalid request. Please try again.'))
    
    try:
        # Create a new flow for token exchange
        credentials_dict = get_credentials_dict()
        flow = Flow.from_client_config(
            credentials_dict,
            scopes=SCOPES
        )
        flow.redirect_uri = url_for('callback', _external=True)
        
        print(f"Callback flow redirect URI: {flow.redirect_uri}")
        print("Attempting to fetch token...")
        
        # Exchange authorization code for tokens
        flow.fetch_token(authorization_response=request.url)
        print("Token exchange successful")
        
        # Save credentials to session as JSON string
        creds = flow.credentials
        session['gmail_token'] = creds.to_json()
        print("Credentials saved to session")
        print(f"Session after saving credentials: {dict(session)}")
        
        # Get user's email address
        service = build('gmail', 'v1', credentials=creds)
        profile = service.users().getProfile(userId='me').execute()
        user_email = profile.get('emailAddress', 'unknown')
        print(f"User email: {user_email}")
        
        # Track user login
        track_user_login(user_email)
        
        # Clean up session state
        session.pop('oauth_state', None)
        print("Flow cleaned up")
        print(f"Session after cleanup: {dict(session)}")
        
        # Explicitly save session for Vercel
        session.permanent = True
        
        return redirect(url_for('index'))
        
    except Exception as e:
        # Handle OAuth errors
        print(f"OAuth callback error: {e}")
        import traceback
        traceback.print_exc()
        session.pop('oauth_state', None)
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

# Jobs dashboard route to view tracked job applications
@app.route('/jobs')
def jobs_dashboard():
    if 'gmail_token' not in session:
        return redirect(url_for('login_page'))
    
    try:
        # Get user's email address
        service = get_gmail_service()
        if service:
            profile = service.users().getProfile(userId='me').execute()
            user_email = profile.get('emailAddress', 'unknown')
            
            # Fetch user's job applications from Supabase
            if supabase:
                response = supabase.table("jobs").select("*").eq("user_email", user_email).order("created_at", desc=True).execute()
                jobs = response.data
            else:
                jobs = []
            
            return render_template('jobs.html', jobs=jobs)
        else:
            return redirect(url_for('login_page'))
    except Exception as e:
        print(f"Error fetching jobs: {e}")
        return render_template('jobs.html', jobs=[], error="Failed to fetch job data")

# Flask route to trigger batch processing of stored emails
@app.route('/process-stored-emails')
def process_stored_emails_route():
    if 'gmail_token' not in session:
        return redirect(url_for('login_page'))
    
    try:
        # Get user's email address
        service = get_gmail_service()
        if service:
            profile = service.users().getProfile(userId='me').execute()
            user_email = profile.get('emailAddress', 'unknown')
            
            # Process all stored emails
            processed_count = process_stored_emails_with_llm(user_email)
            
            return f"Successfully processed {processed_count} stored emails with LLM"
        else:
            return redirect(url_for('login_page'))
    except Exception as e:
        print(f"Error processing stored emails: {e}")
        return f"Error processing stored emails: {str(e)}"

# Flask route to display fetched emails without LLM processing
@app.route('/fetched-emails')
def fetched_emails():
    # Check if user is authenticated
    if 'gmail_token' not in session:
        return redirect(url_for('login_page'))
    
    try:
        print("Fetching emails for fetched-emails route...")
        emails = get_emails()  # Get emails from Gmail API without LLM processing
        print(f"Got {len(emails)} emails for display")
        
        return render_template('fetched_emails.html', emails=emails)
    except Exception as e:
        print(f"Error fetching emails: {e}")
        import traceback
        traceback.print_exc()
        return render_template('fetched_emails.html', emails=[], error="Failed to fetch emails: " + str(e))

# Flask route to render the emails on the dashboard
@app.route('/')
def index():
    print("Index route called")
    print(f"Session contents: {dict(session)}")
    
    # Primary check: if we have Gmail credentials, show the dashboard
    if 'gmail_token' in session:
        print("Gmail token found, displaying dashboard")
        print("Fetching emails...")
        emails = get_emails()  # Get emails from Gmail API
        print(f"Got {len(emails)} emails")
        
        # Process job emails if job processor is available
        if JOB_PROCESSOR_AVAILABLE and process_job_email:
            user_email = None
            try:
                # Get user's email address
                service = get_gmail_service()
                if service:
                    profile = service.users().getProfile(userId='me').execute()
                    user_email = profile.get('emailAddress', 'unknown')
                    print(f"Processing job emails for user: {user_email}")
                    
                    # Process newly fetched emails for job information
                    processed_count = 0
                    for email_data in emails:
                        print(f"Processing newly fetched email: {email_data.get('subject', 'No Subject')}")
                        # Process ALL emails with LLM, not just job-related ones
                        if process_job_email:  # Double-check the function is available
                            success = process_job_email(user_email, email_data)
                            if success:
                                processed_count += 1
                                print(f"Successfully processed newly fetched email")
                            else:
                                print(f"Failed to process newly fetched email")
                    
                    print(f"Processed {processed_count} newly fetched emails with LLM")
                    
                    # Also process previously stored emails
                    stored_processed_count = process_stored_emails_with_llm(user_email)
                    print(f"Additionally processed {stored_processed_count} stored emails with LLM")
                    
            except Exception as e:
                print(f"Error processing job emails: {e}")
        else:
            print("Job processor not available, skipping job email processing")
        
        # Get user's email to save to Supabase
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
                    print(f"Saving emails for user: {user_email}")
                    # Save emails to Supabase
                    save_emails_to_supabase(user_email, emails)
        except Exception as e:
            print(f"Error getting user email for Supabase save: {e}")
        
        return render_template('index.html', emails=emails)
    
    # If no Gmail token but we have user_id, redirect to complete OAuth
    elif 'user_id' in session:
        print("User ID found but no Gmail token, redirecting to login")
        return redirect(url_for('login_page'))
    
    # If neither, redirect to login
    else:
        print("No session found, redirecting to login page")
        return redirect(url_for('login_page'))

# Vercel requires this for the app to work
if __name__ == '__main__':
    print("Starting Flask app in debug mode...")
    app.run(debug=True, host='0.0.0.0', port=int(os.environ.get('PORT', 5000)))
