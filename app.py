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
import re

# Try to import BeautifulSoup for HTML cleaning
try:
    from bs4 import BeautifulSoup
    BS4_AVAILABLE = True
except ImportError:
    BS4_AVAILABLE = False
    BeautifulSoup = None
    print("BeautifulSoup not available. HTML cleaning will use regex fallback.")

# Try to import OCR libraries
try:
    import pytesseract
    from PIL import Image
    OCR_AVAILABLE = True
except ImportError:
    OCR_AVAILABLE = False
    pytesseract = None
    Image = None
    print("OCR libraries not available. Image processing will be skipped.")

# Try to import job processor
try:
    from job_processor import process_job_email, process_job_emails_parallel
    JOB_PROCESSOR_AVAILABLE = True
    print("Job processor module loaded successfully")
except ImportError as e:
    print(f"Warning: job_processor module not found or has import errors: {e}")
    process_job_email = None
    process_job_emails_parallel = None
    JOB_PROCESSOR_AVAILABLE = False

# Load environment variables
load_dotenv()

# Enable OAuthlib's HTTP support for development
os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'

def validate_environment_variables():
    """Validate that all required environment variables are set"""
    required_vars = [
        'SECRET_KEY',
        'GOOGLE_CLIENT_ID',
        'GOOGLE_PROJECT_ID',
        'GOOGLE_CLIENT_SECRET',
        'SUPABASE_URL',
        'SUPABASE_KEY'
    ]
    
    missing_vars = []
    for var in required_vars:
        if not os.environ.get(var):
            missing_vars.append(var)
    
    # Check AWS credentials only if job processor is available
    if JOB_PROCESSOR_AVAILABLE:
        aws_vars = ['AWS_ACCESS_KEY_ID', 'AWS_SECRET_ACCESS_KEY']
        for var in aws_vars:
            if not os.environ.get(var):
                missing_vars.append(var)
    
    if missing_vars:
        print("WARNING: The following environment variables are not set:")
        for var in missing_vars:
            print(f"  - {var}")
        print("Please set these variables in your .env file or environment.")
        return False
    
    print("All required environment variables are set.")
    return True

# Validate environment variables on startup
validate_environment_variables()

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
        raise ValueError("Google OAuth credentials not found in environment variables. Please check your .env file.")
    
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
        # Save emails as JSON in Supabase with date column and email count
        from datetime import datetime
        supabase.table("user_emails").insert({
            "user_email": user_email,
            "email_data": emails,
            "no_of_emails_fetched": len(emails),
            "date": datetime.now().date().isoformat()
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
    if not JOB_PROCESSOR_AVAILABLE or not process_job_emails_parallel:
        print("Job processor not available")
        return 0
    
    try:
        print(f"Processing stored emails with LLM for user: {user_email}")
        emails = get_stored_emails_from_supabase(user_email)
        print(f"Found {len(emails)} stored emails to process")
        
        # Use parallel processing for better performance
        if process_job_emails_parallel:
            processed_count = process_job_emails_parallel(user_email, emails)
        else:
            # Fallback to sequential processing
            processed_count = 0
            for i, email_data in enumerate(emails):
                print(f"Processing stored email {i+1}/{len(emails)}: {email_data.get('subject', 'No Subject')}")
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

                # Extracting the email body with improved preprocessing
                body_content = ""
                # Use our new preprocessing function
                body_content = preprocess_email_content(email['payload'])
                
                # Debug information
                print(f"Email subject: {subject}")
                print(f"Email body length: {len(body_content)}")
                if len(body_content) < 100 and body_content.strip():
                    print(f"Short body content: {body_content[:200]}...")
                elif not body_content.strip():
                    print("WARNING: Empty email body extracted!")
                    # Try to show what parts we have
                    if 'parts' in email['payload']:
                        part_types = [p.get('mimeType', 'unknown') for p in email['payload']['parts']]
                        print(f"Email parts: {part_types}")
                
                # Show when we have image content that might need OCR
                if 'parts' in email['payload']:
                    image_parts = [p for p in email['payload']['parts'] if p.get('mimeType', '').startswith('image/')]
                    if image_parts:
                        print(f"Email contains {len(image_parts)} image parts for potential OCR")
                
                # Simple rule-based filtering for obvious cases
                email_category = None
                if check_rejection_keywords(body_content):
                    email_category = "rejection"
                
                emails.append({
                    "id": msg_id,
                    "subject": subject, 
                    "snippet": snippet, 
                    "body": body_content,
                    "sender": sender,
                    "timestamp": email.get('internalDate', ''),
                    "preclassified_category": email_category  # For optimization
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

# Routes for privacy policy and terms of service
@app.route('/privacy-policy')
@app.route('/privacy-policy.html')
def privacy_policy():
    """Serve the privacy policy page"""
    return render_template('privacy-policy.html')

@app.route('/terms-of-service')
@app.route('/terms-of-service.html')
def terms_of_service():
    """Serve the terms of service page"""
    return render_template('terms-of-service.html')

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
        if JOB_PROCESSOR_AVAILABLE and (process_job_emails_parallel or process_job_email):
            user_email = None
            try:
                # Get user's email address
                service = get_gmail_service()
                if service:
                    profile = service.users().getProfile(userId='me').execute()
                    user_email = profile.get('emailAddress', 'unknown')
                    print(f"Processing job emails for user: {user_email}")
                    
                    # Process newly fetched emails for job information using parallel processing
                    processed_count = 0
                    if process_job_emails_parallel and len(emails) > 1:
                        # Use parallel processing for multiple emails
                        processed_count = process_job_emails_parallel(user_email, emails)
                    elif process_job_email:
                        # Fallback to sequential processing for single email or if parallel processing unavailable
                        for email_data in emails:
                            print(f"Processing newly fetched email: {email_data.get('subject', 'No Subject')}")
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

# Test endpoint for Bedrock functionality
@app.route('/test-bedrock')
def test_bedrock():
    """Dedicated endpoint to test Bedrock functionality"""
    if 'gmail_token' not in session:
        return {"error": "Not authenticated"}, 401
    
    try:
        # Import job processor functions
        from job_processor import (
            validate_aws_credentials,
            get_bedrock_client,
            extract_job_details_with_ai,
            categorize_email_with_ai
        )
        
        # Validate credentials
        credentials_valid = validate_aws_credentials()
        
        # Test Bedrock client
        bedrock_client = get_bedrock_client()
        client_available = bedrock_client is not None
        
        # Test with sample data
        sample_email = {
            "subject": "Job Application Confirmation - Software Engineer Position",
            "sender": "hr@techcompany.com",
            "body": "Thank you for applying to the Software Engineer position at Tech Company. We have received your application and will review it shortly.",
            "timestamp": "2023-10-15T10:30:00Z"
        }
        
        # Test job details extraction
        job_details = extract_job_details_with_ai(sample_email) if client_available else None
        
        # Test email categorization
        category = categorize_email_with_ai(sample_email) if client_available else None
        
        return {
            "bedrock_test": {
                "credentials_valid": credentials_valid,
                "client_available": client_available,
                "job_details_extraction": job_details,
                "email_categorization": category,
                "status": "success" if client_available else "failed"
            }
        }
    except Exception as e:
        return {
            "bedrock_test": {
                "error": str(e),
                "status": "error"
            }
        }, 500

def extract_text_from_html(html_content):
    """
    Extract clean text from HTML content.
    
    Args:
        html_content (str): Raw HTML content
        
    Returns:
        str: Cleaned text content
    """
    if not html_content:
        return ""
    
    try:
        # Use BeautifulSoup if available
        if BS4_AVAILABLE and BeautifulSoup is not None:
            try:
                # Parse HTML and extract text
                soup = BeautifulSoup(html_content, 'html.parser')
                
                # Remove script and style elements
                for script in soup(["script", "style", "head", "title", "meta", "[document]", "noscript"]):
                    script.decompose()
                
                # Add newlines after block elements to preserve structure
                for tag in soup.find_all(['p', 'div', 'br', 'h1', 'h2', 'h3', 'h4', 'h5', 'h6', 'li', 'tr']):
                    tag.append('\n')
                
                # Preserve link text (helps identify "Schedule Interview" links)
                for link in soup.find_all('a'):
                    link_text = link.get_text().strip()
                    if link_text:
                        link.string = f" {link_text} "
                    
                # Get text and clean it
                text = soup.get_text(separator=' ')
                
                # Clean up whitespace
                lines = [line.strip() for line in text.splitlines()]
                lines = [line for line in lines if line]  # Remove empty lines
                text = ' '.join(lines)
                text = re.sub(r'\s+', ' ', text).strip()
                
                # Decode HTML entities
                import html
                text = html.unescape(text)
                
                return text if text else html_content  # Fallback to original if empty
            except Exception as parser_error:
                print(f"Error using BeautifulSoup: {parser_error}")
                # Fallback to regex if BeautifulSoup fails
                pass
        
        # Fallback to regex if BeautifulSoup is not available or fails
        print("Using regex fallback for HTML cleaning")
        # Remove script and style content first
        html_content = re.sub(r'<(script|style|head|title|meta|noscript)[^>]*>.*?</\1>', '', html_content, flags=re.DOTALL | re.IGNORECASE)
        # Remove HTML tags
        clean_text = re.sub(r'<[^<]+?>', ' ', html_content)
        # Clean up whitespace
        clean_text = re.sub(r'\s+', ' ', clean_text).strip()
        # Decode HTML entities
        import html
        clean_text = html.unescape(clean_text)
        return clean_text if clean_text else html_content  # Fallback to original if empty
    except Exception as e:
        print(f"Error cleaning HTML: {e}")
        # Final fallback: try basic regex cleaning
        try:
            # Remove script and style content first
            html_content = re.sub(r'<(script|style|head|title|meta|noscript)[^>]*>.*?</\1>', '', html_content, flags=re.DOTALL | re.IGNORECASE)
            # Remove HTML tags
            clean_text = re.sub(r'<[^<]+?>', ' ', html_content)
            # Clean up whitespace
            clean_text = re.sub(r'\s+', ' ', clean_text).strip()
            # Decode HTML entities
            import html
            clean_text = html.unescape(clean_text)
            return clean_text if clean_text else html_content  # Fallback to original if empty
        except Exception as final_error:
            print(f"Final HTML cleaning fallback failed: {final_error}")
            return html_content  # Ultimate fallback to raw content

def extract_images_from_email_parts(parts):
    """
    Extract image data from email parts for OCR processing.
    
    Args:
        parts (list): Email parts from Gmail API
        
    Returns:
        list: List of image data suitable for OCR
    """
    images = []
    if not OCR_AVAILABLE:
        return images
        
    try:
        for part in parts:
            if part.get('mimeType', '').startswith('image/'):
                if 'data' in part.get('body', {}):
                    image_data = part['body']['data']
                    images.append(image_data)
    except Exception as e:
        print(f"Error extracting images: {e}")
    
    return images

def ocr_image_data(image_data_base64):
    """
    Perform OCR on base64 encoded image data.
    
    Args:
        image_data_base64 (str): Base64 encoded image data
        
    Returns:
        str: Extracted text from image, empty if OCR fails
    """
    if not OCR_AVAILABLE or pytesseract is None or Image is None:
        return ""
        
    try:
        # Decode base64 image data
        image_bytes = base64.urlsafe_b64decode(image_data_base64)
        
        # Create image from bytes
        from io import BytesIO
        image = Image.open(BytesIO(image_bytes))
        
        # Perform OCR
        text = pytesseract.image_to_string(image)
        return text.strip()
    except Exception as e:
        print(f"Error performing OCR: {e}")
        return ""

def preprocess_email_content(email_payload):
    """
    Preprocess email content with proper MIME handling, HTML cleaning, and conditional OCR.
    
    Args:
        email_payload (dict): Email payload from Gmail API
        
    Returns:
        str: Clean, normalized text ready for AI processing
    """
    body_content = ""
    
    try:
        # Handle different email structures
        # Case 1: Email has parts (multipart)
        if 'parts' in email_payload:
            parts = email_payload['parts']
            # Extract all text content from all parts
            text_contents = []
            html_contents = []
            image_data_list = []
            
            def process_part(part):
                """Recursively process email parts"""
                mime_type = part.get('mimeType', '').lower()
                content_text = ""
                
                # Process content if available
                if 'data' in part.get('body', {}):
                    content_data = part['body']['data']
                    try:
                        decoded_content = base64.urlsafe_b64decode(content_data).decode('utf-8')
                        
                        if mime_type == 'text/plain':
                            text_contents.append(decoded_content)
                        elif mime_type == 'text/html':
                            html_contents.append(decoded_content)
                        elif mime_type.startswith('image/'):
                            image_data_list.append(content_data)
                    except Exception as decode_error:
                        print(f"Error decoding content for mime_type {mime_type}: {decode_error}")
                        # Even if we can't decode, keep the raw data for OCR if it's an image
                        if mime_type.startswith('image/'):
                            image_data_list.append(content_data)
                
                # Handle nested parts (recursive)
                if 'parts' in part:
                    for nested_part in part['parts']:
                        process_part(nested_part)
            
            # Process all parts
            for part in parts:
                process_part(part)
            
            # Combine all text contents (plain text takes precedence)
            if text_contents:
                body_content = "\n\n".join(filter(None, text_contents))  # Filter out None/empty values
            elif html_contents:
                # Combine all HTML contents and clean them
                combined_html = "\n\n".join(filter(None, html_contents))  # Filter out None/empty values
                if combined_html:
                    body_content = extract_text_from_html(combined_html)
            
            # If we still don't have content, try to extract from any part
            if not body_content.strip():
                for part in parts:
                    if 'body' in part and 'data' in part['body']:
                        try:
                            content_data = part['body']['data']
                            decoded_content = base64.urlsafe_b64decode(content_data).decode('utf-8')
                            if decoded_content.strip():
                                body_content = decoded_content
                                break
                        except:
                            continue
            
            # Always process images with OCR to extract important information
            # Many job emails have critical details (interview dates, rejection notices) in images
            if image_data_list and OCR_AVAILABLE:
                print(f"Processing OCR on {len(image_data_list)} image(s)...")
                ocr_texts = []
                for i, image_data in enumerate(image_data_list[:10]):  # Process up to 10 images
                    print(f"Extracting text from image {i+1}/{min(len(image_data_list), 10)}...")
                    ocr_text = ocr_image_data(image_data)
                    if ocr_text and ocr_text.strip():
                        ocr_texts.append(ocr_text)
                        print(f"Successfully extracted {len(ocr_text)} characters from image {i+1}")
                
                if ocr_texts:
                    # Append OCR text to existing content
                    ocr_combined = "\n".join(ocr_texts)
                    if body_content.strip():
                        body_content = body_content + "\n\n[Image Content Extracted via OCR]\n" + ocr_combined
                    else:
                        body_content = "[Image Content Extracted via OCR]\n" + ocr_combined
                    print(f"Added {len(ocr_combined)} characters of OCR text to email body")
            elif image_data_list and not OCR_AVAILABLE:
                print(f"WARNING: Found {len(image_data_list)} images but OCR is not available. Install pytesseract and Pillow for better accuracy.")
        
        # Case 2: Simple email without parts (single body)
        elif 'body' in email_payload and 'data' in email_payload['body']:
            body_data = email_payload['body']['data']
            try:
                body_content = base64.urlsafe_b64decode(body_data).decode('utf-8')
                # If it looks like HTML, clean it
                if body_content.strip().startswith('<'):
                    body_content = extract_text_from_html(body_content)
            except Exception as decode_error:
                print(f"Error decoding simple email body: {decode_error}")
                body_content = ""
        
        # Case 3: No body found - try fallback extraction
        else:
            print("No body content found in email payload, trying fallback extraction")
            body_content = extract_any_text_from_payload(email_payload)
            
    except Exception as e:
        print(f"Error in preprocess_email_content: {e}")
        # Fallback: try to extract any available content
        try:
            body_content = extract_any_text_from_payload(email_payload)
        except Exception as fallback_error:
            print(f"Fallback extraction also failed: {fallback_error}")
            body_content = ""
    
    # Final fallback - if still empty, try to get any text
    if not body_content.strip():
        try:
            body_content = extract_any_text_from_payload(email_payload)
        except Exception as final_error:
            print(f"Final fallback extraction failed: {final_error}")
            body_content = ""
    
    # Ensure we return a string, even if empty
    return body_content if body_content is not None else ""

def extract_any_text_from_payload(payload):
    """
    Fallback function to extract any available text from email payload.
    
    Args:
        payload (dict): Email payload from Gmail API
        
    Returns:
        str: Any extracted text content
    """
    texts = []
    
    # Try to extract from body
    if 'body' in payload and 'data' in payload['body']:
        try:
            body_data = payload['body']['data']
            text = base64.urlsafe_b64decode(body_data).decode('utf-8')
            if text.strip():
                if text.strip().startswith('<'):
                    text = extract_text_from_html(text)
                texts.append(text)
        except Exception as e:
            print(f"Error extracting from body: {e}")
            pass
    
    # Try to extract from parts recursively
    if 'parts' in payload:
        for part in payload['parts']:
            try:
                if 'body' in part and 'data' in part['body']:
                    body_data = part['body']['data']
                    text = base64.urlsafe_b64decode(body_data).decode('utf-8')
                    if text.strip():
                        if text.strip().startswith('<'):
                            text = extract_text_from_html(text)
                        texts.append(text)
                elif 'parts' in part:
                    # Recursive call for nested parts
                    nested_text = extract_any_text_from_payload(part)
                    if nested_text and nested_text.strip():
                        texts.append(nested_text)
            except Exception as e:
                print(f"Error processing part: {e}")
                pass
    
    result = "\n\n".join(filter(None, texts)) if texts else ""
    return result

def check_rejection_keywords(text):
    """
    Simple rule-based check for obvious rejection keywords.
    
    Args:
        text (str): Email text content
        
    Returns:
        bool: True if rejection keywords are found
    """
    if not text:
        return False
        
    rejection_keywords = [
        'unfortunately', 'regret to inform', 'not been selected', 'not moving forward',
        'not selected for', 'thank you for your interest', 'we have decided to move forward',
        'another candidate', 'better fit', 'not be able to offer', 'passed on this occasion'
    ]
    
    text_lower = text.lower()
    for keyword in rejection_keywords:
        if keyword in text_lower:
            return True
    return False

# Vercel requires this for the app to work
if __name__ == '__main__':
    print("Starting Flask app in debug mode...")
    app.run(debug=True, host='0.0.0.0', port=int(os.environ.get('PORT', 5000)))