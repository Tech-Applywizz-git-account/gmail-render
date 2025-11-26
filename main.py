from __future__ import print_function #Ensures compatibility with Python 2 and 3 print functions
import os.path #Provides functions for pathname manipulations
import base64 #Used for encoding/decoding binary data to ASCII text
from google.auth.transport.requests import Request #Google's authentication transport layer for making HTTP requests
from google.oauth2.credentials import Credentials #Handles OAuth2 credentials for authentication
from google_auth_oauthlib.flow import InstalledAppFlow #Manages OAuth2 flow for installed applications
from googleapiclient.discovery import build #Used to build Google API service objects

# Permission scope → read-only Gmail access
SCOPES = ['https://www.googleapis.com/auth/gmail.readonly']

def get_gmail_service():
    """Authenticate and return Gmail API service."""
    creds = None

    # Load token.json if exists
    if os.path.exists('token.json'):
        creds = Credentials.from_authorized_user_file('token.json', SCOPES)

    # If no valid token, get a new one using OAuth
    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            creds.refresh(Request())
        else:
            flow = InstalledAppFlow.from_client_secrets_file(
                'credentials.json', SCOPES
            )
            # Use run_local_server instead of run_console (deprecated)
            creds = flow.run_local_server(port=0)

        # Save the new token
        with open('token.json', 'w') as token:
            token.write(creds.to_json())

    # Build Gmail API service
    service = build('gmail', 'v1', credentials=creds)
    return service


def list_full_email_body(service, max_results=None):
    """List emails from the last 24 hours with full body content (text or HTML)."""
    print("\nFetching emails from the last 24 hours...\n")
    
    # Calculate timestamp for 24 hours ago
    import time
    twenty_four_hours_ago = int(time.time() * 1000) - (24 * 60 * 60 * 1000)
    
    # Create query to fetch emails from the last 24 hours
    query = f"after:{twenty_four_hours_ago // 1000}"
    
    # Prepare parameters for the API call
    list_params = {
        'userId': 'me',
        'labelIds': ['INBOX'],
        'q': query
    }
    
    # Only add maxResults if specified
    if max_results is not None:
        list_params['maxResults'] = max_results
    
    results = service.users().messages().list(**list_params).execute()

    messages = results.get('messages', [])

    if not messages:
        print("No emails found in the last 24 hours.")
        # Try without label filter
        list_params.pop('labelIds')
        results = service.users().messages().list(**list_params).execute()
        messages = results.get('messages', [])
        if not messages:
            print("Still no emails found after removing label filter.")
            return

    print(f"Found {len(messages)} emails from the last 24 hours:")
    for msg in messages:
        msg_id = msg['id']
        email = service.users().messages().get(userId='me', id=msg_id).execute()

        # Extract subject from headers
        headers = email['payload']['headers']
        subject = next((h['value'] for h in headers if h['name'] == 'Subject'), "(No Subject)")

        # Get email body content (both plain text or HTML)
        parts = email['payload'].get('parts', [])
        body_content = ""

        for part in parts:
            mime_type = part['mimeType']
            if mime_type == 'text/plain':
                body_content = part['body']['data']  # Extract base64 content
                body_content = base64.urlsafe_b64decode(body_content).decode('utf-8')  # Decode it
                break  # We will use the first plain text body
            elif mime_type == 'text/html':
                body_content = part['body']['data']
                body_content = base64.urlsafe_b64decode(body_content).decode('utf-8')  # Decode HTML body

        print(f"🔹 Email ID: {msg_id}")
        print(f"   Subject: {subject}")
        print(f"   Body: {body_content}")
        print("-" * 50)


def main():
    service = get_gmail_service()
    list_full_email_body(service)

if __name__ == '__main__':
    main()