from __future__ import print_function
import os.path
import base64
from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build

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
            # Use run_console to avoid localhost issues
            creds = flow.run_console()

        # Save the new token
        with open('token.json', 'w') as token:
            token.write(creds.to_json())

    # Build Gmail API service
    service = build('gmail', 'v1', credentials=creds)
    return service


def list_full_email_body(service, max_results=100):
    """List latest emails with full body content (text or HTML)."""
    print("\nFetching full email bodies...\n")

    results = service.users().messages().list(
        userId='me',
        maxResults=max_results,
        labelIds=['INBOX']
    ).execute()

    messages = results.get('messages', [])

    if not messages:
        print("No emails found.")
        return

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
    list_full_email_body(service, max_results=100)


if __name__ == '__main__':
    main()