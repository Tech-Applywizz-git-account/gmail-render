# Gmail Email Dashboard - Multi-User Service

This is a Flask web application that allows multiple users to authenticate with their Gmail accounts and view their latest 100 emails in a dashboard.

## Features

- Multi-user support with individual authentication
- Secure OAuth 2.0 authentication with Google
- Displays latest 100 emails from user's inbox
- Clean, responsive web interface
- Session management and logout functionality

## Prerequisites

- Python 3.7 or higher
- Google Cloud Platform project with Gmail API enabled
- OAuth 2.0 credentials from Google Cloud Console

## Installation

1. Clone or download this repository
2. Install the required packages:
   ```
   pip install -r requirements.txt
   ```

3. Set up Google OAuth credentials:
   - Create a project in Google Cloud Console
   - Enable the Gmail API
   - Create OAuth 2.0 credentials
   - Download the credentials JSON file and save it as `credentials.json` in the project root

## Usage

1. Run the Flask application:
   ```
   python app.py
   ```

2. Open your web browser and navigate to `http://localhost:5000`

3. Click "Login with Google" to authenticate with your Gmail account

4. View your latest 100 emails in the dashboard

5. Use the "Logout" button to sign out

## How It Works

- Each user gets a unique session and token storage
- Authentication tokens are securely stored per user
- The application fetches the latest 100 emails from the authenticated user's inbox
- Email subjects, snippets, and full body content are displayed in the dashboard

## Security Notes

- Tokens are stored locally in the `tokens/` directory
- Each user's tokens are isolated from other users
- Always use HTTPS in production environments
- Change the Flask secret key in production

## Files

- `app.py` - Main Flask application with multi-user support
- `main.py` - Command-line interface for single-user usage
- `templates/index.html` - Web interface template
- `credentials.json` - Google OAuth credentials (not included in repo)
- `requirements.txt` - Python package dependencies

## Support

For issues or questions, please open an issue in the repository.