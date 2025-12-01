# Gmail Email Dashboard - Multi-User Service

This is a Flask web application that allows multiple users to authenticate with their Gmail accounts and view their latest emails in a dashboard. The application also includes an automated job application tracking system that processes job-related emails using AWS Bedrock AI.

## Features

- Multi-user support with individual authentication
- Secure OAuth 2.0 authentication with Google
- Displays latest emails from user's inbox (last 24 hours)
- Clean, responsive web interface
- Session management and logout functionality
- **Job Application Tracking System** - Automatically processes job-related emails
- **Fetched Emails View** - Dedicated page to view raw emails without AI processing
- **Enhanced AI Categorization** - Improved email classification accuracy

## Prerequisites

- Python 3.7 or higher
- Google Cloud Platform project with Gmail API enabled
- OAuth 2.0 credentials from Google Cloud Console
- AWS Account with Bedrock access (for AI processing)
- Supabase Account (for data storage)

## Installation

1. Clone or download this repository
2. Install the required packages:
   ```
   pip install -r requirements.txt
   ```

3. Set up Google OAuth credentials:
   - Create a project in Google Cloud Console
   - Enable the Gmail API
   - Create OAuth 2.0 credentials (use "Web application" type)
   - Set environment variables:
     ```
     GOOGLE_CLIENT_ID=your_client_id
     GOOGLE_PROJECT_ID=your_project_id
     GOOGLE_CLIENT_SECRET=your_client_secret
     ```

4. Set up AWS Bedrock for AI processing:
   - Install AWS CLI and configure credentials
   - Or set environment variables:
     ```
     AWS_ACCESS_KEY_ID=your_access_key
     AWS_SECRET_ACCESS_KEY=your_secret_key
     AWS_REGION=us-east-1
     ```

5. Set up Supabase:
   - Create a Supabase project
   - Get your project URL and API key
   - Set environment variables:
     ```
     SUPABASE_URL=your_supabase_url
     SUPABASE_KEY=your_supabase_key
     ```

6. Set Flask secret key:
   ```
   SECRET_KEY=your_secret_key
   ```

## Usage

1. Run the Flask application:
   ```
   python app.py
   ```

2. Open your web browser and navigate to `http://localhost:5000`

3. Click "Login with Google" to authenticate with your Gmail account

4. View your latest emails in the dashboard

5. Use the navigation links to access different sections:
   - **Recent Emails** - View latest processed emails
   - **Fetched Emails** - View raw emails without AI processing
   - **Job Applications** - View tracked job applications
   - **Process Stored Emails** - Manually trigger AI processing of stored emails

6. Use the "Logout" button to sign out

## Job Application Tracking System

The application includes an automated job application tracking system that:

1. **Fetches last 24 hours Gmail Emails** - Only processes recent emails to avoid re-processing old data
2. **Extracts raw data** - Captures subject, body, sender, and timestamp from each email
3. **AI Parser** - Uses AWS Bedrock to extract structured job information:
   - job_name
   - company_name
   - job_link
   - req_id
   - additional_details
4. **Categorization** - Classifies emails as:
   - Application Submitted
   - Next Steps (interviews, assessments, etc.)
   - Reject
   - Other
5. **Status Conversion** - Maps categories to consistent statuses for tracking
6. **Duplicate Prevention** - Checks if jobs already exist in the database
7. **Data Storage** - Saves structured job data to Supabase
8. **Status Updates** - Updates existing jobs when new emails arrive

## Fetched Emails Feature

A dedicated `/fetched-emails` route allows users to view their raw Gmail emails without any AI processing. This feature:
- Displays emails exactly as they appear in Gmail
- Shows subject, sender, body, and timestamp
- Does not involve any LLM processing
- Provides a clean interface for reviewing email content

## Enhanced AI Categorization

The AI email categorization has been improved to better distinguish between different types of emails:
- More accurate identification of "next steps" emails (only after application submission)
- Better filtering of incomplete application requests (categorized as "other")
- Improved security code detection (categorized as "other")

## How It Works

- Each user gets a unique session and token storage
- Authentication tokens are securely stored in session
- The application fetches emails from the authenticated user's inbox
- Email subjects, snippets, and full body content are displayed in the dashboard
- Job-related emails are automatically processed and stored in the jobs table
- Users can manually trigger AI processing of stored emails

## Security Notes

- Tokens are stored in secure session storage
- Each user's data is isolated from other users
- Always use HTTPS in production environments
- Change the Flask secret key in production
- Never commit credentials or tokens to version control

## Files

- `app.py` - Main Flask application with multi-user support
- `job_processor.py` - Job application tracking system and AI processing
- `main.py` - Command-line interface for single-user usage
- `templates/` - Web interface templates
  - `index.html` - Main dashboard
  - `jobs.html` - Job applications view
  - `fetched_emails.html` - Raw emails view
  - `login.html` - Login page
- `requirements.txt` - Python package dependencies

## Support

For issues or questions, please open an issue in the repository.