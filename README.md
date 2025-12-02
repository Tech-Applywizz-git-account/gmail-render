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

3. Set up environment variables:
   - Copy `.env.example` to `.env`:
     ```
     cp .env.example .env
     ```
   - Edit `.env` and fill in your actual credentials

4. Set up Google OAuth credentials:
   - Create a project in Google Cloud Console
   - Enable the Gmail API
   - Create OAuth 2.0 credentials (use "Web application" type)
   - Update the corresponding values in your `.env` file

5. Set up AWS Bedrock for AI processing:
   - Create an AWS account and configure Bedrock access
   - Create an IAM user with Bedrock permissions
   - Update the corresponding values in your `.env` file

6. Set up Supabase:
   - Create a Supabase project
   - Get your project URL and API key
   - Update the corresponding values in your `.env` file

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

## Security Best Practices

- Never commit `.env` files or actual credentials to version control
- The `.gitignore` file is configured to exclude `.env` files
- Always use strong, unique passwords for all services
- Regularly rotate your API keys and credentials
- Use HTTPS in production environments
- Change the Flask secret key in production

## Deployment

See [DEPLOYMENT.md](DEPLOYMENT.md) for detailed instructions on deploying this application to Vercel and setting up GitHub secrets.

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
- `.env.example` - Template for environment variables
- `DEPLOYMENT.md` - Deployment guide for Vercel and GitHub Actions

## Support

For issues or questions, please open an issue in the repository.