# Gmail Email Dashboard - Multi-User Service

This is a Flask web application that allows multiple users to authenticate with their Gmail accounts and view their latest emails in a dashboard. The application also includes an automated job application tracking system that processes job-related emails using AWS Bedrock AI.

## Features

### Core Features
- Multi-user support with individual authentication
- Secure OAuth 2.0 authentication with Google
- Displays latest emails from user's inbox (last 24 hours)
- Clean, responsive web interface
- Session management and logout functionality

### Job Application Tracking
- **Intelligent Email Categorization** - AI classifies job emails using only email body content
- **Enhanced HTML Processing** - Preserves structure, links, and decodes HTML entities
- **OCR Image Processing** - Extracts text from all images (up to 10 per email)
- **Guaranteed Email Saving** - 3-tier fallback ensures NO email is lost
- **Fetched Emails View** - Dedicated page to view raw emails without AI processing
- **Performance Optimizations** - Parallel processing for faster email handling
- **Date Tracking** - Uses actual email received date, not processing date

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
   - Run the schema updates in `supabase_schema_updates.sql` to add date columns

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

## Performance Improvements

The application now includes several performance optimizations:

1. **Parallel Processing** - Multiple emails are processed concurrently rather than sequentially
2. **Client Reuse** - AWS Bedrock clients are reused across multiple operations
3. **Batch Database Operations** - Database queries are batched for efficiency
4. **Date Indexing** - New date columns enable faster time-based queries

## Deployment

See [DEPLOYMENT.md](DEPLOYMENT.md) for detailed instructions on deploying this application to Vercel and setting up GitHub secrets.

## Job Application Tracking System

The application includes an automated job application tracking system with advanced email processing:

### Email Fetching & Processing
1. **Fetches last 24 hours Gmail Emails** - Automatically retrieves recent emails from inbox
2. **Enhanced HTML Extraction** - Preserves paragraph structure, link text, and decodes HTML entities
3. **OCR Image Processing** - Extracts text from ALL images (up to 10 per email) using Tesseract
4. **Extracts raw data** - Captures subject, body, sender, and timestamp from each email

### AI-Powered Categorization
5. **Body-Only Classification** - AI analyzes ONLY email body content (not subject) for accurate categorization
6. **Smart Categorization** - Classifies emails into 4 categories:
   - **Application Submitted** - Job application confirmations
   - **Next Steps** - Interview/assessment invitations  
   - **Reject** - Application rejections
   - **Other** - Non-job emails (verification codes, newsletters, etc.)
7. **Job Details Extraction** - Uses AWS Bedrock AI to extract:
   - job_name, company_name, job_link, req_id, additional_details

### Data Management
8. **Guaranteed Saving** - 3-tier fallback system ensures ALL emails are saved:
   - Tier 1: Normal AI processing
   - Tier 2: Fallback to 'other' category if AI fails
   - Tier 3: Minimal data save as last resort
9. **Duplicate Prevention** - Updates existing records (same company + job name)
10. **Date Tracking** - Uses actual email received date from Gmail
11. **Data Storage** - Saves all emails to Supabase jobs table

## Fetched Emails Feature

A dedicated `/fetched-emails` route allows users to view their raw Gmail emails without any AI processing. This feature:
- Displays emails exactly as they appear in Gmail
- Shows subject, sender, body, and timestamp
- Does not involve any LLM processing
- Provides a clean interface for reviewing email content

## Recent Improvements (December 2024)

### Enhanced Email Processing
1. **HTML Text Extraction**
   - Preserves paragraph structure and block elements
   - Extracts link text to identify action phrases (e.g., "Schedule Interview")
   - Properly decodes HTML entities (`&nbsp;`, `&amp;`, etc.)
   - Better whitespace normalization

2. **OCR Image Processing**
   - Removed 200-character restriction - now processes ALL images
   - Increased image limit from 5 to 10 per email
   - Detailed logging for OCR operations
   - Handles image-based job emails (interview details in banners)

3. **AI Categorization**
   - Uses ONLY email body (removed subject from analysis)
   - Enhanced prompts handle HTML artifacts and OCR text
   - Focuses on core message and key phrases
   - More accurate identification of email types

4. **Error Handling**
   - 3-tier fallback system prevents data loss
   - ALL fetched emails are guaranteed to be saved
   - Failed categorizations default to 'other' category
   - Comprehensive error logging with visual indicators (✓/✗)

## How It Works

### Authentication Flow
- Each user authenticates via Google OAuth 2.0
- Session tokens are securely stored
- Multi-user support with isolated sessions

### Email Processing Flow
1. Fetches last 24 hours emails from Gmail API
2. Pre-processes email content:
   - Extracts text from HTML with structure preservation
   - Runs OCR on all images to extract text
   - Combines text and OCR content
3. AI categorizes email based on body content only
4. Extracts job details for relevant categories
5. Saves to Supabase with actual email received date
6. Updates existing records if duplicate found

### Data Storage
- ALL emails are saved to `jobs` table
- Email body, subject, sender, and timestamp always stored
- Job details extracted for application/interview/rejection emails
- Date column uses Gmail's actual email date
- Failed processing defaults to 'other' category (still saved)

## Files

- `app.py` - Main Flask application with multi-user support
- `job_processor.py` - Job application tracking system and AI processing with performance optimizations
- `main.py` - Command-line interface for single-user usage
- `templates/` - Web interface templates
  - `index.html` - Main dashboard
  - `jobs.html` - Job applications view
  - `fetched_emails.html` - Raw emails view
  - `login.html` - Login page
- `requirements.txt` - Python package dependencies
- `.env.example` - Template for environment variables
- `supabase_schema_updates.sql` - Database schema updates for date columns
- `DEPLOYMENT.md` - Deployment guide for Vercel and GitHub Actions

## Support

For issues or questions, please open an issue in the repository.