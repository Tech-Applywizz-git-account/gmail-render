"""
Job Application Tracking System
Processes job-related emails and extracts structured job information using AWS Bedrock AI.

This module provides functions to:
1. Extract structured job details from emails using AI
2. Categorize emails into different job application stages
3. Save job information to a database
4. Process multiple emails efficiently in parallel
"""

import os
import json
import re
from datetime import datetime
from supabase import create_client, Client
from concurrent.futures import ThreadPoolExecutor, as_completed

# Load environment variables from .env file
from dotenv import load_dotenv
load_dotenv()

# AWS Bedrock Configuration - Remove default values for sensitive credentials
AWS_ACCESS_KEY_ID = os.environ.get("AWS_ACCESS_KEY_ID")
AWS_SECRET_ACCESS_KEY = os.environ.get("AWS_SECRET_ACCESS_KEY")
AWS_REGION = os.environ.get("AWS_REGION", "us-east-1")
BEDROCK_MODEL_ID = os.environ.get("BEDROCK_MODEL_ID", "us.amazon.nova-lite-v1:0")

# Supabase Configuration
SUPABASE_URL = os.environ.get('SUPABASE_URL')
SUPABASE_KEY = os.environ.get('SUPABASE_KEY')
supabase = create_client(SUPABASE_URL, SUPABASE_KEY) if SUPABASE_URL and SUPABASE_KEY else None

def validate_aws_credentials():
    """
    Validate that AWS credentials are properly configured for Bedrock API access.
    
    This function checks if the required AWS credentials (access key and secret key) 
    are set in environment variables. It also refreshes the global credential variables
    in case they've been updated since the module was loaded.
    
    Returns:
        bool: True if credentials are valid, False otherwise
        
    Side Effects:
        - Updates global AWS credential variables
        - Prints diagnostic information to stdout
    """
    # Refresh the environment variables in case they've changed
    global AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, AWS_REGION, BEDROCK_MODEL_ID
    AWS_ACCESS_KEY_ID = os.environ.get("AWS_ACCESS_KEY_ID")
    AWS_SECRET_ACCESS_KEY = os.environ.get("AWS_SECRET_ACCESS_KEY")
    AWS_REGION = os.environ.get("AWS_REGION", "us-east-1")
    BEDROCK_MODEL_ID = os.environ.get("BEDROCK_MODEL_ID", "us.amazon.nova-lite-v1:0")
    
    if not AWS_ACCESS_KEY_ID or not AWS_SECRET_ACCESS_KEY:
        print("WARNING: AWS credentials not set. AI processing will be disabled.")
        print("Please set AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY in your .env file or environment variables.")
        print(f"AWS_ACCESS_KEY_ID is set: {bool(AWS_ACCESS_KEY_ID)}")
        print(f"AWS_SECRET_ACCESS_KEY is set: {bool(AWS_SECRET_ACCESS_KEY)}")
        return False
    
    if not AWS_REGION:
        print("WARNING: AWS_REGION not set. Using default 'us-east-1'.")
    
    print("AWS credentials configured.")
    print(f"AWS_REGION: {AWS_REGION}")
    print(f"BEDROCK_MODEL_ID: {BEDROCK_MODEL_ID}")
    return True

def get_bedrock_client():
    """
    Initialize and return AWS Bedrock client for AI processing.
    
    Creates a boto3 client configured to communicate with AWS Bedrock service.
    This client is used for all AI operations including job detail extraction 
    and email categorization.
    
    Returns:
        boto3.client: Configured Bedrock client, or None if initialization fails
        
    Side Effects:
        - May print error messages and stack traces
        - Attempts to import boto3 library
    """
    try:
        import boto3
        from botocore.exceptions import ClientError
        
        # Check if credentials are available
        if not AWS_ACCESS_KEY_ID or not AWS_SECRET_ACCESS_KEY:
            print("AWS credentials not available. AI processing will be disabled.")
            print(f"AWS_ACCESS_KEY_ID set: {bool(AWS_ACCESS_KEY_ID)}")
            print(f"AWS_SECRET_ACCESS_KEY set: {bool(AWS_SECRET_ACCESS_KEY)}")
            return None
            
        print(f"Initializing Bedrock client with region: {AWS_REGION}")
        print(f"Using Bedrock model ID: {BEDROCK_MODEL_ID}")
        
        bedrock = boto3.client(
            service_name='bedrock-runtime',
            region_name=AWS_REGION,
            aws_access_key_id=AWS_ACCESS_KEY_ID,
            aws_secret_access_key=AWS_SECRET_ACCESS_KEY
        )
        return bedrock
    except ImportError as e:
        print(f"boto3 not installed. AI processing will be disabled. Please install it with: pip install boto3. Error: {e}")
        return None
    except Exception as e:
        print(f"Error initializing Bedrock client: {e}")
        print(f"AWS_REGION: {AWS_REGION}")
        print(f"BEDROCK_MODEL_ID: {BEDROCK_MODEL_ID}")
        import traceback
        traceback.print_exc()
        return None

def extract_job_details_with_ai_client(bedrock_client, email_data):
    """
    Use AWS Bedrock AI to extract job details from email with provided client.
    
    Sends an email to the Bedrock AI model with a prompt asking it to extract
    structured job information such as job name, company name, job link, etc.
    The function handles JSON parsing of the AI response and error cases.
    
    Args:
        bedrock_client: Initialized Bedrock client for API communication
        email_data (dict): Dictionary containing email subject, body, sender, and timestamp
        
    Returns:
        dict: Extracted job details with keys:
            - job_name (str): Name/title of the job position
            - company_name (str): Name of the company
            - job_link (str): Job application or position link (if available)
            - req_id (str): Job requisition ID or reference number (if available)
            - additional_details (str): Any other relevant information
            Returns empty strings for all fields if extraction fails.
            
    Side Effects:
        - Makes API call to AWS Bedrock service
        - May print diagnostic information and error messages
    """
    if not bedrock_client:
        # Return empty job details if Bedrock is not available
        print("Bedrock client not available")
        return {
            'job_name': '',
            'company_name': '',
            'job_link': '',
            'req_id': '',
            'additional_details': ''
        }
    
    # Prepare the prompt for the AI model
    prompt = f"""
You are an expert job application analyst. Your task is to extract structured job information from the provided email.

EMAIL TO ANALYZE:
Subject: {email_data.get('subject', '')}
Sender: {email_data.get('sender', '')}
Body: {email_data.get('body', '')}

INSTRUCTIONS:
1. Extract the following information and return it in valid JSON format:
   - job_name: The exact job title/position name
   - company_name: The name of the company offering the position
   - job_link: Direct URL to the job posting (if available)
   - req_id: Job requisition/ID number (if available)
   - additional_details: Other relevant information about the position

2. Guidelines:
   - Extract ONLY information explicitly stated in the email
   - If information is not clearly provided, leave the field as an empty string ""
   - Do NOT make assumptions or infer information not directly stated
   - For job_link, only extract URLs that directly point to the job posting
   - Be precise with company names (use the exact legal name when possible)

3. Response Format:
   Return ONLY valid JSON in this exact format:
   {{
       "job_name": "Senior Software Engineer",
       "company_name": "TechCorp Inc.",
       "job_link": "https://company.com/jobs/12345",
       "req_id": "REQ-7890",
       "additional_details": "Remote position, competitive salary"
   }}

4. Examples:
   Example 1 - Complete information:
   Input: "We're excited to offer you the Senior Developer position at InnovateCo. The role details can be found at https://innovateco.com/careers/positions/67890. Reference ID: IC-DEV-2023."
   Output: {{
       "job_name": "Senior Developer",
       "company_name": "InnovateCo",
       "job_link": "https://innovateco.com/careers/positions/67890",
       "req_id": "IC-DEV-2023",
       "additional_details": ""
   }}

   Example 2 - Partial information:
   Input: "Thank you for your interest in the Marketing Manager role at BrandCorp."
   Output: {{
       "job_name": "Marketing Manager",
       "company_name": "BrandCorp",
       "job_link": "",
       "req_id": "",
       "additional_details": ""
   }}

EXTRACTION RESULT:
"""
    
    try:
        print(f"Calling Bedrock API for job details extraction...")
        # Prepare the request for Bedrock (using converse API for nova-lite model)
        response = bedrock_client.converse(
            modelId=BEDROCK_MODEL_ID,
            messages=[
                {
                    "role": "user",
                    "content": [{"text": prompt}]
                }
            ],
            inferenceConfig={
                "maxTokens": 1000,
                "temperature": 0.5,
                "topP": 0.9
            }
        )
        
        # Parse the response
        result = response['output']['message']['content'][0]['text']
        print(f"Bedrock API response received for job details extraction")
        
        # Try to parse the JSON result with enhanced error handling
        try:
            # First try to extract JSON from the response if it's wrapped in other text
            json_match = re.search(r'\{[^{]*(?:"job_name"|"company_name"|"job_link"|"req_id"|"additional_details")[^}]*\}', result, re.DOTALL)
            if json_match:
                json_text = json_match.group(0)
                job_details = json.loads(json_text)
            else:
                # If no JSON found with our pattern, try parsing the entire result
                job_details = json.loads(result)
            
            # Validate that we have the expected keys
            expected_keys = ['job_name', 'company_name', 'job_link', 'req_id', 'additional_details']
            for key in expected_keys:
                if key not in job_details:
                    job_details[key] = ""
            
            print(f"Successfully extracted job details: {job_details}")
            return job_details
        except json.JSONDecodeError as e:
            # If JSON parsing fails, try to fix common issues
            print(f"Initial JSON parsing failed: {e}")
            try:
                # Try to fix common JSON issues
                fixed_result = result.strip()
                # Remove any trailing commas before closing braces/brackets
                fixed_result = re.sub(r',(\s*[}\]])', r'\1', fixed_result)
                # Replace single quotes with double quotes for string values
                fixed_result = re.sub(r"'([^']*)':", r'"\1":', fixed_result)
                fixed_result = re.sub(r":\s*'([^']*)'", r': "\1"', fixed_result)
                
                # Try to extract JSON again
                json_match = re.search(r'\{[^{]*(?:"job_name"|"company_name"|"job_link"|"req_id"|"additional_details")[^}]*\}', fixed_result, re.DOTALL)
                if json_match:
                    json_text = json_match.group(0)
                    job_details = json.loads(json_text)
                else:
                    job_details = json.loads(fixed_result)
                
                # Validate that we have the expected keys
                expected_keys = ['job_name', 'company_name', 'job_link', 'req_id', 'additional_details']
                for key in expected_keys:
                    if key not in job_details:
                        job_details[key] = ""
                
                print(f"Successfully extracted job details after fixing: {job_details}")
                return job_details
            except (json.JSONDecodeError, Exception) as e2:
                # If all else fails, return empty job details
                print(f"All JSON parsing attempts failed. Error: {e2}")
                print(f"Raw AI response: {result}")
                return {
                    'job_name': '',
                    'company_name': '',
                    'job_link': '',
                    'req_id': '',
                    'additional_details': ''
                }
            
    except Exception as e:
        print(f"Error calling Bedrock API: {e}")
        print(f"Model ID used: {BEDROCK_MODEL_ID}")
        print(f"Prompt length: {len(prompt)} characters")
        import traceback
        traceback.print_exc()
        # Return empty job details
        return {
            'job_name': '',
            'company_name': '',
            'job_link': '',
            'req_id': '',
            'additional_details': ''
        }

def extract_job_details_with_ai(email_data):
    """
    Use AWS Bedrock AI to extract job details from email.
    
    Convenience function that initializes a Bedrock client and calls 
    extract_job_details_with_ai_client. This is a wrapper function that
    handles client initialization for simpler use cases.
    
    Args:
        email_data (dict): Dictionary containing email subject, body, sender, and timestamp
        
    Returns:
        dict: Extracted job details (see extract_job_details_with_ai_client for format)
    """
    bedrock_client = get_bedrock_client()
    return extract_job_details_with_ai_client(bedrock_client, email_data)

def categorize_email_with_ai_client(bedrock_client, email_data):
    """
    Classify email using AWS Bedrock with provided client.
    
    Sends an email to the Bedrock AI model with a prompt asking it to categorize
    the email into one of four categories: application_submitted, next_steps, 
    reject, or other. Uses semantic analysis rather than keyword matching.
    
    Args:
        bedrock_client: Initialized Bedrock client for API communication
        email_data (dict): Dictionary containing subject, body, sender, and timestamp
        
    Returns:
        str: One of "application_submitted", "next_steps", "reject", "other"
        
    Side Effects:
        - Makes API call to AWS Bedrock service
        - May print diagnostic information and error messages
    """
    if not bedrock_client:
        print("Bedrock client not available for email categorization")
        return "other"

    # Use ONLY email body for categorization (subject can be misleading)
    email_body = email_data.get("body", "")

    prompt = f"""
You are an expert job application email classifier. Analyze the email body content to determine the correct category.

IMPORTANT: The email content may include HTML artifacts, OCR-extracted text from images, or formatting noise. Focus on the CORE MESSAGE and KEY PHRASES, ignoring technical noise.

EMAIL BODY TO CLASSIFY:
{email_body}

CATEGORIES AND DEFINITIONS:
1. application_submitted - Emails that CONFIRM receipt of a job application or describe the general hiring process WITHOUT requiring IMMEDIATE, SPECIFIC action
   - Positive indicators: "thank you for applying", "we have received your application", "application successfully submitted", "application received", "received your application", "here's what happens next", "our hiring process", "application review process", "candidate selection process", "we will review your application", "our team will evaluate"
   - CRITICAL: Emails describing the general hiring timeline or process (e.g., "here's what happens next: 1. Application Review 2. Assessment Process 3. Candidate Selection") should be classified here, NOT as next_steps
   - Negative indicators (must NOT be in this category): specific requests with links to schedule interviews NOW, specific assessment links to complete NOW, rejection language

2. next_steps - Emails requesting IMMEDIATE, SPECIFIC action with provided links/instructions (interviews, assessments to complete NOW)
   - Positive indicators: "please schedule an interview using this link", "complete this coding assessment by [date]", "click here to schedule your interview", "complete the assessment at [specific URL]", "book your interview slot", "take the assessment now"
   - CRITICAL: Only classify as next_steps if the email contains SPECIFIC, ACTIONABLE requests with links or deadlines - NOT general descriptions of future steps
   - CRITICAL: Emails that say "you will be invited for an interview" or "we may invite you for assessment" are NOT next_steps (they are application_submitted)
   - Negative indicators (must NOT be in this category): general application confirmations, general process descriptions without specific action links, rejections

3. reject - Emails DECLINING or ENDING candidacy
   - Positive indicators: "we've decided not to move forward", "unfortunately, you were not selected", "we will not be proceeding", "position has been filled", "decided not to move forward", "regret to inform", "not selected", "other candidates"
   - Negative indicators (must NOT be in this category): requests for more information, interview scheduling

4. other - ALL other emails including:
   - Security/password emails: "verify your email address", "password reset request"
   - General correspondence: "profile update reminder", "newsletter", "general notifications"
   - Incomplete applications: "your application is incomplete", "please complete your submission"
   - Follow-ups: "checking on your application status" (when sent by applicant)

IMPORTANT CLASSIFICATION RULES:
- Choose ONLY ONE category that BEST fits the email's primary purpose
- When uncertain, prefer "other" over incorrect classification
- Body content is MORE IMPORTANT than subject line
- NEVER classify emails requesting completion of incomplete applications as "next_steps"
- NEVER classify follow-up emails (checking status) as any category except "other"
- NEVER classify rejection follow-ups as "reject" unless they contain explicit rejection language
- IGNORE HTML artifacts like "[Image Content Extracted via OCR]", extra whitespace, or formatting marks
- FOCUS on the actual message content, especially ACTION VERBS and KEY PHRASES
- If the email contains both confirmation AND next steps, classify as "next_steps" (the more important action)

HANDLING NOISY TEXT:
- If you see "[Image Content Extracted via OCR]" or similar markers, the content after is from OCR
- OCR text may have typos or formatting issues - focus on recognizable key phrases
- HTML-extracted text may have repetitive content - look for the core message
- Ignore navigation elements, headers, footers, and boilerplate text

RESPONSE FORMAT:
Respond ONLY with valid JSON in this exact format:
{{"category": "application_submitted"}}

VALID CATEGORIES:
- application_submitted
- next_steps
- reject
- other

CLASSIFICATION RESULT:
"""
    
    try:
        print(f"Calling Bedrock API for email categorization...")
        # Prepare the request for Bedrock (using converse API for nova-lite model)
        response = bedrock_client.converse(
            modelId=BEDROCK_MODEL_ID,
            messages=[
                {
                    "role": "user",
                    "content": [{"text": prompt}]
                }
            ],
            inferenceConfig={
                "maxTokens": 200,
                "temperature": 0.2,
                "topP": 0.8
            }
        )
        
        # Parse the response
        result_text = response['output']['message']['content'][0]['text']
        print(f"Bedrock API response received for email categorization")
        
        # Extract only JSON if there is extra text
        match = re.search(r'\{[^{]*"category"[^}]*\}', result_text, re.DOTALL)
        if match:
            result_text = match.group(0)
        
        # Try to parse JSON with fallbacks
        try:
            data = json.loads(result_text)
        except json.JSONDecodeError:
            # Try to fix common JSON issues
            fixed_result = result_text.strip()
            # Remove any trailing commas before closing braces/brackets
            fixed_result = re.sub(r',(\s*[}\]])', r'\1', fixed_result)
            # Replace single quotes with double quotes for string values
            fixed_result = re.sub(r"'([^']*)':", r'"\1":', fixed_result)
            fixed_result = re.sub(r":\s*'([^']*)'", r': "\1"', fixed_result)
            try:
                data = json.loads(fixed_result)
            except json.JSONDecodeError:
                # Last resort: try to extract category with regex
                category_match = re.search(r'"category"\s*:\s*"([^"]+)"', result_text)
                if category_match:
                    data = {"category": category_match.group(1)}
                else:
                    # If all else fails, default to "other"
                    print(f"Could not parse JSON from AI response: {result_text}")
                    return "other"
        
        category = data.get("category", "").lower().strip()
        print(f"Email categorized as: {category}")
        
        # Ensure output is one of the allowed values
        valid = {"application_submitted", "next_steps", "reject", "other"}
        final_category = category if category in valid else "other"
        print(f"Final email category: {final_category}")
        return final_category
        
    except Exception as e:
        print("AI Classification Error:", e)
        print(f"Model ID used: {BEDROCK_MODEL_ID}")
        print(f"Prompt length: {len(prompt)} characters")
        import traceback
        traceback.print_exc()
        return "other"

def categorize_email_with_ai(email_data):
    """
    Classify email using AWS Bedrock (no keywords, pure LLM classification).
    
    Convenience function that initializes a Bedrock client and calls 
    categorize_email_with_ai_client. This is a wrapper function that
    handles client initialization for simpler use cases.
    
    Args:
        email_data (dict): Dictionary containing subject, body, sender, and timestamp
        
    Returns:
        str: One of "application_submitted", "next_steps", "reject", "other"
    """
    bedrock_client = get_bedrock_client()
    return categorize_email_with_ai_client(bedrock_client, email_data)

def convert_category_to_status(category):
    """
    Convert email category to job status for database storage.
    
    Maps the email categorization results to standardized job application statuses
    that are stored in the database. This provides a consistent way to track
    job application progress across different email types.
    
    Args:
        category (str): Email category from categorization functions
        
    Returns:
        str: Corresponding job status:
            - 'applied' for application_submitted emails
            - 'next_steps' for next_steps emails
            - 'rejected' for reject emails
            - 'other' for other emails
    """
    category_to_status = {
        'application_submitted': 'applied',
        'next_steps': 'next_steps',
        'reject': 'rejected',
        'other': 'other'
    }
    return category_to_status.get(category, 'other')

def get_user_jobs_batch(user_email):
    """
    Fetch all user's jobs in batch for efficient duplicate checking.
    
    Retrieves all job records for a specific user from the database to create
    a lookup dictionary. This is used to efficiently check if a job already
    exists before inserting new records, preventing duplicates.
    
    Args:
        user_email (str): User's email address to filter jobs
        
    Returns:
        dict: Dictionary with (company_name, job_name) tuples as keys and 
              job data as values for fast lookup, or empty dict on error
              
    Side Effects:
        - Makes database query to Supabase
        - May print error messages
    """
    if not supabase:
        print("Supabase client not configured")
        return {}
    
    try:
        response = supabase.table("jobs").select("*").eq("user_email", user_email).execute()
        # Create a lookup dictionary for fast checking
        job_lookup = {(job['company_name'], job['job_name']): job for job in response.data}
        return job_lookup
    except Exception as e:
        print(f"Error fetching user jobs: {e}")
        return {}

def check_job_exists_batch(job_lookup, company_name, job_name):
    """
    Check if a job already exists using batched lookup.
    
    Performs a fast lookup in the pre-fetched job dictionary to check if
    a specific job (identified by company name and job name) already exists.
    This is much faster than querying the database for each individual job.
    
    Args:
        job_lookup (dict): Dictionary with (company_name, job_name) tuples as keys
        company_name (str): Name of the company
        job_name (str): Name of the job position
        
    Returns:
        dict or None: Existing job data if found, None otherwise
    """
    return job_lookup.get((company_name, job_name))

def save_job_to_supabase(user_email, job_data):
    """
    Save or update job information in Supabase.
    
    Inserts a new job record or updates an existing one in the Supabase database.
    Before inserting, it checks if a job with the same company and job name 
    already exists for this user to prevent duplicates.
    
    Args:
        user_email (str): User's email address
        job_data (dict): Job information to save, including job details and metadata
        
    Returns:
        bool: True if successful, False otherwise
        
    Side Effects:
        - May insert or update records in Supabase database
        - May print diagnostic information and error messages
        - Adds timestamp and user email to job_data
    """
    if not supabase:
        print("Supabase client not configured")
        return False
    
    try:
        # Add user email and timestamp to job data
        job_data['user_email'] = user_email
        job_data['created_at'] = datetime.now().isoformat()
        job_data['updated_at'] = datetime.now().isoformat()
        
        # Use the email's actual date instead of current date
        email_timestamp = job_data.get('email_timestamp', '')
        if email_timestamp:
            try:
                # Convert Gmail's internalDate (milliseconds since epoch) to date
                email_date = datetime.fromtimestamp(int(email_timestamp) / 1000).date().isoformat()
                job_data['date'] = email_date
            except (ValueError, TypeError):
                # If conversion fails, use current date as fallback
                job_data['date'] = datetime.now().date().isoformat()
                print(f"Warning: Could not parse email timestamp '{email_timestamp}', using current date")
        else:
            # If no timestamp, use current date
            job_data['date'] = datetime.now().date().isoformat()
        
        # Check if job already exists
        existing_job = check_job_exists(user_email, job_data.get('company_name', ''), job_data.get('job_name', ''))
        
        if existing_job:
            # Update existing job
            job_id = existing_job['id']
            job_data['updated_at'] = datetime.now().isoformat()
            # Preserve the original created_at timestamp
            if 'created_at' in job_data:
                del job_data['created_at']
            
            response = supabase.table("jobs").update(job_data).eq("id", job_id).execute()
            print(f"Updated existing job: {job_data.get('job_name', '')}")
        else:
            # Insert new job
            response = supabase.table("jobs").insert(job_data).execute()
            print(f"Inserted new job: {job_data.get('job_name', '')}")
        
        return True
    except Exception as e:
        print(f"Error saving job to Supabase: {e}")
        import traceback
        traceback.print_exc()
        return False

def save_job_to_supabase_batch(user_email, job_data, job_lookup):
    """
    Save or update job information in Supabase using batch lookup.
    
    Similar to save_job_to_supabase but uses a pre-fetched job lookup dictionary
    for faster duplicate checking. This is more efficient when processing
    multiple jobs for the same user.
    
    Args:
        user_email (str): User's email address
        job_data (dict): Job information to save
        job_lookup (dict): Batch lookup dictionary for duplicate checking
        
    Returns:
        bool: True if successful, False otherwise
        
    Side Effects:
        - May insert or update records in Supabase database
        - May print diagnostic information and error messages
        - Adds timestamp and user email to job_data
    """
    if not supabase:
        print("Supabase client not configured")
        return False
    
    try:
        # Add user email and timestamp to job data
        job_data['user_email'] = user_email
        job_data['created_at'] = datetime.now().isoformat()
        job_data['updated_at'] = datetime.now().isoformat()
        
        # Use the email's actual date instead of current date
        email_timestamp = job_data.get('email_timestamp', '')
        if email_timestamp:
            try:
                # Convert Gmail's internalDate (milliseconds since epoch) to date
                email_date = datetime.fromtimestamp(int(email_timestamp) / 1000).date().isoformat()
                job_data['date'] = email_date
            except (ValueError, TypeError):
                # If conversion fails, use current date as fallback
                job_data['date'] = datetime.now().date().isoformat()
                print(f"Warning: Could not parse email timestamp '{email_timestamp}', using current date")
        else:
            # If no timestamp, use current date
            job_data['date'] = datetime.now().date().isoformat()        
        # Check if job already exists using batch lookup
        existing_job = check_job_exists_batch(
            job_lookup, 
            job_data.get('company_name', ''), 
            job_data.get('job_name', '')
        )
        
        if existing_job:
            # Update existing job
            job_id = existing_job['id']
            job_data['updated_at'] = datetime.now().isoformat()
            # Preserve the original created_at timestamp
            if 'created_at' in job_data:
                del job_data['created_at']
            
            response = supabase.table("jobs").update(job_data).eq("id", job_id).execute()
            print(f"Updated existing job: {job_data.get('job_name', '')}")
        else:
            # Insert new job
            response = supabase.table("jobs").insert(job_data).execute()
            print(f"Inserted new job: {job_data.get('job_name', '')}")
        
        return True
    except Exception as e:
        print(f"Error saving job to Supabase: {e}")
        import traceback
        traceback.print_exc()
        return False

def check_job_exists(user_email, company_name, job_name):
    """
    Check if a job already exists in Supabase for the user.
    
    Queries the database directly to check if a job with the specified
    company name and job name already exists for the given user.
    
    Args:
        user_email (str): User's email address
        company_name (str): Name of the company
        job_name (str): Name of the job position
        
    Returns:
        dict or None: Existing job data if found, None otherwise
        
    Side Effects:
        - Makes database query to Supabase
        - May print error messages
    """
    if not supabase:
        print("Supabase client not configured")
        return None
    
    try:
        response = supabase.table("jobs").select("*").eq("user_email", user_email).eq("company_name", company_name).eq("job_name", job_name).execute()
        if response.data:
            return response.data[0]
        return None
    except Exception as e:
        print(f"Error checking job existence: {e}")
        return None

def process_job_email_optimized(bedrock_client, user_email, email_data, job_lookup=None):
    """
    Process a single job-related email through the complete pipeline with optimized client usage.
    
    Orchestrates the complete job email processing workflow:
    1. Extract structured job details using AI
    2. Categorize the email using AI
    3. Convert category to job status
    4. Save/update job information in database
    
    This function is optimized to reuse an existing Bedrock client and
    optionally use a pre-fetched job lookup for duplicate checking.
    
    Args:
        bedrock_client: Initialized Bedrock client for AI operations
        user_email (str): User's email address
        email_data (dict): Email data containing subject, body, sender, timestamp
        job_lookup (dict): Optional batch lookup for duplicate checking
        
    Returns:
        bool: True if processing successful, False otherwise
        
    Side Effects:
        - Makes API calls to Bedrock and database queries
        - May print diagnostic information and error messages
    """
    try:
        print(f"Processing job email: {email_data.get('subject', '')}")
        print(f"Email sender: {email_data.get('sender', '')}")
        print(f"Email body length: {len(email_data.get('body', ''))} characters")
        
        # Initialize with defaults to ensure we always save something
        category = 'other'
        status = 'other'
        job_details = {
            'job_name': '',
            'company_name': '',
            'job_link': '',
            'req_id': '',
            'additional_details': ''
        }
        
        # Try to categorize with AI (with error handling)
        try:
            # Check for preclassified category from rule-based filtering
            preclassified_category = email_data.get('preclassified_category')
            if preclassified_category:
                print(f"Using preclassified category: {preclassified_category}")
                category = preclassified_category
            else:
                # STEP 4: Categorization using AI
                print("Categorizing email with AI...")
                category = categorize_email_with_ai_client(bedrock_client, email_data)
                print(f"Email category: {category}")
            
            # STEP 5: Convert category → job status
            status = convert_category_to_status(category)
            
            # STEP 3: AI Parser → Extract job details (only for relevant categories)
            if category in ['application_submitted', 'next_steps']:
                print("Extracting job details with AI...")
                try:
                    job_details = extract_job_details_with_ai_client(bedrock_client, email_data)
                    if not job_details:
                        print("Failed to extract job details, using defaults")
                        job_details = {
                            'job_name': '',
                            'company_name': '',
                            'job_link': '',
                            'req_id': '',
                            'additional_details': ''
                        }
                except Exception as extraction_error:
                    print(f"Error extracting job details: {extraction_error}")
                    # Continue with empty job details
                    job_details = {
                        'job_name': '',
                        'company_name': '',
                        'job_link': '',
                        'req_id': '',
                        'additional_details': ''
                    }
        except Exception as categorization_error:
            print(f"Error during AI categorization: {categorization_error}")
            print("Falling back to 'other' category to ensure email is still saved")
            category = 'other'
            status = 'other'
            # job_details already initialized with empty values
        
        print(f"Extracted job details: {job_details}")
        
        job_details['status'] = status
        job_details['category'] = category
        print(f"Job status: {status}")
        
        # STEP 6: Check if job already exists
        # (This is handled in the save function)
        
        # STEP 7 & 8: Save job and update status if needed
        # Always save email data, even if AI processing failed
        job_details['email_timestamp'] = email_data.get('timestamp', '')
        job_details['email_subject'] = email_data.get('subject', '')
        job_details['email_sender'] = email_data.get('sender', '')
        # Add email body to store the entire email content
        job_details['email_body'] = email_data.get('body', '')
        
        print("Saving email to Supabase...")
        if job_lookup is not None:
            success = save_job_to_supabase_batch(user_email, job_details, job_lookup)
        else:
            success = save_job_to_supabase(user_email, job_details)
            
        if success:
            print(f"✓ Successfully saved email: {email_data.get('subject', 'No Subject')[:50]}")
            return True
        else:
            print(f"✗ Failed to save email to database: {email_data.get('subject', 'No Subject')[:50]}")
            return False
            
    except Exception as e:
        print(f"✗ CRITICAL ERROR processing email: {e}")
        print(f"   Subject: {email_data.get('subject', 'No Subject')}")
        import traceback
        traceback.print_exc()
        
        # LAST RESORT: Try to save with minimal data
        try:
            print("Attempting to save email with minimal data as last resort...")
            minimal_data = {
                'job_name': '',
                'company_name': '',
                'job_link': '',
                'req_id': '',
                'additional_details': '',
                'status': 'other',
                'category': 'other',
                'email_timestamp': email_data.get('timestamp', ''),
                'email_subject': email_data.get('subject', ''),
                'email_sender': email_data.get('sender', ''),
                'email_body': email_data.get('body', '')
            }
            if job_lookup is not None:
                success = save_job_to_supabase_batch(user_email, minimal_data, job_lookup)
            else:
                success = save_job_to_supabase(user_email, minimal_data)
            
            if success:
                print("✓ Saved email with minimal data")
                return True
            else:
                print("✗ Failed to save even with minimal data")
                return False
        except Exception as final_error:
            print(f"✗ FINAL ERROR: Could not save email at all: {final_error}")
            return False

def process_job_email(user_email, email_data):
    """
    Process a single job-related email through the complete pipeline.
    
    Convenience function that initializes a Bedrock client and calls 
    process_job_email_optimized. This is a wrapper function for simpler use cases.
    
    Args:
        user_email (str): User's email address
        email_data (dict): Email data containing subject, body, sender, timestamp
        
    Returns:
        bool: True if processing successful, False otherwise
    """
    bedrock_client = get_bedrock_client()
    return process_job_email_optimized(bedrock_client, user_email, email_data)

def process_job_emails_parallel(user_email, emails, max_workers=5):
    """
    Process multiple job emails in parallel for better performance.
    
    Uses ThreadPoolExecutor to process multiple emails concurrently, significantly
    improving performance when dealing with many emails. Reuses a single Bedrock
    client and pre-fetches user jobs for efficient duplicate checking.
    
    Args:
        user_email (str): User's email address
        emails (list): List of email data dictionaries to process
        max_workers (int): Maximum number of parallel workers (default: 5)
        
    Returns:
        int: Number of successfully processed emails
        
    Side Effects:
        - Creates multiple threads for parallel processing
        - Makes API calls to Bedrock and database queries
        - May print diagnostic information and error messages
    """
    if not emails:
        return 0
    
    print(f"Processing {len(emails)} emails in parallel with {max_workers} workers...")
    
    # Initialize Bedrock client once for reuse
    bedrock_client = get_bedrock_client()
    if not bedrock_client:
        print("Bedrock client not available, falling back to sequential processing")
        processed_count = 0
        for email_data in emails:
            if process_job_email_optimized(bedrock_client, user_email, email_data):
                processed_count += 1
        return processed_count
    
    # Fetch all user jobs once for batch duplicate checking
    job_lookup = get_user_jobs_batch(user_email)
    
    # Process emails in parallel
    processed_count = 0
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        # Submit all tasks
        future_to_email = {
            executor.submit(process_job_email_optimized, bedrock_client, user_email, email_data, job_lookup): email_data 
            for email_data in emails
        }
        
        # Collect results as they complete
        for future in as_completed(future_to_email):
            email_data = future_to_email[future]
            try:
                success = future.result()
                if success:
                    processed_count += 1
                    print(f"Successfully processed email: {email_data.get('subject', 'No Subject')}")
                else:
                    print(f"Failed to process email: {email_data.get('subject', 'No Subject')}")
            except Exception as e:
                print(f"Error processing email {email_data.get('subject', 'No Subject')}: {e}")
    
    print(f"Processed {processed_count} out of {len(emails)} emails successfully")
    return processed_count

# Add a simple test function that can be run when executing the script directly
if __name__ == "__main__":
    print("Job Processor Module")
    print("===================")
    if validate_aws_credentials():
        print("AWS credentials are properly configured!")
        print("You can now use this module in your application.")
    else:
        print("Please check your .env file for proper AWS credentials.")