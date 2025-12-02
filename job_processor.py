"""
Job Application Tracking System
Processes job-related emails and extracts structured job information using AWS Bedrock AI.
"""

import os
import json
import re
from datetime import datetime
from supabase import create_client, Client

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
    """Validate that AWS credentials are properly configured"""
    if not AWS_ACCESS_KEY_ID or not AWS_SECRET_ACCESS_KEY:
        print("WARNING: AWS credentials not set. AI processing will be disabled.")
        print("Please set AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY in your .env file.")
        return False
    
    if not AWS_REGION:
        print("WARNING: AWS_REGION not set. Using default 'us-east-1'.")
    
    print("AWS credentials configured.")
    return True

# Validate AWS credentials on module import
validate_aws_credentials()

def get_bedrock_client():
    """Initialize and return AWS Bedrock client."""
    try:
        import boto3
        from botocore.exceptions import ClientError
        
        # Check if credentials are available
        if not AWS_ACCESS_KEY_ID or not AWS_SECRET_ACCESS_KEY:
            print("AWS credentials not available. AI processing will be disabled.")
            return None
            
        bedrock = boto3.client(
            service_name='bedrock-runtime',
            region_name=AWS_REGION,
            aws_access_key_id=AWS_ACCESS_KEY_ID,
            aws_secret_access_key=AWS_SECRET_ACCESS_KEY
        )
        return bedrock
    except ImportError:
        print("boto3 not installed. AI processing will be disabled. Please install it with: pip install boto3")
        return None
    except Exception as e:
        print(f"Error initializing Bedrock client: {e}")
        return None

def extract_job_details_with_ai(email_data):
    """
    Use AWS Bedrock AI to extract job details from email.
    
    Args:
        email_data (dict): Dictionary containing email subject, body, sender, and timestamp
        
    Returns:
        dict: Extracted job details or None if extraction fails
    """
    bedrock = get_bedrock_client()
    if not bedrock:
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
    Analyze the following job-related email and extract structured information.
    
    Email Details:
    Subject: {email_data.get('subject', '')}
    Sender: {email_data.get('sender', '')}
    Body: {email_data.get('body', '')}
    
    Please extract the following information and return it in JSON format:
    1. job_name: The name/title of the job position
    2. company_name: The name of the company
    3. job_link: Any job application or position link (if available)
    4. req_id: Job requisition ID or reference number (if available)
    5. additional_details: Any other relevant information
    
    Return only valid JSON with these fields. If a field is not found, leave it as an empty string.
    Example response format:
    {{
        "job_name": "Software Engineer",
        "company_name": "Tech Corp",
        "job_link": "https://example.com/job/123",
        "req_id": "REQ-12345",  
        "additional_details": "This is a remote position..."
    }}
    """
    
    try:
        print(f"Calling Bedrock API for job details extraction...")
        # Prepare the request for Bedrock (using converse API for nova-lite model)
        response = bedrock.converse(
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
        
        # Try to parse the JSON result
        try:
            # Extract JSON from the response if it's wrapped in other text
            json_match = re.search(r'\{.*\}', result, re.DOTALL)
            if json_match:
                json_text = json_match.group(0)
                job_details = json.loads(json_text)
                print(f"Successfully extracted job details: {job_details}")
                return job_details
            else:
                # If no JSON found, try parsing the entire result
                job_details = json.loads(result)
                print(f"Successfully extracted job details: {job_details}")
                return job_details
        except json.JSONDecodeError:
            # If JSON parsing fails, return empty job details
            print("Failed to parse AI response as JSON")
            return {
                'job_name': '',
                'company_name': '',
                'job_link': '',
                'req_id': '',
                'additional_details': ''
            }
            
    except Exception as e:
        print(f"Error calling Bedrock API: {e}")
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

def categorize_email_with_ai(email_data):
    """
    Classify email using AWS Bedrock (no keywords, pure LLM classification).
    
    Args:
        email_data (dict): subject, body, sender, timestamp

    Returns:
        str: One of -> "application_submitted", "next_steps", "reject", "other"
    """

    bedrock = get_bedrock_client()
    if not bedrock:
        print("Bedrock client not available for email categorization")
        return "other"

    subject = email_data.get("subject", "")
    email_body = email_data.get("body", "")

    prompt = f"""
    You are an AI assistant that classifies job-related emails with high precision.

    Read the subject and body carefully. Based on the content,
    classify this email into EXACTLY ONE of the following categories:

    1. application_submitted → ONLY IF the email confirms that the candidate's job application was SUCCESSFULLY SUBMITTED. Look for phrases like "thank you for applying", "application received", "we have received your application". Do NOT categorize security codes, password resets, or verification emails as application_submitted.

    2. next_steps → ONLY IF the company is scheduling interviews, assessments, meetings, or requesting additional steps from the candidate AFTER the application has been successfully submitted. Look for phrases like "schedule an interview", "next steps", "assessment", "phone screen", "video interview", "moved to the next phase", "congratulations". DO NOT categorize emails asking to complete or fix an incomplete application as next_steps.

    3. reject → ONLY IF the company declines or rejects the candidate's application. Look for phrases like "unfortunately", "regret to inform", "not been selected", "not moving forward".

    4. other → For ALL OTHER emails that do not clearly fit the above categories. This includes security codes, password resets, general information emails, verification emails, AND emails asking the candidate to complete or fix their application.

    CRITICAL RULES:
    - Security codes, verification codes, or authentication emails should ALWAYS be categorized as "other"
    - Only emails that explicitly confirm receipt of a job application should be "application_submitted"
    - Emails asking to complete or fix an incomplete application should be categorized as "other", NOT "next_steps"
    - Only emails about genuine next steps in the hiring process (assessments, interviews, etc.) AFTER application submission should be "next_steps"
    - Be very strict about these classifications to avoid mislabeling

    Return ONLY a valid JSON with key: "category".

    EMAIL:
    Subject: {subject}
    Body: {email_body}

    Output format example:
    {{
        "category": "application_submitted"
    }}
    """

    try:
        print(f"Calling Bedrock API for email categorization...")
        # Prepare the request for Bedrock (using converse API for nova-lite model)
        response = bedrock.converse(
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
        match = re.search(r'\{.*\}', result_text, re.DOTALL)
        if match:
            result_text = match.group(0)

        data = json.loads(result_text)
        category = data.get("category", "").lower().strip()
        print(f"Email categorized as: {category}")

        # Ensure output is one of the allowed values
        valid = {"application_submitted", "next_steps", "reject", "other"}
        final_category = category if category in valid else "other"
        print(f"Final email category: {final_category}")
        return final_category

    except Exception as e:
        print("AI Classification Error:", e)
        import traceback
        traceback.print_exc()
        return "other"

def convert_category_to_status(category):
    """
    Convert email category to job status.
    
    Args:
        category (str): Email category
        
    Returns:
        str: Job status
    """
    category_to_status = {
        'application_submitted': 'applied',
        'next_steps': 'next_steps',
        'reject': 'rejected',
        'other': 'other'
    }
    return category_to_status.get(category, 'other')

def check_job_exists(user_email, company_name, job_name):
    """
    Check if a job already exists in Supabase for the user.
    
    Args:
        user_email (str): User's email address
        company_name (str): Name of the company
        job_name (str): Name of the job position
        
    Returns:
        dict or None: Existing job data if found, None otherwise
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

def save_job_to_supabase(user_email, job_data):
    """
    Save or update job information in Supabase.
    
    Args:
        user_email (str): User's email address
        job_data (dict): Job information to save
        
    Returns:
        bool: True if successful, False otherwise
    """
    if not supabase:
        print("Supabase client not configured")
        return False
    
    try:
        # Add user email and timestamp to job data
        job_data['user_email'] = user_email
        job_data['created_at'] = datetime.now().isoformat()
        job_data['updated_at'] = datetime.now().isoformat()
        
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
        return False

def process_job_email(user_email, email_data):
    """
    Process a single job-related email through the complete pipeline.
    
    Args:
        user_email (str): User's email address
        email_data (dict): Email data containing subject, body, sender, timestamp
        
    Returns:
        bool: True if processing successful, False otherwise
    """
    try:
        print(f"Processing job email: {email_data.get('subject', '')}")
        print(f"Email sender: {email_data.get('sender', '')}")
        print(f"Email body length: {len(email_data.get('body', ''))} characters")
        
        # STEP 1: Already done - We're working with last 24 hours emails
        
        # STEP 2: Extract raw data (already provided in email_data)
        
        # STEP 3: AI Parser → Extract job details
        print("Extracting job details with AI...")
        job_details = extract_job_details_with_ai(email_data)
        if not job_details:
            print("Failed to extract job details")
            return False
        
        print(f"Extracted job details: {job_details}")
        
        # STEP 4: Categorization
        print("Categorizing email with AI...")
        category = categorize_email_with_ai(email_data)
        print(f"Email category: {category}")
        
        # STEP 5: Convert category → job status
        status = convert_category_to_status(category)
        job_details['status'] = status
        job_details['category'] = category
        print(f"Job status: {status}")
        
        # STEP 6: Check if job already exists
        # (This is handled in the save function)
        
        # STEP 7 & 8: Save job and update status if needed
        job_details['email_timestamp'] = email_data.get('timestamp', '')
        job_details['email_subject'] = email_data.get('subject', '')
        job_details['email_sender'] = email_data.get('sender', '')
        
        print("Saving job to Supabase...")
        success = save_job_to_supabase(user_email, job_details)
        if success:
            print(f"Successfully processed job: {job_details.get('job_name', '')}")
            return True
        else:
            print("Failed to save job to database")
            return False
            
    except Exception as e:
        print(f"Error processing job email: {e}")
        import traceback
        traceback.print_exc()
        return False
