"""
Karmafy Task Mapper
Maps job applications from the local 'jobs' table to the karmafy_task table
in the external karmafy database.

This script:
1. Fetches completed tasks from karmafy_task table from the LAST 2 DAYS (status = 'COMPLETED')
2. Joins with karmafy_scoredjob to get jobTitle and companyName
3. Fetches jobs from the local 'jobs' table
4. Performs fuzzy matching using permutation logic:
   - First tries exact match on both company_name and job_title
   - Then tries match on company_name only
   - Then tries match on job_title only
5. Updates is_email_received = true for matched tasks
"""

import os
import psycopg2
from psycopg2.extras import RealDictCursor
from dotenv import load_dotenv
from datetime import datetime
import re

# Load environment variables
load_dotenv()

# Karmafy Database Configuration
KARMAFY_DB_HOST = os.environ.get('KARMAFY_DB_HOST')
KARMAFY_DB_PORT = os.environ.get('KARMAFY_DB_PORT', '5432')
KARMAFY_DB_NAME = os.environ.get('KARMAFY_DB_NAME')
KARMAFY_DB_USER = os.environ.get('KARMAFY_DB_USER')
KARMAFY_DB_PASSWORD = os.environ.get('KARMAFY_DB_PASSWORD')

# Local Supabase Configuration (for jobs table)
from supabase import create_client, Client
SUPABASE_URL = os.environ.get('SUPABASE_URL')
SUPABASE_KEY = os.environ.get('SUPABASE_KEY')
supabase = create_client(SUPABASE_URL, SUPABASE_KEY) if SUPABASE_URL and SUPABASE_KEY else None


def normalize_text(text):
    """
    Normalize text for comparison by:
    - Converting to lowercase
    - Removing extra whitespace
    - Removing special characters
    
    Args:
        text (str): Text to normalize
        
    Returns:
        str: Normalized text
    """
    if not text:
        return ""
    
    # Convert to lowercase
    text = text.lower()
    
    # Remove special characters, keep alphanumeric and spaces
    text = re.sub(r'[^a-z0-9\s]', '', text)
    
    # Remove extra whitespace
    text = ' '.join(text.split())
    
    return text


def fuzzy_match(text1, text2, threshold=0.8):
    """
    Perform fuzzy matching between two strings.
    
    Args:
        text1 (str): First string
        text2 (str): Second string
        threshold (float): Similarity threshold (0.0 to 1.0)
        
    Returns:
        bool: True if strings match above threshold
    """
    if not text1 or not text2:
        return False
    
    text1_norm = normalize_text(text1)
    text2_norm = normalize_text(text2)
    
    # Exact match after normalization
    if text1_norm == text2_norm:
        return True
    
    # Check if one contains the other (for partial matches)
    if text1_norm in text2_norm or text2_norm in text1_norm:
        return True
    
    # Could add more sophisticated fuzzy matching here (e.g., Levenshtein distance)
    # For now, we use simple containment logic
    
    return False


def get_karmafy_connection():
    """
    Establish connection to Karmafy PostgreSQL database.
    
    Returns:
        psycopg2.connection: Database connection object
    """
    try:
        conn = psycopg2.connect(
            host=KARMAFY_DB_HOST,
            port=KARMAFY_DB_PORT,
            database=KARMAFY_DB_NAME,
            user=KARMAFY_DB_USER,
            password=KARMAFY_DB_PASSWORD
        )
        print(f"✓ Connected to Karmafy database: {KARMAFY_DB_NAME}")
        return conn
    except Exception as e:
        print(f"✗ Error connecting to Karmafy database: {e}")
        import traceback
        traceback.print_exc()
        return None


def fetch_completed_tasks_with_jobs(conn):
    """
    Fetch completed tasks with associated job information and user emails.
    Only fetches tasks from the LAST 2 DAYS.
    
    Joins:
    - karmafy_task (status = 'COMPLETED', last 2 days)
    - karmafy_scoredjob (job details)
    - karmafy_lead (user email)
    
    Args:
        conn: Database connection
        
    Returns:
        list: List of task dictionaries with job and user info
    """
    query = """
    SELECT 
        kt.id AS task_id,
        kt.status,
        kt.is_email_received,
        kt."leadId",
        kt."scored_jobId",
        kj.title AS "jobTitle",
        kj.company AS "companyName",
        ksj.lead_id,
        kl.email AS user_email,
        kl.name AS user_name,
        kt."createdAt"
    FROM 
        public.karmafy_task kt
    INNER JOIN 
        public.karmafy_scoredjob ksj ON kt."scored_jobId" = ksj.id 
            AND kt."leadId" = ksj.lead_id
    INNER JOIN 
        public.karmafy_job kj ON ksj."jobId" = kj.id::text
    INNER JOIN 
        public.karmafy_lead kl ON kt."leadId" = kl.id
    WHERE 
        kt.status = 'COMPLETED'
        AND kt.is_email_received = false
        AND kt."createdAt" >= NOW() - INTERVAL '2 days'
    ORDER BY 
        kt."createdAt" DESC
    """
    
    try:
        with conn.cursor(cursor_factory=RealDictCursor) as cursor:
            cursor.execute(query)
            tasks = cursor.fetchall()
            print(f"✓ Fetched {len(tasks)} completed tasks from Karmafy database (last 2 days)")
            return tasks
    except Exception as e:
        print(f"✗ Error fetching tasks: {e}")
        import traceback
        traceback.print_exc()
        return []


def fetch_jobs_from_supabase(user_email=None):
    """
    Fetch jobs from local Supabase 'jobs' table.
    
    Args:
        user_email (str, optional): Filter by specific user email
        
    Returns:
        list: List of job dictionaries
    """
    if not supabase:
        print("✗ Supabase client not configured")
        return []
    
    try:
        query = supabase.table("jobs").select("*")
        
        if user_email:
            query = query.eq("user_email", user_email)
        
        # IMPORTANT: Only fetch jobs categorized as "Application_Submitted"
        # These are emails where the AI confirmed a job application was submitted
        query = query.eq("category", "application_submitted")
        
        response = query.execute()
        jobs = response.data
        
        print(f"✓ Fetched {len(jobs)} jobs with category='application_submitted' from local database" + 
              (f" for user {user_email}" if user_email else ""))
        return jobs
    except Exception as e:
        print(f"✗ Error fetching jobs from Supabase: {e}")
        import traceback
        traceback.print_exc()
        return []


def match_jobs_with_permutations(karmafy_job_title, karmafy_company_name, local_jobs):
    """
    Match a Karmafy job with local jobs using permutation logic.
    
    Matching strategy (in order of priority):
    1. Both company_name AND job_title match
    2. Only company_name matches
    3. Only job_title matches
    
    Args:
        karmafy_job_title (str): Job title from Karmafy
        karmafy_company_name (str): Company name from Karmafy
        local_jobs (list): List of jobs from local database
        
    Returns:
        dict: Matched job or None
    """
    # Strategy 1: Match both company and job title
    for job in local_jobs:
        local_company = job.get('company_name', '')
        local_job_name = job.get('job_name', '')
        
        company_match = fuzzy_match(karmafy_company_name, local_company)
        job_match = fuzzy_match(karmafy_job_title, local_job_name)
        
        if company_match and job_match:
            print(f"  ✓ FULL MATCH: Company '{karmafy_company_name}' + Job '{karmafy_job_title}'")
            return job
    
    # Strategy 2: Match company name only
    for job in local_jobs:
        local_company = job.get('company_name', '')
        
        if fuzzy_match(karmafy_company_name, local_company):
            print(f"  ✓ COMPANY MATCH: '{karmafy_company_name}'")
            return job
    
    # Strategy 3: Match job title only
    for job in local_jobs:
        local_job_name = job.get('job_name', '')
        
        if fuzzy_match(karmafy_job_title, local_job_name):
            print(f"  ✓ JOB TITLE MATCH: '{karmafy_job_title}'")
            return job
    
    # No match found
    print(f"  ✗ NO MATCH: Company '{karmafy_company_name}', Job '{karmafy_job_title}'")
    return None


def update_task_email_received(conn, task_id):
    """
    Update is_email_received to true for a specific task.
    
    Args:
        conn: Database connection
        task_id (str): Task ID to update
        
    Returns:
        bool: True if successful
    """
    query = """
    UPDATE public.karmafy_task
    SET is_email_received = true
    WHERE id = %s
    """
    
    try:
        with conn.cursor() as cursor:
            cursor.execute(query, (task_id,))
            conn.commit()
            print(f"  ✓ Updated task {task_id}: is_email_received = true")
            return True
    except Exception as e:
        print(f"  ✗ Error updating task {task_id}: {e}")
        conn.rollback()
        return False


def fetch_karmafy_tasks_by_user(user_email, conn):
    """
    Fetch completed tasks for a specific user with associated job information.
    Only fetches tasks from the LAST 2 DAYS.
    
    Args:
        user_email (str): Email of the user to fetch tasks for
        conn: Database connection
        
    Returns:
        list: List of task dictionaries with job and user info
    """
    query = """
    SELECT 
        kt.id AS task_id,
        kt.status,
        kt.is_email_received,
        kt."leadId",
        kt."scored_jobId",
        kj.title AS job_title,
        kj.company AS company_name,
        ksj.lead_id,
        kl.email AS user_email,
        kl.name AS user_name,
        kt."createdAt"
    FROM 
        public.karmafy_task kt
    INNER JOIN 
        public.karmafy_scoredjob ksj ON kt."scored_jobId" = ksj.id 
            AND kt."leadId" = ksj.lead_id
    INNER JOIN 
        public.karmafy_job kj ON ksj."jobId" = kj.id::text
    INNER JOIN 
        public.karmafy_lead kl ON kt."leadId" = kl.id
    WHERE 
        kl.email = %s
        AND kt.status = 'COMPLETED'
        AND kt.is_email_received = false
        AND kt."createdAt" >= NOW() - INTERVAL '2 days'
    ORDER BY 
        kt."createdAt" DESC
    """
    
    try:
        with conn.cursor(cursor_factory=RealDictCursor) as cursor:
            cursor.execute(query, (user_email,))
            tasks = cursor.fetchall()
            print(f"✓ Fetched {len(tasks)} completed tasks for {user_email} (last 2 days)")
            return tasks
    except Exception as e:
        print(f"✗ Error fetching tasks for {user_email}: {e}")
        import traceback
        traceback.print_exc()
        return []


def map_user_emails(user_email):
    """
    Map emails to Karmafy tasks for a specific user.
    This function is called from the Flask app when a user clicks the "Map Emails" button.
    
    Args:
        user_email (str): Email of the user to process
        
    Returns:
        dict: {
            'success': bool,
            'matches_found': int,
            'tasks_processed': int,
            'error': str (if failed),
            'full_matches': int,
            'company_matches': int,
            'job_title_matches': int
        }
    """
    matches_found = 0
    full_matches = 0
    company_matches = 0
    job_title_matches = 0
    tasks_processed = 0
    
    try:
        # Connect to Karmafy database
        karmafy_conn = psycopg2.connect(
            host=KARMAFY_DB_HOST,
            port=KARMAFY_DB_PORT,
            database=KARMAFY_DB_NAME,
            user=KARMAFY_DB_USER,
            password=KARMAFY_DB_PASSWORD
        )
        
        # Fetch tasks for this specific user
        tasks = fetch_karmafy_tasks_by_user(user_email, karmafy_conn)
        tasks_processed = len(tasks)
        
        if tasks_processed == 0:
            karmafy_conn.close()
            return {
                'success': True,
                'matches_found': 0,
                'tasks_processed': 0,
                'full_matches': 0,
                'company_matches': 0,
                'job_title_matches': 0,
                'error': 'No Karmafy tasks found for this user in the last 2 days'
            }
        
        # Fetch local jobs for this user
        local_jobs = fetch_jobs_from_supabase(user_email)
        
        if not local_jobs:
            karmafy_conn.close()
            return {
                'success': True,
                'matches_found': 0,
                'tasks_processed': tasks_processed,
                'full_matches': 0,
                'company_matches': 0,
                'job_title_matches': 0,
                'error': 'No application confirmation emails found for this user'
            }
        
        # Match and update tasks
        for task in tasks:
            karmafy_job = task['job_title']
            karmafy_company = task['company_name']
            
            # Try to find a match
            matched_job = match_jobs_with_permutations(karmafy_job, karmafy_company, local_jobs)
            
            if matched_job:
                # Determine match type for statistics
                company_match = fuzzy_match(karmafy_company, matched_job.get('company_name', ''))
                job_match = fuzzy_match(karmafy_job, matched_job.get('job_name', ''))
                
                if company_match and job_match:
                    full_matches += 1
                elif company_match:
                    company_matches += 1
                else:
                    job_title_matches += 1
                
                # Update the task
                if update_task_email_received(karmafy_conn, task['task_id']):
                    matches_found += 1
        
        # Commit and close
        karmafy_conn.commit()
        karmafy_conn.close()
        
        return {
            'success': True,
            'matches_found': matches_found,
            'tasks_processed': tasks_processed,
            'full_matches': full_matches,
            'company_matches': company_matches,
            'job_title_matches': job_title_matches
        }
        
    except Exception as e:
        error_msg = str(e)
        import traceback
        traceback.print_exc()
        
        return {
            'success': False,
            'matches_found': 0,
            'tasks_processed': 0,
            'full_matches': 0,
            'company_matches': 0,
            'job_title_matches': 0,
            'error': error_msg
        }


def process_mapping():
    """
    Main processing function to map jobs and update tasks.
    """
    print("\n" + "="*80)
    print("KARMAFY TASK MAPPER - Starting Process")
    print("="*80 + "\n")
    
    # Step 1: Connect to Karmafy database
    karmafy_conn = get_karmafy_connection()
    if not karmafy_conn:
        print("✗ Cannot proceed without Karmafy database connection")
        return
    
    try:
        # Step 2: Fetch completed tasks
        print("\n--- Step 1: Fetching Completed Tasks ---")
        tasks = fetch_completed_tasks_with_jobs(karmafy_conn)
        
        if not tasks:
            print("No tasks to process")
            return
        
        # Step 3: Process each task
        print("\n--- Step 2: Processing Tasks ---")
        matched_count = 0
        unmatched_count = 0
        
        for idx, task in enumerate(tasks, 1):
            print(f"\n[Task {idx}/{len(tasks)}] Processing:")
            print(f"  Task ID: {task['task_id']}")
            print(f"  User: {task['user_email']} ({task['user_name']})")
            print(f"  Job Title: {task['jobTitle']}")
            print(f"  Company: {task['companyName']}")
            
            # Fetch jobs for this user
            user_jobs = fetch_jobs_from_supabase(task['user_email'])
            
            if not user_jobs:
                print(f"  ✗ No jobs found for user {task['user_email']}")
                unmatched_count += 1
                continue
            
            # Try to match with permutations
            matched_job = match_jobs_with_permutations(
                task['jobTitle'],
                task['companyName'],
                user_jobs
            )
            
            if matched_job:
                # Update the task
                if update_task_email_received(karmafy_conn, task['task_id']):
                    matched_count += 1
                else:
                    unmatched_count += 1
            else:
                unmatched_count += 1
        
        # Step 4: Summary
        print("\n" + "="*80)
        print("SUMMARY")
        print("="*80)
        print(f"Total tasks processed: {len(tasks)}")
        print(f"Successfully matched: {matched_count}")
        print(f"Not matched: {unmatched_count}")
        print(f"Success rate: {matched_count/len(tasks)*100:.2f}%")
        print("="*80 + "\n")
        
    finally:
        karmafy_conn.close()
        print("✓ Karmafy database connection closed")


if __name__ == "__main__":
    # Validate configuration
    if not all([KARMAFY_DB_HOST, KARMAFY_DB_NAME, KARMAFY_DB_USER, KARMAFY_DB_PASSWORD]):
        print("✗ Missing Karmafy database configuration")
        print("Please set the following environment variables:")
        print("  - KARMAFY_DB_HOST")
        print("  - KARMAFY_DB_NAME")
        print("  - KARMAFY_DB_USER")
        print("  - KARMAFY_DB_PASSWORD")
        print("  - KARMAFY_DB_PORT (optional, defaults to 5432)")
        exit(1)
    
    if not supabase:
        print("✗ Supabase client not configured")
        print("Please set SUPABASE_URL and SUPABASE_KEY in your .env file")
        exit(1)
    
    # Run the mapping process
    process_mapping()
