"""
Karmafy Task Mapper - DRY RUN VERSION
This version performs all matching logic but DOES NOT update the database.
Use this to test matching before running the actual mapper.
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

# Local Supabase Configuration
from supabase import create_client, Client
SUPABASE_URL = os.environ.get('SUPABASE_URL')
SUPABASE_KEY = os.environ.get('SUPABASE_KEY')
supabase = create_client(SUPABASE_URL, SUPABASE_KEY) if SUPABASE_URL and SUPABASE_KEY else None


def normalize_text(text):
    """Normalize text for comparison."""
    if not text:
        return ""
    text = text.lower()
    text = re.sub(r'[^a-z0-9\s]', '', text)
    text = ' '.join(text.split())
    return text


def fuzzy_match(text1, text2, threshold=0.8):
    """Perform fuzzy matching between two strings."""
    if not text1 or not text2:
        return False
    
    text1_norm = normalize_text(text1)
    text2_norm = normalize_text(text2)
    
    if text1_norm == text2_norm:
        return True
    
    if text1_norm in text2_norm or text2_norm in text1_norm:
        return True
    
    return False


def get_karmafy_connection():
    """Establish connection to Karmafy PostgreSQL database."""
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


def fetch_completed_tasks_with_jobs(conn, limit=10):
    """Fetch completed tasks with associated job information and user emails."""
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
    LIMIT %s
    """
    
    try:
        with conn.cursor(cursor_factory=RealDictCursor) as cursor:
            cursor.execute(query, (limit,))
            tasks = cursor.fetchall()
            print(f"✓ Fetched {len(tasks)} completed tasks from Karmafy database (limited to {limit} for dry run)")
            return tasks
    except Exception as e:
        print(f"✗ Error fetching tasks: {e}")
        import traceback
        traceback.print_exc()
        return []


def fetch_jobs_from_supabase(user_email=None):
    """Fetch jobs from local Supabase 'jobs' table."""
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
        
        print(f"  ✓ Fetched {len(jobs)} jobs with status='applied' from local database for user {user_email}")
        return jobs
    except Exception as e:
        print(f"  ✗ Error fetching jobs from Supabase: {e}")
        import traceback
        traceback.print_exc()
        return []


def match_jobs_with_permutations(karmafy_job_title, karmafy_company_name, local_jobs):
    """Match a Karmafy job with local jobs using permutation logic."""
    # Strategy 1: Match both company and job title
    for job in local_jobs:
        local_company = job.get('company_name', '')
        local_job_name = job.get('job_name', '')
        
        company_match = fuzzy_match(karmafy_company_name, local_company)
        job_match = fuzzy_match(karmafy_job_title, local_job_name)
        
        if company_match and job_match:
            return {
                'match_type': 'FULL_MATCH',
                'job': job,
                'message': f"Company '{karmafy_company_name}' + Job '{karmafy_job_title}'"
            }
    
    # Strategy 2: Match company name only
    for job in local_jobs:
        local_company = job.get('company_name', '')
        
        if fuzzy_match(karmafy_company_name, local_company):
            return {
                'match_type': 'COMPANY_MATCH',
                'job': job,
                'message': f"Company '{karmafy_company_name}'"
            }
    
    # Strategy 3: Match job title only
    for job in local_jobs:
        local_job_name = job.get('job_name', '')
        
        if fuzzy_match(karmafy_job_title, local_job_name):
            return {
                'match_type': 'JOB_TITLE_MATCH',
                'job': job,
                'message': f"Job Title '{karmafy_job_title}'"
            }
    
    return None


def process_dry_run(limit=10):
    """Main dry run function - reads data but doesn't update anything."""
    print("\n" + "="*80)
    print("KARMAFY TASK MAPPER - DRY RUN MODE")
    print("="*80)
    print("⚠️  This is a DRY RUN - NO database updates will be performed")
    print("="*80 + "\n")
    
    # Connect to Karmafy database
    karmafy_conn = get_karmafy_connection()
    if not karmafy_conn:
        print("✗ Cannot proceed without Karmafy database connection")
        return
    
    try:
        # Fetch completed tasks
        print(f"\n--- Fetching up to {limit} Completed Tasks (for testing) ---")
        tasks = fetch_completed_tasks_with_jobs(karmafy_conn, limit)
        
        if not tasks:
            print("No tasks to process")
            return
        
        # Process each task
        print("\n--- Processing Tasks (Dry Run) ---\n")
        matches = {
            'FULL_MATCH': [],
            'COMPANY_MATCH': [],
            'JOB_TITLE_MATCH': [],
            'NO_MATCH': []
        }
        
        for idx, task in enumerate(tasks, 1):
            print(f"{'='*80}")
            print(f"[Task {idx}/{len(tasks)}]")
            print(f"{'='*80}")
            print(f"Task ID: {task['task_id']}")
            print(f"User: {task['user_email']} ({task['user_name']})")
            print(f"Karmafy Job Title: {task['jobTitle']}")
            print(f"Karmafy Company: {task['companyName']}")
            print(f"-" * 80)
            
            # Fetch jobs for this user
            user_jobs = fetch_jobs_from_supabase(task['user_email'])
            
            if not user_jobs:
                print(f"  ✗ NO JOBS found in local database for user {task['user_email']}")
                matches['NO_MATCH'].append(task)
                print("")
                continue
            
            # Try to match with permutations
            match_result = match_jobs_with_permutations(
                task['jobTitle'],
                task['companyName'],
                user_jobs
            )
            
            if match_result:
                match_type = match_result['match_type']
                matched_job = match_result['job']
                
                print(f"  ✓ {match_type}: {match_result['message']}")
                print(f"  Matched with local job:")
                print(f"    - Job Name: {matched_job.get('job_name', 'N/A')}")
                print(f"    - Company: {matched_job.get('company_name', 'N/A')}")
                print(f"    - Date: {matched_job.get('date', 'N/A')}")
                print(f"  🔄 WOULD UPDATE: is_email_received = true (DRY RUN - not updating)")
                
                matches[match_type].append({
                    'task': task,
                    'matched_job': matched_job
                })
            else:
                print(f"  ✗ NO MATCH found")
                matches['NO_MATCH'].append(task)
            
            print("")
        
        # Summary
        print("\n" + "="*80)
        print("DRY RUN SUMMARY")
        print("="*80)
        print(f"Total tasks analyzed: {len(tasks)}")
        print(f"")
        print(f"✓ FULL MATCH (Company + Job Title): {len(matches['FULL_MATCH'])}")
        print(f"✓ COMPANY MATCH only: {len(matches['COMPANY_MATCH'])}")
        print(f"✓ JOB TITLE MATCH only: {len(matches['JOB_TITLE_MATCH'])}")
        print(f"✗ NO MATCH: {len(matches['NO_MATCH'])}")
        print(f"")
        
        total_matches = len(matches['FULL_MATCH']) + len(matches['COMPANY_MATCH']) + len(matches['JOB_TITLE_MATCH'])
        success_rate = (total_matches / len(tasks) * 100) if tasks else 0
        
        print(f"Total matches: {total_matches}")
        print(f"Success rate: {success_rate:.2f}%")
        print("="*80)
        
        # Show unmatched details
        if matches['NO_MATCH']:
            print(f"\n--- Unmatched Tasks Details ---")
            for task in matches['NO_MATCH']:
                print(f"❌ {task['user_email']}: {task['companyName']} - {task['jobTitle']}")
        
        print("\n" + "="*80)
        print("⚠️  REMINDER: This was a DRY RUN - no data was modified")
        print("⚠️  To perform actual updates, run: python karmafy_mapper.py")
        print("="*80 + "\n")
        
    finally:
        karmafy_conn.close()
        print("✓ Karmafy database connection closed")


if __name__ == "__main__":
    # Validate configuration
    if not all([KARMAFY_DB_HOST, KARMAFY_DB_NAME, KARMAFY_DB_USER, KARMAFY_DB_PASSWORD]):
        print("✗ Missing Karmafy database configuration")
        print("Please set the following environment variables in your .env file:")
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
    
    # Run dry run with limit of 10 tasks
    print("\nHow many tasks would you like to test? (default: 10)")
    print("Enter a number or press Enter for default:")
    try:
        user_input = input().strip()
        limit = int(user_input) if user_input else 10
    except ValueError:
        limit = 10
    
    process_dry_run(limit)
