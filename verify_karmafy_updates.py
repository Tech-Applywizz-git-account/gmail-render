"""
Verify Karmafy Mapper Results
Checks if is_email_received was updated correctly in Karmafy database
"""

import os
import psycopg2
from psycopg2.extras import RealDictCursor
from dotenv import load_dotenv

load_dotenv()

# Karmafy Database Configuration
KARMAFY_DB_HOST = os.environ.get('KARMAFY_DB_HOST')
KARMAFY_DB_PORT = os.environ.get('KARMAFY_DB_PORT', '5432')
KARMAFY_DB_NAME = os.environ.get('KARMAFY_DB_NAME')
KARMAFY_DB_USER = os.environ.get('KARMAFY_DB_USER')
KARMAFY_DB_PASSWORD = os.environ.get('KARMAFY_DB_PASSWORD')

# User to verify
TEST_USER = "govardhankonduru0802@gmail.com"

print("="*80)
print(f"Verifying Mapping Results in Karmafy Database")
print(f"User: {TEST_USER}")
print("="*80)

try:
    # Connect to Karmafy database
    conn = psycopg2.connect(
        host=KARMAFY_DB_HOST,
        port=KARMAFY_DB_PORT,
        database=KARMAFY_DB_NAME,
        user=KARMAFY_DB_USER,
        password=KARMAFY_DB_PASSWORD
    )
    
    print(f"\n✓ Connected to Karmafy database: {KARMAFY_DB_NAME}\n")
    
    # Query 1: Count matched tasks (is_email_received = true)
    query_matched = """
    SELECT 
        COUNT(*) as matched_tasks
    FROM karmafy_task kt
    JOIN karmafy_lead kl ON kt."leadId" = kl.id
    WHERE kl.email = %s
      AND kt.status = 'COMPLETED'
      AND kt.is_email_received = true
      AND kt."createdAt" >= NOW() - INTERVAL '2 days'
    """
    
    # Query 2: Count unmatched tasks (is_email_received = false)
    query_unmatched = """
    SELECT 
        COUNT(*) as unmatched_tasks
    FROM karmafy_task kt
    JOIN karmafy_lead kl ON kt."leadId" = kl.id
    WHERE kl.email = %s
      AND kt.status = 'COMPLETED'
      AND kt.is_email_received = false
      AND kt."createdAt" >= NOW() - INTERVAL '2 days'
    """
    
    # Query 3: Get details of matched tasks
    query_details = """
    SELECT 
        kt.id,
        kj.title AS job_title,
        kj.company AS company_name,
        kt.is_email_received,
        kt."createdAt"
    FROM karmafy_task kt
    JOIN karmafy_lead kl ON kt."leadId" = kl.id
    JOIN karmafy_scoredjob ksj ON kt."scored_jobId" = ksj.id 
        AND kt."leadId" = ksj.lead_id
    JOIN karmafy_job kj ON ksj."jobId" = kj.id::text
    WHERE kl.email = %s
      AND kt.status = 'COMPLETED'
      AND kt.is_email_received = true
      AND kt."createdAt" >= NOW() - INTERVAL '2 days'
    ORDER BY kt."createdAt" DESC
    """
    
    with conn.cursor(cursor_factory=RealDictCursor) as cursor:
        # Get matched count
        cursor.execute(query_matched, (TEST_USER,))
        matched_result = cursor.fetchone()
        matched_count = matched_result['matched_tasks']
        
        # Get unmatched count
        cursor.execute(query_unmatched, (TEST_USER,))
        unmatched_result = cursor.fetchone()
        unmatched_count = unmatched_result['unmatched_tasks']
        
        # Get matched task details
        cursor.execute(query_details, (TEST_USER,))
        matched_tasks = cursor.fetchall()
    
    # Display results
    print("="*80)
    print("VERIFICATION RESULTS")
    print("="*80)
    print(f"✅ Tasks with is_email_received = true:  {matched_count}")
    print(f"❌ Tasks with is_email_received = false: {unmatched_count}")
    print(f"📊 Total tasks (last 2 days):            {matched_count + unmatched_count}")
    
    if matched_count > 0:
        success_rate = (matched_count / (matched_count + unmatched_count)) * 100
        print(f"🎯 Success rate:                         {success_rate:.1f}%")
    
    print("="*80)
    
    if matched_tasks:
        print(f"\nMatched Tasks Details:")
        print("-"*80)
        for idx, task in enumerate(matched_tasks, 1):
            print(f"\n[{idx}] {task['company_name']} - {task['job_title']}")
            print(f"    Task ID: {task['id']}")
            print(f"    Email Received: {task['is_email_received']}")
            print(f"    Created: {task['createdAt']}")
        print("-"*80)
    
    print(f"\n✅ Verification complete!")
    
    conn.close()
    
except Exception as e:
    print(f"\n❌ Error: {e}")
    import traceback
    traceback.print_exc()
