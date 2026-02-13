"""
Simple Supabase Connection Test
Tests if we can connect to Supabase and fetch data from the jobs table.
"""

import os
from dotenv import load_dotenv
from supabase import create_client

load_dotenv()

SUPABASE_URL = os.environ.get('SUPABASE_URL')
SUPABASE_KEY = os.environ.get('SUPABASE_KEY')

print("="*80)
print("SUPABASE CONNECTION TEST")
print("="*80)
print(f"\nSupabase URL: {SUPABASE_URL}")
print(f"Supabase Key: {'*' * 20}... (hidden)\n")

try:
    print("Attempting to connect to Supabase...")
    supabase = create_client(SUPABASE_URL, SUPABASE_KEY)
    print("✓ Supabase client created successfully\n")
    
    print("Testing database query (fetching 5 jobs)...")
    response = supabase.table("jobs").select("*").limit(5).execute()
    jobs = response.data
    
    print(f"✓ Successfully fetched {len(jobs)} jobs from database\n")
    
    if jobs:
        print("Sample job:")
        job = jobs[0]
        print(f"  - User Email: {job.get('user_email', 'N/A')}")
        print(f"  - Job Name: {job.get('job_name', 'N/A')}")
        print(f"  - Company: {job.get('company_name', 'N/A')}")
        print(f"  - Date: {job.get('date', 'N/A')}")
    
    print("\n" + "="*80)
    print("✅ SUPABASE CONNECTION: SUCCESS")
    print("="*80)
    
except Exception as e:
    print(f"\n❌ SUPABASE CONNECTION: FAILED")
    print(f"Error: {e}")
    print("\nPossible causes:")
    print("  1. No internet connection")
    print("  2. Firewall blocking Supabase")
    print("  3. Incorrect credentials in .env file")
    print("  4. DNS resolution issue")
    print("\n" + "="*80)
    import traceback
    traceback.print_exc()
