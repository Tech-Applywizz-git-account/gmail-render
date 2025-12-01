

"""
Test script for job processor module
"""

import os
import sys
from datetime import datetime

# Add the current directory to Python path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

def test_job_processor():
    """Test the job processor with sample data."""
    try:
        from job_processor import (
            extract_job_details_manually, 
            categorize_email, 
            convert_category_to_status,
            process_job_email
        )
        
        # Sample email data
        sample_email = {
            "subject": "Thank you for your application for Software Engineer Position",
            "body": "Dear Applicant, Thank you for applying for the Software Engineer position at TechCorp. We have received your application and will review it shortly. Job ID: TC-12345. For more information, visit https://techcorp.com/jobs/12345",
            "sender": "jobs@techcorp.com",
            "timestamp": datetime.now().isoformat()
        }
        
        print("Testing job processor with sample email...")
        print(f"Sample email: {sample_email}")
        
        # Test manual extraction
        print("\n1. Testing manual extraction...")
        job_details = extract_job_details_manually(sample_email)
        print(f"Extracted job details: {job_details}")
        
        # Test categorization
        print("\n2. Testing email categorization...")
        category = categorize_email(sample_email)
        print(f"Email category: {category}")
        
        # Test status conversion
        print("\n3. Testing category to status conversion...")
        status = convert_category_to_status(category)
        print(f"Job status: {status}")
        
        # Test full processing (this will fail without Supabase config)
        print("\n4. Testing full processing...")
        user_email = "test@example.com"
        success = process_job_email(user_email, sample_email)
        print(f"Processing result: {'Success' if success else 'Failed'}")
        
        print("\nTest completed!")
        
    except ImportError as e:
        print(f"Error importing job_processor: {e}")
        print("Make sure all dependencies are installed.")
    except Exception as e:
        print(f"Error during testing: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    test_job_processor()