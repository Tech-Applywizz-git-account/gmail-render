"""
Quick Test: User-Specific Mapper Function
Tests the new map_user_emails() function
"""

from karmafy_mapper import map_user_emails

# Test with the same user we've been testing
TEST_USER = "govardhankonduru0802@gmail.com"

print("="*80)
print(f"Testing map_user_emails() for: {TEST_USER}")
print("="*80)

result = map_user_emails(TEST_USER)

print("\n" + "="*80)
print("RESULT")
print("="*80)
print(f"Success: {result['success']}")
print(f"Tasks Processed: {result['tasks_processed']}")
print(f"Matches Found: {result['matches_found']}")
print(f"  - Full Matches: {result['full_matches']}")
print(f"  - Company Matches: {result['company_matches']}")
print(f"  - Job Title Matches: {result['job_title_matches']}")

if not result['success']:
    print(f"\nError: {result.get('error', 'Unknown')}")
elif result['matches_found'] == 0:
    print(f"\nInfo: {result.get('error', 'No matches found')}")
else:
    print(f"\n✅ Successfully updated {result['matches_found']} tasks!")
    print("   is_email_received = true in Karmafy database")

print("="*80)
