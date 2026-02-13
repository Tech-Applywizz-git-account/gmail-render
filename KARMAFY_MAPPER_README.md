# Karmafy Task Mapper

## Overview

This mapper script connects your local job tracking database with the external Karmafy database to automatically match job applications and update task statuses.

## What It Does

The mapper performs the following operations:

1. **Fetches Completed Tasks**: Retrieves all tasks from `karmafy_task` table where:
   - `status = 'COMPLETED'`
   - `is_email_received = false`

2. **Joins Related Data**: Combines data from three Karmafy tables:
   - `karmafy_task` - Task information
   - `karmafy_scoredjob` - Job details (jobTitle, companyName)
   - `karmafy_lead` - User information (email)

3. **Matches Jobs Using Permutation Logic**:
   - **Strategy 1**: Exact match on BOTH company_name AND job_title
   - **Strategy 2**: Match on company_name only
   - **Strategy 3**: Match on job_title only

4. **Updates Tasks**: Sets `is_email_received = true` for matched tasks

## Installation

### 1. Install Dependencies

```bash
pip install -r requirements.txt
```

This will install the required `psycopg2-binary` package for PostgreSQL connectivity.

### 2. Configure Environment Variables

Add the following to your `.env` file:

```env
# Karmafy Database Configuration
KARMAFY_DB_HOST=your-karmafy-db-host.com
KARMAFY_DB_PORT=5432
KARMAFY_DB_NAME=your-database-name
KARMAFY_DB_USER=applywizz_prod_user
KARMAFY_DB_PASSWORD=your-database-password
```

**Note**: You already have `SUPABASE_URL` and `SUPABASE_KEY` configured for your local jobs database.

## Usage

### Run the Mapper

```bash
cd gmail-render
python karmafy_mapper.py
```

### Expected Output

```
================================================================================
KARMAFY TASK MAPPER - Starting Process
================================================================================

✓ Connected to Karmafy database: your-database-name

--- Step 1: Fetching Completed Tasks ---
✓ Fetched 25 completed tasks from Karmafy database

--- Step 2: Processing Tasks ---

[Task 1/25] Processing:
  Task ID: task-abc-123
  User: john.doe@example.com (John Doe)
  Job Title: Senior Software Engineer
  Company: TechCorp Inc
✓ Fetched 15 jobs from local database for user john.doe@example.com
  ✓ FULL MATCH: Company 'TechCorp Inc' + Job 'Senior Software Engineer'
  ✓ Updated task task-abc-123: is_email_received = true

[Task 2/25] Processing:
  Task ID: task-def-456
  User: jane.smith@example.com (Jane Smith)
  Job Title: Data Scientist
  Company: DataCo
✓ Fetched 8 jobs from local database for user jane.smith@example.com
  ✓ COMPANY MATCH: 'DataCo'
  ✓ Updated task task-def-456: is_email_received = true

...

================================================================================
SUMMARY
================================================================================
Total tasks processed: 25
Successfully matched: 22
Not matched: 3
Success rate: 88.00%
================================================================================
```

## Matching Logic Details

### Text Normalization

The script normalizes all text before comparison:
- Converts to lowercase
- Removes special characters
- Removes extra whitespace

### Fuzzy Matching

The matching algorithm:
1. **Exact Match**: After normalization, checks for exact equality
2. **Containment**: Checks if one string contains the other
3. **Extensible**: Can add Levenshtein distance or other algorithms

### Permutation Priority

The script tries matches in this order:

```
Priority 1: company_name ✓ AND job_title ✓
Priority 2: company_name ✓ only
Priority 3: job_title ✓ only
```

## Database Schema Reference

### Local Database (`jobs` table - Supabase)

```sql
- id (primary key)
- user_email (text)
- job_name (text)
- company_name (text)
- job_link (text)
- req_id (text)
- status (text)
- date (date)
- created_at (timestamp)
- updated_at (timestamp)
```

### Karmafy Database

**karmafy_task** (Tasks to update)
```sql
- id (text, primary key)
- status (text) -- Filter: 'COMPLETED'
- is_email_received (boolean) -- Update this to TRUE
- leadId (bigint, FK to karmafy_lead)
- scored_jobId (varchar, FK to karmafy_scoredjob)
- dueDate, createdAt, startedAt, completedAt, etc.
```

**karmafy_scoredjob** (Job details)
```sql
- id (varchar, primary key)
- jobTitle (varchar) -- Match with jobs.job_name
- companyName (varchar) -- Match with jobs.company_name
- lead_id (bigint, FK to karmafy_lead)
- jobUrl, score, reasoning, etc.
```

**karmafy_lead** (User information)
```sql
- id (bigint, primary key) -- Maps to task.leadId and scoredjob.lead_id
- email (varchar) -- Used to fetch user's jobs
- name, resumeUrl, location, etc.
```

## Troubleshooting

### Connection Issues

**Error**: `Error connecting to Karmafy database`

**Solution**: 
- Verify your `.env` file has correct database credentials
- Check network connectivity to the database host
- Ensure the database port (default: 5432) is accessible

### No Matches Found

**Error**: All tasks show `NO MATCH`

**Solution**:
- Check if the user emails in Karmafy match those in your local database
- Verify that jobs exist in your local database for those users
- Check the job_name and company_name values for typos

### Package Import Errors

**Error**: `ModuleNotFoundError: No module named 'psycopg2'`

**Solution**:
```bash
pip install psycopg2-binary
```

## Advanced Configuration

### Adjusting Match Threshold

In `karmafy_mapper.py`, modify the `fuzzy_match` function:

```python
def fuzzy_match(text1, text2, threshold=0.8):  # Adjust threshold here
    # Lower threshold = more lenient matching
    # Higher threshold = stricter matching
```

### Custom Matching Logic

You can add more sophisticated matching algorithms in the `fuzzy_match` function:

```python
# Example: Add Levenshtein distance
from difflib import SequenceMatcher

def fuzzy_match(text1, text2, threshold=0.8):
    if not text1 or not text2:
        return False
    
    text1_norm = normalize_text(text1)
    text2_norm = normalize_text(text2)
    
    # Calculate similarity ratio
    ratio = SequenceMatcher(None, text1_norm, text2_norm).ratio()
    
    return ratio >= threshold
```

## Security Notes

- ⚠️ Never commit your `.env` file to version control
- ⚠️ Keep database credentials secure
- ⚠️ Use read-write permissions only where necessary
- ✓ The script only updates `is_email_received` field (minimal write access)

## Support

For issues or questions, please refer to:
- Main project README: `../README.md`
- Job processor documentation: Check `job_processor.py` docstrings
