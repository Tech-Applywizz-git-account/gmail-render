# Testing Guide: Real User Validation

## Prerequisites

Before testing, ensure you have a **real user** who meets ALL these criteria:

### ✅ User Requirements
1. **Has Karmafy account** with completed tasks (last 2 days)
2. **Connected Gmail** to your project via OAuth
3. **Received job application confirmation emails** (Gmail inbox)
4. **Emails processed by AI** and categorized as `Application_Submitted`
5. **Jobs saved to Supabase** with `status='applied'`

## Step 1: Identify Test User

Find a user email that exists in BOTH databases:

### Check Karmafy Database
```bash
python inspect_karmafy_db.py
```

Look for a user with:
- Recent completed tasks (last 2 days)
- Valid job titles and company names
- Example: `user@example.com`

### Check Local Supabase Database
```bash
python inspect_local_db.py
```

Look for the SAME user with:
- Jobs where `status='applied'`
- Jobs where `category='application_submitted'`
- Company names and job titles that might match Karmafy tasks

## Step 2: Manual Verification (Optional but Recommended)

### Query Karmafy Tasks
Connect to Karmafy database and run:
```sql
SELECT 
    kt.id,
    kl.email,
    kj.title,
    kj.company,
    kt.status,
    kt.is_email_received
FROM karmafy_task kt
JOIN karmafy_scoredjob ksj ON kt."scored_jobId" = ksj.id
JOIN karmafy_job kj ON ksj."jobId" = kj.id::text
JOIN karmafy_lead kl ON kt."leadId" = kl.id
WHERE kl.email = 'user@example.com'
  AND kt.status = 'COMPLETED'
  AND kt."createdAt" >= NOW() - INTERVAL '2 days'
ORDER BY kt."createdAt" DESC
LIMIT 10;
```

### Query Local Jobs
Connect to Supabase and run:
```sql
SELECT 
    user_email,
    job_name,
    company_name,
    status,
    category,
    date
FROM jobs
WHERE user_email = 'user@example.com'
  AND status = 'applied'
ORDER BY date DESC
LIMIT 10;
```

### Compare Results
Check if any job titles/companies match between both databases.

## Step 3: Run Dry-Run Test

```bash
python karmafy_mapper_dry_run.py
```

**Enter number of tasks to test**: Start with 10

### Expected Output

#### If User Has Matching Jobs
```
[Task 1/10]
Task ID: xxx-xxx-xxx
User: user@example.com (User Name)
Karmafy Job Title: Senior Software Engineer
Karmafy Company: PayPal
--------------------------------------------------------------------------------
  ✓ Fetched 5 jobs with status='applied' from local database for user user@example.com
  ✓ FULL MATCH: Company 'PayPal' + Job 'Senior Software Engineer'
```

#### If User Has No Matching Jobs
```
[Task 1/10]
Task ID: xxx-xxx-xxx
User: user@example.com (User Name)
Karmafy Job Title: Senior Software Engineer
Karmafy Company: PayPal
--------------------------------------------------------------------------------
  ✓ Fetched 5 jobs with status='applied' from local database for user user@example.com
  ✗ NO MATCH: Company 'PayPal', Job 'Senior Software Engineer'
```

#### If User Has No Jobs in Local DB
```
[Task 1/10]
Task ID: xxx-xxx-xxx
User: user@example.com (User Name)
Karmafy Job Title: Senior Software Engineer
Karmafy Company: PayPal
--------------------------------------------------------------------------------
  ✓ Fetched 0 jobs with status='applied' from local database for user user@example.com
  ✗ NO JOBS found in local database for user user@example.com
```

## Step 4: Analyze Results

### Success Indicators ✅
- At least 1 match found (FULL, COMPANY, or JOB_TITLE)
- Success rate > 0%
- Jobs fetched have `status='applied'` only

### Common Issues ❌

#### Issue 1: No Jobs Fetched
**Cause**: User hasn't received application confirmation emails yet
**Solution**: Wait for user to apply to jobs and receive confirmation emails

#### Issue 2: Jobs Fetched but No Matches
**Cause**: Job titles/companies don't match (different wording)
**Example**: 
- Karmafy: "Sr. Software Engineer" at "Google Inc."
- Local: "Senior Software Developer" at "Google"
**Solution**: Fuzzy matching should handle this, but may need adjustment

#### Issue 3: "Fetched 0 jobs with status='applied'"
**Cause**: User's emails categorized as different status
**Solution**: 
1. Check what statuses exist: `SELECT DISTINCT status FROM jobs WHERE user_email = 'user@example.com'`
2. Verify AI is categorizing application emails correctly
3. Check if emails are actually application confirmations

## Step 5: Production Run (After Successful Dry-Run)

**ONLY run this if dry-run shows successful matches!**

```bash
python karmafy_mapper.py
```

This will:
- Fetch completed Karmafy tasks
- Match with local applied jobs
- **UPDATE is_email_received = true** in Karmafy database

### Verify Updates
After running, check Karmafy database:
```sql
SELECT 
    kt.id,
    kl.email,
    kj.title,
    kj.company,
    kt.is_email_received
FROM karmafy_task kt
JOIN karmafy_scoredjob ksj ON kt."scored_jobId" = ksj.id
JOIN karmafy_job kj ON ksj."jobId" = kj.id::text
JOIN karmafy_lead kl ON kt."leadId" = kl.id
WHERE kl.email = 'user@example.com'
  AND kt.status = 'COMPLETED'
  AND kt."createdAt" >= NOW() - INTERVAL '2 days';
```

Check that `is_email_received` changed to `true` for matched tasks.

## Troubleshooting

### No Real User Available?
**Option 1**: Create test data manually
1. Insert test task in Karmafy with known job title/company
2. Insert matching job in Supabase with `status='applied'`
3. Run dry-run to verify matching

**Option 2**: Lower the date filter temporarily
Edit both mapper files, change:
```python
AND kt."createdAt" >= NOW() - INTERVAL '2 days'
```
To:
```python
AND kt."createdAt" >= NOW() - INTERVAL '30 days'
```
This will find older tasks that might have matching emails.

### Matching Not Working?
1. **Check exact values**: Compare job titles/companies character by character
2. **Test fuzzy matching**: Use Python console:
   ```python
   from karmafy_mapper import fuzzy_match
   fuzzy_match("Sr Software Engineer", "Senior Software Engineer")  # Should return True
   ```
3. **Verify normalization**: Check if special characters are causing issues

## Success Criteria

The test is successful if:
- ✅ Mapper connects to both databases
- ✅ Fetches only jobs with `status='applied'`
- ✅ Finds at least 1 match
- ✅ Dry-run shows expected matching behavior
- ✅ Production run updates `is_email_received` correctly

---

**Ready to test? Start with Step 1!**
