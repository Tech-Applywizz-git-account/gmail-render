# ✅ Karmafy Mapper - Setup Checklist

## Pre-Flight Checklist

### 1. ⚙️ Environment Configuration
- [ ] Open `.env` file in `gmail-render/` folder
- [ ] Add/Update these lines with your Karmafy database credentials:
  ```env
  KARMAFY_DB_HOST=your-actual-host.com
  KARMAFY_DB_PORT=5432
  KARMAFY_DB_NAME=your-actual-database-name
  KARMAFY_DB_USER=applywizz_prod_user
  KARMAFY_DB_PASSWORD=your-actual-password
  ```
- [ ] Save the `.env` file
- [ ] Verify `SUPABASE_URL` and `SUPABASE_KEY` are already set (they should be)

### 2. 📦 Dependencies
- [ ] Open terminal/command prompt
- [ ] Navigate to project: `cd c:\Users\91901\Documents\job-tracking-main\gmail-render`
- [ ] Install dependencies: `pip install psycopg2-binary` (already done ✓)
- [ ] Or install all: `pip install -r requirements.txt`

### 3. 🔍 Inspection (Optional but Recommended)
- [ ] Run: `python inspect_local_db.py`
- [ ] Verify you see job records with `job_name` and `company_name`
- [ ] Note the user emails shown (these should match Karmafy database)

### 4. 🧪 Dry Run Testing (HIGHLY RECOMMENDED)
- [ ] Run: `python karmafy_mapper_dry_run.py`
- [ ] When prompted, enter number of tasks to test (e.g., 10)
- [ ] Review the output:
  - [ ] Check connection to Karmafy database succeeded
  - [ ] Verify tasks are being fetched
  - [ ] Review match results (FULL_MATCH, COMPANY_MATCH, JOB_TITLE_MATCH)
  - [ ] Check success rate percentage
- [ ] If success rate is low (<50%), review unmatched tasks for issues

### 5. 🚀 Production Run
- [ ] Only proceed if dry run results look good
- [ ] Run: `python karmafy_mapper.py`
- [ ] Monitor the output for any errors
- [ ] Review the final summary statistics
- [ ] Verify `is_email_received` was updated in Karmafy database

## Post-Run Verification

### Database Verification (Optional)
- [ ] Connect to Karmafy database
- [ ] Run query to verify updates:
  ```sql
  SELECT 
    id, 
    status, 
    is_email_received, 
    "scored_jobId"
  FROM karmafy_task 
  WHERE status = 'COMPLETED' 
    AND is_email_received = true 
  ORDER BY "createdAt" DESC 
  LIMIT 10;
  ```

## Quick Reference Commands

```bash
# Navigate to project
cd c:\Users\91901\Documents\job-tracking-main\gmail-render

# Inspect local database
python inspect_local_db.py

# Test matching (dry run)
python karmafy_mapper_dry_run.py

# Run actual mapper
python karmafy_mapper.py
```

## What Each File Does

| File | Safe to Run? | Purpose |
|------|--------------|---------|
| `inspect_local_db.py` | ✅ YES | View local jobs table (read-only) |
| `karmafy_mapper_dry_run.py` | ✅ YES | Test matching logic (no updates) |
| `karmafy_mapper.py` | ⚠️ CAUTION | Updates Karmafy database |

## Troubleshooting Quick Fixes

### "Cannot connect to Karmafy database"
```bash
# Check your .env file has the correct credentials
# Make sure you're connected to the right network/VPN
```

### "No matches found" / Low success rate
```bash
# 1. Check if user emails match in both databases
# 2. Verify jobs exist for those users:
python inspect_local_db.py

# 3. Check for data quality issues (typos, formatting)
```

### "Module not found: psycopg2"
```bash
pip install psycopg2-binary
```

### "Supabase client not configured"
```bash
# Verify these are in your .env file:
# SUPABASE_URL=...
# SUPABASE_KEY=...
```

## Expected Results

### Good Results ✓
- Success rate: **>70%**
- Most matches are FULL_MATCH or COMPANY_MATCH
- No database connection errors
- Updates complete successfully

### Needs Investigation ⚠️
- Success rate: **<50%**
- Many "NO MATCH" results
- User emails don't exist in local database
- Job names/companies don't match at all

### Critical Issues ❌
- Cannot connect to database
- Python errors/crashes
- All tasks show as "NO MATCH"
- Updates fail with errors

## Support Files Reference

- 📘 **Full Documentation**: `KARMAFY_MAPPER_README.md`
- 🚀 **Quick Start**: `SETUP_GUIDE.md`
- 🏗️ **Architecture Details**: `ARCHITECTURE.md`
- ✅ **This Checklist**: `CHECKLIST.md`

## Safety Reminders

- ⚠️ **Always run dry-run first** before production
- ⚠️ **Never commit `.env` file** to version control
- ⚠️ Keep database credentials secure
- ✅ The mapper only updates ONE field (`is_email_received`)
- ✅ Read-only access to your local database
- ✅ Automatic rollback on errors

---

**Ready to Start?**
1. Complete checklist items above ☝️
2. Start with dry run test
3. Review results
4. Run production mapper if satisfied

Good luck! 🎉
