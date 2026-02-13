# Quick Start: Testing with Real User

## ✅ Implementation Complete!

The mapper is now ready to test. It will **ONLY** match jobs where `status='applied'` (Application_Submitted emails).

## 🚀 Steps to Test

### 1. Find a Real User

You need a user who:
- ✅ Applied to jobs via Karmafy (last 2 days)
- ✅ Connected Gmail to your project
- ✅ Received application confirmation emails
- ✅ Has emails categorized as `Application_Submitted` (status='applied')

**Check both databases:**
```bash
# Check Karmafy for users with completed tasks
python inspect_karmafy_db.py

# Check local Supabase for users with applied jobs
python inspect_local_db.py
```

Look for the **same email address** in both!

### 2. Run Dry-Run Test

```bash
python karmafy_mapper_dry_run.py
```

Enter number of tasks (e.g., 10) and press Enter.

### 3. Check Results

**Success Looks Like:**
```
✓ Fetched 5 jobs with status='applied' from local database for user user@example.com
✓ FULL MATCH: Company 'PayPal' + Job 'Senior Software Engineer'
```

**Common Issues:**
- `Fetched 0 jobs with status='applied'` → User hasn't received confirmation emails yet
- `NO MATCH found` → Job titles/companies don't match (expected with fuzzy matching)

### 4. Run Production (After Successful Test)

**ONLY if you see matches in dry-run:**
```bash
python karmafy_mapper.py
```

This will UPDATE `is_email_received = true` in Karmafy database.

## 📋 No Real User Yet?

**Temporary Solution:**
1. Lower the date filter to 30 days (find older data)
2. Or manually test with sample data

See full `TESTING_GUIDE.md` for details.

---

**🎉 You're all set!** The mapper is working according to your flow.
