# CORRECT Testing Workflow 

## ⚠️ Important: Process Emails FIRST!

The mapper needs **FRESH** emails processed TODAY, not old data from weeks ago.

---

## Step-by-Step Guide

### Step 1: Process Current Emails 📧

**For test user: `govardhankonduru0802@gmail.com`**

#### Option A: Via Web App (Recommended)

1. **Start the Flask app**:
   ```bash
   python app.py
   ```

2. **User logs in**:
   - Go to `http://localhost:5000`
   - User (`govardhankonduru0802@gmail.com`) logs in with Gmail OAuth
   - Grants email permissions

3. **Process emails**:
   - App automatically fetches emails from last 24 hours
   - AI categorizes them (Application_Submitted, Rejected, Next_Steps, Other)
   - Saves to Supabase with TODAY's date and `status='applied'` for confirmations

**Result**: Fresh jobs with today's date in Supabase

#### Option B: Direct Script (If you have one)

If you have a standalone script that processes emails without the web app, run that instead.

---

### Step 2: Verify Fresh Data ✅

Check that emails were processed:

```bash
python check_test_user_local.py
```

**Look for**:
- Jobs with TODAY's date (2026-02-11)
- `status='applied'` for application confirmations
- Fresh company names and job titles

---

### Step 3: Run the Mapper 🔄

**NOW** run the mapper with fresh data:

```bash
# Dry-run first
python test_specific_user.py

# Or use the full dry-run
python karmafy_mapper_dry_run.py
```

**Expected**:
- Karmafy tasks from last 2 days (Feb 10-11)
- Local jobs from TODAY (Feb 11)
- Better chance of matching!

---

### Step 4: Production Run (If Matches Found) 🚀

```bash
python karmafy_mapper.py
```

Updates `is_email_received = true` in Karmafy for matched tasks.

---

## Why This Order Matters

### ❌ Wrong Order (What We Did Before)
```
Karmafy tasks: Feb 10, 2026
Local jobs: Feb 2, 2026 (old)
Result: 10% match (different time periods!)
```

### ✅ Correct Order
```
1. Process TODAY's emails → New jobs dated Feb 11
2. Fetch Karmafy tasks (last 2 days) → Feb 10-11
3. Match them → Much better overlap!
```

---

## Quick Start for Your Test User

```bash
# Terminal 1: Start web app
cd c:\Users\91901\Documents\job-tracking-main\gmail-render
python app.py

# Browser: User logs in
# http://localhost:5000
# Login as: govardhankonduru0802@gmail.com

# Terminal 2: After emails processed, verify
python check_test_user_local.py

# Terminal 2: Run mapper test
python test_specific_user.py
```

---

## Alternative: If User Can't Log In Now

**Temporarily test with a different user who:**
1. Already has fresh emails processed (last 1-2 days)
2. Also has Karmafy tasks (last 2 days)

OR

**Extend the time window** in the mapper to find older overlapping data:

Change in both mapper scripts:
```python
# From:
AND kt."createdAt" >= NOW() - INTERVAL '2 days'

# To:
AND kt."createdAt" >= NOW() - INTERVAL '14 days'
```

This will find Karmafy tasks from the same period as the old emails (Feb 2).

---

**Bottom line**: Process emails FIRST, then map! 🎯
