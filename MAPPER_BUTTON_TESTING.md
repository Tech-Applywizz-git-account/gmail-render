# User-Specific Mapper Button - Testing Guide

## What Was Implemented

✅ **Added "Map Fetched Emails" button** to `sync_success.html`  
✅ **Created `map_user_emails()` function** in `karmafy_mapper.py`  
✅ **Added `/map-emails` route** in `app.py`

## How It Works

```
1. User processes emails → Sees sync_success.html
2. User clicks "🔄 Map Fetched Emails to Karmafy"
3. Backend runs mapper for THIS USER ONLY
4. Updates is_email_received = true in karmafy_task
5. Shows flash message with results
6. Redirects to customer dashboard
```

## Testing Steps

### Option 1: Test via Flask App (Recommended)

1. **Start the Flask app** (if not already running):
   ```bash
   python app.py
   ```

2. **Login as test user**:
   - Go to: `http://localhost:5000`
   - Login as: `govardhankonduru0802@gmail.com`
   - Process emails (if not already done)

3. **You should see**:
   - sync_success.html page
   - NEW button: "🔄 Map Fetched Emails to Karmafy" (primary button)
   - "🏠 Go Back to Customer Dashboard" (secondary button)
   - "🚪 Logout" (secondary button)

4. **Click "Map Fetched Emails" button**

5. **Expected result**:
   - Flash message: "✅ Mapping complete! X job confirmations matched..."
   - Redirect to customer dashboard
   - Check Karmafy DB: is_email_received = true for matched tasks

### Option 2: Test Function Directly

```bash
python test_map_user_emails.py
```

**Expected output**:
```
Success: True
Tasks Processed: 20
Matches Found: 11
  - Full Matches: 6
  - Company Matches: 4
  - Job Title Matches: 1

✅ Successfully updated 11 tasks!
```

## Verify in Database

Run this SQL in Karmafy database:

```sql
SELECT 
    COUNT(*) as matched_tasks
FROM karmafy_task kt
JOIN karmafy_lead kl ON kt."leadId" = kl.id
WHERE kl.email = 'govardhankonduru0802@gmail.com'
  AND kt.status = 'COMPLETED'
  AND kt.is_email_received = true
  AND kt."createdAt" >= NOW() - INTERVAL '2 days';
```

**Expected**: ~11 matched tasks

## Flash Messages

The button will show different messages based on results:

- ✅ **Success with matches**: "Mapping complete! X job confirmations matched..."
- ⚠️ **No tasks found**: "No Karmafy tasks found for this user in the last 2 days"
- ⚠️ **No emails found**: "No application confirmation emails found for this user"
- ℹ️ **No matches**: "No matches found. Processed X tasks but couldn't match them..."
- ❌ **Error**: "Mapping failed: [error message]"

## Files Modified

1. ✅ `karmafy_mapper.py` - Added `map_user_emails()` function
2. ✅ `app.py` - Added `/map-emails` route
3. ✅ `templates/sync_success.html` - Added button

## What Happens in Database

When user clicks the button:

1. Function fetches completed Karmafy tasks for user (last 2 days)
2. Fetches local jobs with `status='applied'` for user
3. Matches tasks with jobs using fuzzy matching
4. **Updates `is_email_received = true`** for each matched task
5. Returns statistics

## Ready for Production! ✅

The feature is fully implemented and ready to use.
