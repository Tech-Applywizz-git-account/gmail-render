# 🔄 UPDATED: 2-Day Filter Applied

## What Changed

Both mapper scripts now **only process tasks from the last 2 days** instead of all historical dates.

### Updated SQL Query

```sql
WHERE 
    kt.status = 'COMPLETED'
    AND kt.is_email_received = false
    AND kt."createdAt" >= NOW() - INTERVAL '2 days'  -- ✅ NEW: Only last 2 days
```

### What This Means

- ✅ Only tasks created in the **last 2 days** will be processed
- ✅ More efficient for regular/daily runs
- ✅ Prevents processing very old tasks
- ✅ Keeps matching focused on recent activity

### Files Updated

1. **karmafy_mapper.py** - Production mapper
2. **karmafy_mapper_dry_run.py** - Test mapper

Both files now include:
- Updated SQL with `NOW() - INTERVAL '2 days'` filter
- Updated docstrings mentioning the 2-day limit
- Updated console output showing "(last 2 days)"

### Example Scenarios

**Today's Date: Feb 11, 2026**

| Task Created | Will Process? |
|--------------|---------------|
| Feb 11, 2026 | ✅ YES |
| Feb 10, 2026 | ✅ YES |
| Feb 9, 2026  | ✅ YES (within 2 days) |
| Feb 8, 2026  | ❌ NO (older than 2 days) |
| Jan 25, 2026 | ❌ NO (older than 2 days) |

### How to Use

**No changes needed to your workflow!**

Just run the scripts as before:

```bash
# Test first (dry run)
python karmafy_mapper_dry_run.py

# Run production mapper
python karmafy_mapper.py
```

The 2-day filter is now automatically applied.

### Need to Change the Time Window?

If you want to change from 2 days to something else, edit the SQL query in both files:

```sql
-- For 1 day only
AND kt."createdAt" >= NOW() - INTERVAL '1 day'

-- For 7 days (1 week)
AND kt."createdAt" >= NOW() - INTERVAL '7 days'

-- For 30 days (1 month)
AND kt."createdAt" >= NOW() - INTERVAL '30 days'

-- For specific date
AND kt."createdAt" >= '2026-02-01'
```

---

**✅ Ready to test! The mappers now only process tasks from the last 2 days.**
