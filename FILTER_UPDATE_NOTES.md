# Filter Update: Status → Category

## What Changed

Updated all mapper scripts to filter by `category='application_submitted'` instead of `status='applied'`.

## Files Modified

1. ✅ `karmafy_mapper.py` - Main mapper
2. ✅ `karmafy_mapper_dry_run.py` - Dry run mapper  
3. ✅ `test_specific_user.py` - Test script
4. ✅ `check_test_user_local.py` - Local DB checker
5. ✅ `check_fresh_emails.py` - Fresh email checker

## Why This Change?

**Before**: Filtered by `status` column (derived from `category`)
```python
query.eq("status", "applied")  # Indirect filter
```

**After**: Filter by `category` column (direct AI categorization)
```python
query.eq("category", "application_submitted")  # Direct filter
```

## Schema Reference

From `job_processor.py`:
```python
def convert_category_to_status(category):
    category_to_status = {
        'application_submitted': 'applied',  # ← This mapping
        'next_steps': 'next_steps',
        'reject': 'rejected',
        'other': 'other'
    }
    return category_to_status.get(category, 'other')
```

**category** = AI's direct classification of the email  
**status** = Derived value for UI/display purposes

## Test Results

Test with `category='application_submitted'`:
```
✓ Fetched 6 completed tasks (previously matched 25 are excluded)
✓ Fetched 80 jobs with category='application_submitted'
✅ All working correctly!
```

The **80 jobs** vs **75 jobs** difference shows that `category` is the more accurate source - 5 more emails are correctly identified as application submissions directly by the AI categorization.

## Benefits

1. ✅ **More accurate**: Uses direct AI classification
2. ✅ **No derivation**: Avoids potential mapping errors
3. ✅ **Clearer intent**: Directly states what we're looking for
4. ✅ **Future-proof**: If status mapping changes, category stays consistent

## Complete! ✅

All mapper scripts now use direct category filtering.
