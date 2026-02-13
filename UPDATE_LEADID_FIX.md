# 🔧 UPDATED: Lead ID Verification Added

## What Changed

Added an additional join condition to ensure the `lead_id` in `karmafy_scoredjob` matches the `leadId` in `karmafy_task`.

## Previous Query (Potentially Incorrect)

```sql
INNER JOIN 
    public.karmafy_scoredjob ksj ON kt."scored_jobId" = ksj.id
```

This only checked if the scored job ID exists, but didn't verify it belongs to the correct lead.

## Updated Query (More Robust)

```sql
INNER JOIN 
    public.karmafy_scoredjob ksj ON kt."scored_jobId" = ksj.id 
        AND kt."leadId" = ksj.lead_id
```

Now we verify BOTH:
1. ✅ The scored job ID matches (`kt."scored_jobId" = ksj.id`)
2. ✅ The lead ID matches (`kt."leadId" = ksj.lead_id`)

## Why This Matters

### Data Integrity
- Ensures we're matching the scored job to the correct user/lead
- Prevents mixing data from different users
- Catches potential database inconsistencies

### Example Scenario

**Without the check:**
```
Task: leadId=100, scored_jobId=ABC
Could match: ScoredJob ABC from leadId=200 (WRONG USER!)
```

**With the check:**
```
Task: leadId=100, scored_jobId=ABC
Only matches: ScoredJob ABC from leadId=100 (CORRECT!)
If leadId doesn't match → Record excluded
```

## Files Updated

All three files now have this fix:
- ✅ `karmafy_mapper.py` (production)
- ✅ `karmafy_mapper_dry_run.py` (testing)
- ✅ `inspect_karmafy_db.py` (diagnostic)

## Impact on Results

This change might:
1. **Reduce the number of tasks returned** (if there were mismatches)
2. **Fix the NULL jobTitle/companyName issue** (if the wrong jobs were being joined)
3. **Improve data accuracy** (only correct lead-job pairs)

## Testing

Run the inspection script to see if this fixes the NULL issue:

```bash
python inspect_karmafy_db.py
```

Then run the dry-run again:

```bash
python karmafy_mapper_dry_run.py
```

---

**This should potentially fix the "None - None" issue you were seeing!**

Let's test it now to see if the jobTitle and companyName are populated correctly.
