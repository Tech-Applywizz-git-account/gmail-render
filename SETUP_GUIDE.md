# Quick Setup Guide - Karmafy Mapper

## 📋 Summary
This tool maps job applications between your local database and the Karmafy production database using intelligent matching logic.

## ⚡ Quick Start

### 1. Update `.env` file
Add your Karmafy database credentials:

```env
# Add these lines to your .env file
KARMAFY_DB_HOST=your-karmafy-host.com
KARMAFY_DB_PORT=5432
KARMAFY_DB_NAME=your-db-name
KARMAFY_DB_USER=applywizz_prod_user
KARMAFY_DB_PASSWORD=your-password
```

### 2. Install Dependencies
```bash
cd gmail-render
pip install psycopg2-binary
# or
pip install -r requirements.txt
```

### 3. Test First (Recommended)
Run the dry-run version to see what would be matched WITHOUT making changes:

```bash
python karmafy_mapper_dry_run.py
```

### 4. Run the Actual Mapper
Once you're satisfied with the dry-run results:

```bash
python karmafy_mapper.py
```

## 🎯 What It Does

### Matching Logic (in priority order):
1. ✅ **Full Match**: Both company name AND job title match
2. ✅ **Company Match**: Only company name matches  
3. ✅ **Job Title Match**: Only job title matches

### What Gets Updated:
- Sets `is_email_received = true` in `karmafy_task` table
- Only for tasks with `status = 'COMPLETED'` and `is_email_received = false`

## 📊 Database Flow

```
Karmafy DB                        Local DB (Supabase)
├── karmafy_task                  └── jobs
│   └── leadId ──────┐                ├── job_name
├── karmafy_scoredjob│                ├── company_name
│   ├── jobTitle     │                └── user_email
│   ├── companyName  │
│   └── lead_id ─────┤
└── karmafy_lead     │
    ├── id ──────────┘
    └── email ────> Match by user email
```

## 📝 Files Created

| File | Purpose |
|------|---------|
| `karmafy_mapper.py` | Main mapper (updates database) |
| `karmafy_mapper_dry_run.py` | Test version (no updates) |
| `KARMAFY_MAPPER_README.md` | Full documentation |
| `SETUP_GUIDE.md` | This file |

## ⚠️ Important Notes

1. **Always test with dry-run first!**
2. The mapper only reads from your local `jobs` table
3. The mapper only writes to `karmafy_task.is_email_received` field
4. Uses fuzzy matching to handle minor text differences

## 🔍 Example Output

```
[Task 1/5] Processing:
  Task ID: abc-123
  User: john@example.com (John Doe)
  Karmafy Job Title: Senior Software Engineer
  Karmafy Company: TechCorp
  ✓ Fetched 12 jobs from local database for user john@example.com
  ✓ FULL_MATCH: Company 'TechCorp' + Job 'Senior Software Engineer'
  ✓ Updated task abc-123: is_email_received = true

SUMMARY
Total tasks processed: 5
Successfully matched: 4
Not matched: 1
Success rate: 80.00%
```

## 🐛 Troubleshooting

### Can't connect to database
- Check your `.env` file has correct credentials
- Verify network access to Karmafy database
- Check firewall/VPN settings

### No matches found
- Verify user emails match between both databases
- Check if jobs exist for those users in local database
- Review job_name and company_name for typos

### Import errors
```bash
pip install psycopg2-binary
```

## 📚 Need More Info?

See `KARMAFY_MAPPER_README.md` for:
- Detailed schema information
- Advanced configuration
- Custom matching logic
- Security best practices
