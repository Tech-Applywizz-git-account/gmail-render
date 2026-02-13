# Karmafy Job Mapping System - Architecture

## System Overview

```
┌─────────────────────────────────────────────────────────────────────────┐
│                        KARMAFY JOB MAPPING SYSTEM                        │
└─────────────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────┐         ┌──────────────────────────────┐
│   LOCAL DATABASE (Supabase)     │         │  KARMAFY DATABASE (PostgreSQL)│
│                                 │         │                               │
│  ┌───────────────────────────┐  │         │  ┌────────────────────────┐  │
│  │   jobs table              │  │         │  │   karmafy_lead         │  │
│  │  ───────────────────────  │  │         │  │  ──────────────────    │  │
│  │  - id                     │  │         │  │  - id (PK)             │  │
│  │  - user_email      ◄──────┼──┼─────────┼──┼─ - email              │  │
│  │  - job_name               │  │         │  │  - name                │  │
│  │  - company_name           │  │  MATCH  │  │                        │  │
│  │  - job_link               │  │    BY   │  └────────────────────────┘  │
│  │  - req_id                 │  │  EMAIL  │              │                │
│  │  - status                 │  │         │              │ lead_id        │
│  │  - date                   │  │         │              │                │
│  │  - created_at             │  │         │              ▼                │
│  │  - updated_at             │  │         │  ┌────────────────────────┐  │
│  └───────────────────────────┘  │         │  │   karmafy_scoredjob    │  │
│                                 │         │  │  ──────────────────    │  │
└─────────────────────────────────┘         │  │  - id (PK)             │  │
                                            │  │  - jobTitle      ◄─────┼──┐
                                            │  │  - companyName   ◄─────┼──┤
                                            │  │  - lead_id (FK)        │  │
                                            │  │  - score               │  │
                                            │  └────────────────────────┘  │
                                            │              │                │
                                            │              │ scored_jobId   │
                                            │              │                │
                                            │              ▼                │
                                            │  ┌────────────────────────┐  │
                                            │  │   karmafy_task         │  │
                                            │  │  ──────────────────    │  │
                                            │  │  - id (PK)             │  │
                                            │  │  - status              │  │
                                            │  │  - is_email_received ◄─┼──┼─ UPDATED
                                            │  │  - leadId (FK)         │  │    HERE
                                            │  │  - scored_jobId (FK)   │  │
                                            │  │  - dueDate             │  │
                                            │  │  - createdAt           │  │
                                            │  └────────────────────────┘  │
                                            │                               │
                                            └───────────────────────────────┘
                          │
                          │
                          ▼
            ┌──────────────────────────────┐
            │  MATCHING ALGORITHM          │
            │  (Permutation-based)         │
            │                              │
            │  Priority 1: ✓ Company       │
            │              ✓ Job Title     │
            │                              │
            │  Priority 2: ✓ Company       │
            │              ✗ Job Title     │
            │                              │
            │  Priority 3: ✗ Company       │
            │              ✓ Job Title     │
            └──────────────────────────────┘
```

## Data Flow

```
┌──────────────────────────────────────────────────────────────────────────┐
│  STEP 1: FETCH COMPLETED TASKS                                           │
├──────────────────────────────────────────────────────────────────────────┤
│                                                                          │
│  SELECT FROM karmafy_task WHERE:                                        │
│    - status = 'COMPLETED'                                               │
│    - is_email_received = false                                          │
│                                                                          │
│  JOIN karmafy_scoredjob → Get jobTitle, companyName                     │
│  JOIN karmafy_lead → Get user email                                     │
│                                                                          │
└──────────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
┌──────────────────────────────────────────────────────────────────────────┐
│  STEP 2: FETCH USER'S JOBS FROM LOCAL DB                                │
├──────────────────────────────────────────────────────────────────────────┤
│                                                                          │
│  SELECT FROM jobs WHERE user_email = {task.user_email}                  │
│                                                                          │
└──────────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
┌──────────────────────────────────────────────────────────────────────────┐
│  STEP 3: APPLY MATCHING LOGIC                                           │
├──────────────────────────────────────────────────────────────────────────┤
│                                                                          │
│  FOR each local job:                                                    │
│    1. Normalize text (lowercase, remove special chars)                   │
│    2. Try Strategy 1: Match company AND job title                       │
│    3. If no match, try Strategy 2: Match company only                   │
│    4. If no match, try Strategy 3: Match job title only                 │
│                                                                          │
│  RETURN: First matching job (or null)                                   │
│                                                                          │
└──────────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
┌──────────────────────────────────────────────────────────────────────────┐
│  STEP 4: UPDATE TASK IF MATCHED                                         │
├──────────────────────────────────────────────────────────────────────────┤
│                                                                          │
│  IF match found:                                                        │
│    UPDATE karmafy_task                                                  │
│    SET is_email_received = true                                         │
│    WHERE id = {task_id}                                                 │
│                                                                          │
└──────────────────────────────────────────────────────────────────────────┘
```

## Fuzzy Matching Logic

```python
# Text Normalization Example
"Senior Software Engineer at TechCorp!"
    ↓ lowercase
"senior software engineer at techcorp!"
    ↓ remove special chars
"senior software engineer at techcorp"
    ↓ remove extra whitespace
"senior software engineer at techcorp"

# Matching Strategies
Input from Karmafy:
  Company: "TechCorp Inc"
  Job: "Senior Software Engineer"

Local Database Jobs:
  Job 1: company="TechCorp Inc.", job="Senior Software Engineer"
  Job 2: company="TechCorp Inc.", job="DevOps Engineer"
  Job 3: company="StartupXYZ", job="Senior Software Engineer"

Results:
  Job 1 → FULL_MATCH ✓✓ (both match)
  Job 2 → COMPANY_MATCH ✓ (company only)
  Job 3 → JOB_TITLE_MATCH ✓ (job title only)

Winner: Job 1 (highest priority match)
```

## Security & Safety

```
┌─────────────────────────────────────────────────────────────────┐
│  SAFETY FEATURES                                                │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  ✓ Dry-run mode available for testing                          │
│  ✓ Only updates ONE field (is_email_received)                  │
│  ✓ Read-only access to local database                          │
│  ✓ Filters tasks by status ('COMPLETED' only)                  │
│  ✓ Detailed logging of all operations                          │
│  ✓ Rollback on errors (database transactions)                  │
│  ✓ Environment variables for credentials                       │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

## Files & Their Purpose

```
gmail-render/
├── karmafy_mapper.py              # Main mapper (UPDATES database)
├── karmafy_mapper_dry_run.py      # Test version (NO updates)
├── inspect_local_db.py            # View local jobs table
├── KARMAFY_MAPPER_README.md       # Full documentation
├── SETUP_GUIDE.md                 # Quick start guide
├── ARCHITECTURE.md                # This file
├── .env                          # Configuration (DO NOT COMMIT!)
└── requirements.txt              # Python dependencies
```

## Usage Workflow

```
┌────────────────┐
│ 1. Configure   │  Edit .env with Karmafy DB credentials
│    .env file   │
└────────┬───────┘
         │
         ▼
┌────────────────┐
│ 2. Inspect     │  python inspect_local_db.py
│    Local DB    │  (Verify your jobs table structure)
└────────┬───────┘
         │
         ▼
┌────────────────┐
│ 3. Dry Run     │  python karmafy_mapper_dry_run.py
│    Test        │  (Preview matches WITHOUT updates)
└────────┬───────┘
         │
         ▼
┌────────────────┐
│ 4. Run Mapper  │  python karmafy_mapper.py
│    (Production)│  (Actually update is_email_received)
└────────────────┘
```

## Expected Performance

```
Typical Runtime:
├── 10 tasks: ~2-5 seconds
├── 100 tasks: ~15-30 seconds
└── 1000 tasks: ~2-5 minutes

Rate:
├── Database queries: ~20-30 per task
├── Matching operations: O(n*m) where n=tasks, m=jobs per user
└── Network latency: Depends on database location
```

## Troubleshooting Map

```
Problem: Can't connect to Karmafy DB
├── Check .env credentials
├── Verify network/VPN access
└── Test database port (default: 5432)

Problem: No matches found
├── Verify user emails match across databases
├── Check job_name/company_name capitalization
├── Run inspect_local_db.py to verify data
└── Adjust fuzzy_match threshold in code

Problem: Import errors
└── pip install -r requirements.txt

Problem: Supabase connection fails
├── Check SUPABASE_URL in .env
└── Check SUPABASE_KEY in .env
```
