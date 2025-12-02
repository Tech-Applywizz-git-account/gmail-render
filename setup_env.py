#!/usr/bin/env python3
"""
Helper script to set up environment variables for the Gmail Job Tracker application.
This script will copy .env.example to .env if .env doesn't exist yet.
"""

import os
import shutil

def setup_env():
    """Copy .env.example to .env if .env doesn't exist"""
    env_file = '.env'
    env_example = '.env.example'
    
    if os.path.exists(env_file):
        print(f"{env_file} already exists. Skipping creation.")
        return
    
    if os.path.exists(env_example):
        shutil.copyfile(env_example, env_file)
        print(f"Created {env_file} from {env_example}")
        print("Please edit .env and fill in your actual credentials")
    else:
        print(f"{env_example} not found. Creating a new .env file")
        with open(env_file, 'w') as f:
            f.write("# Environment variables for Gmail Job Tracker Application\n")
            f.write("SECRET_KEY=change-this-to-a-random-secret-key\n")
            f.write("GOOGLE_CLIENT_ID=\n")
            f.write("GOOGLE_PROJECT_ID=\n")
            f.write("GOOGLE_CLIENT_SECRET=\n")
            f.write("AWS_ACCESS_KEY_ID=\n")
            f.write("AWS_SECRET_ACCESS_KEY=\n")
            f.write("AWS_REGION=us-east-1\n")
            f.write("BEDROCK_MODEL_ID=us.amazon.nova-lite-v1:0\n")
            f.write("SUPABASE_URL=\n")
            f.write("SUPABASE_KEY=\n")
        print(f"Created {env_file}. Please fill in your actual credentials")

if __name__ == "__main__":
    setup_env()