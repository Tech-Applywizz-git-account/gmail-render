# Deployment Guide

This document explains how to deploy the Gmail Job Tracker application and securely manage credentials.

## GitHub Secrets Setup

To deploy this application using GitHub Actions, you'll need to set up the following secrets in your GitHub repository:

1. Go to your repository on GitHub
2. Click on "Settings" tab
3. Click on "Secrets and variables" in the left sidebar
4. Click on "Actions" tab
5. Click "New repository secret" to add each of the following:

### Required Secrets

| Secret Name | Description | How to Obtain |
|-------------|-------------|---------------|
| `VERCEL_TOKEN` | Vercel authentication token | Create in Vercel dashboard under Settings > Tokens |
| `VERCEL_ORG_ID` | Vercel organization ID | Found in Vercel dashboard under Settings > General |
| `VERCEL_PROJECT_ID` | Vercel project ID | Found in Vercel dashboard under Project Settings > General |

### Environment Variables for Application

For the application to work correctly, you'll also need to set the following environment variables in Vercel:

| Variable Name | Description | Example Value |
|---------------|-------------|---------------|
| `SECRET_KEY` | Flask secret key | Generate a random string |
| `GOOGLE_CLIENT_ID` | Google OAuth client ID | From Google Cloud Console |
| `GOOGLE_PROJECT_ID` | Google Cloud project ID | From Google Cloud Console |
| `GOOGLE_CLIENT_SECRET` | Google OAuth client secret | From Google Cloud Console |
| `AWS_ACCESS_KEY_ID` | AWS access key ID | From AWS IAM |
| `AWS_SECRET_ACCESS_KEY` | AWS secret access key | From AWS IAM |
| `AWS_REGION` | AWS region | us-east-1 |
| `SUPABASE_URL` | Supabase project URL | From Supabase dashboard |
| `SUPABASE_KEY` | Supabase API key | From Supabase dashboard |

## Local Development Setup

For local development, copy the `.env.example` file to `.env` and fill in your actual credentials:

```bash
cp .env.example .env
```

Then edit the `.env` file with your actual credentials.

## Security Best Practices

1. Never commit actual credentials to version control
2. The `.gitignore` file is configured to exclude `.env` files
3. Rotate your API keys regularly
4. Use strong, unique passwords for all services
5. Limit permissions for AWS IAM users to only what's necessary
6. Use HTTPS in production environments

## Vercel Deployment

When deploying to Vercel:

1. Connect your GitHub repository to Vercel
2. During setup, add all the required environment variables listed above
3. Configure the build command as `pip install -r requirements.txt`
4. Configure the output directory as appropriate for your setup

## Troubleshooting

If you encounter issues with credentials:

1. Verify all required environment variables are set
2. Check that AWS IAM user has proper permissions for Bedrock
3. Ensure Google OAuth credentials are configured for web application type
4. Confirm Supabase URL and key are correct