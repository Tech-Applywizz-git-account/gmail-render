-- =====================================================
-- Supabase Schema: User Tokens Table
-- Purpose: Store OAuth tokens for persistent login
-- =====================================================

-- Create user_tokens table
CREATE TABLE IF NOT EXISTS user_tokens (
    id BIGSERIAL PRIMARY KEY,
    user_email TEXT UNIQUE NOT NULL,
    access_token TEXT NOT NULL,
    refresh_token TEXT,
    token_expiry BIGINT,  -- Unix timestamp in milliseconds (when access token expires)
    last_sync_time BIGINT,  -- Unix timestamp in milliseconds (last time emails were synced)
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Create index for fast email lookup
CREATE INDEX IF NOT EXISTS idx_user_tokens_email ON user_tokens(user_email);

-- Create index for sync time queries
CREATE INDEX IF NOT EXISTS idx_user_tokens_sync_time ON user_tokens(last_sync_time);

-- Add comment to table
COMMENT ON TABLE user_tokens IS 'Stores OAuth tokens and sync metadata for persistent user sessions';

-- Add comments to columns
COMMENT ON COLUMN user_tokens.user_email IS 'User email address (unique identifier)';
COMMENT ON COLUMN user_tokens.access_token IS 'OAuth access token for Gmail API';
COMMENT ON COLUMN user_tokens.refresh_token IS 'OAuth refresh token for renewing access';
COMMENT ON COLUMN user_tokens.token_expiry IS 'Expiry time of access token (milliseconds since epoch)';
COMMENT ON COLUMN user_tokens.last_sync_time IS 'Last email sync timestamp (milliseconds since epoch)';

-- Optional: Create function to auto-update updated_at timestamp
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Create trigger to auto-update updated_at
CREATE TRIGGER update_user_tokens_updated_at
    BEFORE UPDATE ON user_tokens
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

-- Grant permissions (adjust based on your Supabase setup)
-- ALTER TABLE user_tokens ENABLE ROW LEVEL SECURITY;

-- Optional: Add RLS policies (if you want row-level security)
-- CREATE POLICY "Users can only access their own tokens" ON user_tokens
--     FOR ALL USING (auth.email() = user_email);
