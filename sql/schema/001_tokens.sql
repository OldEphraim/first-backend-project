-- +goose Up
CREATE TABLE refresh_tokens (
    token VARCHAR PRIMARY KEY,  -- String primary key for the refresh token
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),  -- Timestamp for when the token was created
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),  -- Timestamp for when the token was last updated
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,  -- Foreign key to users table
    expires_at TIMESTAMPTZ NOT NULL,  -- Timestamp for when the token expires
    revoked_at TIMESTAMPTZ  -- Timestamp for when the token was revoked, null if not revoked
);

-- +goose Down
DROP TABLE refresh_tokens;