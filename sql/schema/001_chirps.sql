-- +goose Up
CREATE TABLE chirps (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),  -- Automatically generate UUID
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),  -- Use TIMESTAMPTZ for timezone-aware timestamps
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),  -- Same as above
    body TEXT NOT NULL,                              -- The content of the chirp
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE  -- Foreign key referencing users table
);

-- +goose Down
DROP TABLE chirps;