-- up.sql
CREATE TABLE chirps (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    body TEXT NOT NULL,
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,
);

-- down.sql
DROP TABLE chirps;