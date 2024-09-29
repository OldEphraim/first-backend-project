-- +goose Up
-- +goose StatementBegin
CREATE TABLE chirps (
    id SERIAL PRIMARY KEY,
    user_id UUID NOT NULL,
    body TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE chirps;
-- +goose StatementEnd