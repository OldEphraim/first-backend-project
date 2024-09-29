-- name: CreateUser :one
INSERT INTO users (id, created_at, updated_at, email, hashed_password, is_chirpy_red)
VALUES (gen_random_uuid(), NOW(), NOW(), $1, $2, FALSE)
RETURNING id, created_at, updated_at, email, hashed_password, is_chirpy_red;

-- name: GetUser :one
SELECT *
FROM users
WHERE id = $1;

-- name: GetUserByEmail :one
SELECT * FROM users WHERE email = $1;

-- name: DeleteAllUsers :exec
DELETE FROM users;

-- name: UpdateUser :one
UPDATE users
SET 
    email = COALESCE(NULLIF($1, ''), email),
    hashed_password = COALESCE(NULLIF($2, ''), hashed_password)
WHERE 
    id = $3
RETURNING id, created_at, updated_at, email, hashed_password, is_chirpy_red;

-- name: UpgradeUserToChirpyRed :exec
UPDATE users
SET is_chirpy_red = TRUE
WHERE id = $1;