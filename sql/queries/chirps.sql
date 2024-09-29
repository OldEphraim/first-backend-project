-- name: CreateChirp :one
INSERT INTO chirps (body, user_id)
VALUES ($1, $2)
RETURNING id, created_at, updated_at;

-- name: GetAllChirps :many
SELECT id, body, user_id, created_at, updated_at
FROM chirps
ORDER BY created_at ASC;

-- name: GetChirpsByAuthorID :many
SELECT id, body, user_id, created_at, updated_at
FROM chirps
WHERE user_id = $1
ORDER BY created_at ASC;

-- name: GetChirpByID :one
SELECT * FROM chirps
WHERE id = $1;

-- name: GetChirpAuthorID :one
SELECT user_id
FROM chirps
WHERE id = $1;

-- name: DeleteChirp :exec
DELETE FROM chirps
WHERE id = $1;