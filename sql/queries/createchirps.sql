-- name: CreateChirp :one
INSERT INTO chirps (created_at, updated_at, body, user_id, author_id)
VALUES ($1, $2, $3, $4, $5)
RETURNING *;