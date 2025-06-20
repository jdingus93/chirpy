-- name: CreateUser :one
INSERT INTO users (id, created_at, updated_at, email, hashed_password)
VALUES (
    DEFAULT,
    NOW(),
    NOW(),
    $1,
    $2
)
RETURNING *;