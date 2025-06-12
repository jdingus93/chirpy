-- name: GetUserFromRefreshToken :one
SELECT id, revoked_at, expires_at
FROM users
JOIN refresh_tokens ON users.id = refresh_tokens.user_id
WHERE token = $1 AND revoked_at IS NULL AND expires_at > NOW();