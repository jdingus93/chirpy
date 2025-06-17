-- name: UpgradeUser :execresult
UPDATE users SET is_chirpy_red = TRUE WHERE id = $1;