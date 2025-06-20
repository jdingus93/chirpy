-- name: RetrieveChirps :many
SELECT * FROM chirps
WHERE author_id = $1 OR $1 = 0
ORDER BY created_at ASC;