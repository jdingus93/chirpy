-- name: DeleteChirp :exec
DELETE FROM chirps
WHERE id = $1;

-- name: DeleteAllChirps :exec
DELETE FROM chirps;