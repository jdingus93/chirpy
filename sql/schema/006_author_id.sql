-- +goose Up
ALTER TABLE chirps ADD COLUMN author_id INTEGER;