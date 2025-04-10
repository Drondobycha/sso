CREATE TABLE IF NOT EXISTS apps
(
    id     INTEGER PRIMARY KEY,
    name   TEXT NOT NULL UNIQUE,
    secret TEXT NOT NULL UNIQUE
);

INSERT INTO apps (id, name, secret)
VALUES (1, 'test', 'test-secret')
ON CONFLICT DO NOTHING;