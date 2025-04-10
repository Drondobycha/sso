CREATE TABLE IF NOT EXISTS users (
    id         SERIAL PRIMARY KEY,
    email      TEXT NOT NULL UNIQUE,
    pass_hash  BYTEA NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW() NOT NULL,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW() NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_users_email ON users (email);

CREATE TABLE IF NOT EXISTS apps (
    id          SERIAL PRIMARY KEY,
    name        TEXT NOT NULL UNIQUE,
    secret      TEXT NOT NULL UNIQUE
);

CREATE TABLE IF NOT EXISTS permissions (
    id          SERIAL PRIMARY KEY,
    user_id     INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    permission  TEXT NOT NULL,
    granted_at  TIMESTAMP WITH TIME ZONE DEFAULT NOW() NOT NULL,
    CONSTRAINT  uq_user_permission UNIQUE (user_id, permission)
);