CREATE TABLE IF NOT EXISTS peers (
    peer_id TEXT PRIMARY KEY,
    username TEXT UNIQUE NOT NULL,
    public_key BLOB NOT NULL,
    created_at TEXT NOT NULL
);
