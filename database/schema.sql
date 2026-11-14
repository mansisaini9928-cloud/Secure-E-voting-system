PRAGMA foreign_keys = ON;
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE,
    email TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'voter' CHECK(role IN ('voter','admin')),
    has_voted INTEGER NOT NULL DEFAULT 0 CHECK(has_voted IN (0,1)),
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS candidates (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    party TEXT NOT NULL,
    symbol TEXT NOT NULL DEFAULT '◈',
    active INTEGER NOT NULL DEFAULT 1 CHECK(active IN (0,1))
);
CREATE TABLE IF NOT EXISTS election (
    id INTEGER PRIMARY KEY CHECK(id = 1),
    status TEXT NOT NULL DEFAULT 'open' CHECK(status IN ('open','closed')),
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
INSERT OR IGNORE INTO election(id,status) VALUES(1,'open');
-- ballot_hash is a one-way commitment. Candidate choice is never stored here.
CREATE TABLE IF NOT EXISTS ballots (
    id TEXT PRIMARY KEY,
    ballot_hash TEXT NOT NULL UNIQUE,
    previous_hash TEXT NOT NULL,
    chain_hash TEXT NOT NULL UNIQUE,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
-- Aggregate-only counts; there is no voter or ballot id on this table.
CREATE TABLE IF NOT EXISTS tally_counts (
    candidate_id INTEGER PRIMARY KEY REFERENCES candidates(id),
    vote_count INTEGER NOT NULL DEFAULT 0 CHECK(vote_count >= 0)
);
CREATE TABLE IF NOT EXISTS vote_tokens (
    token_hash TEXT PRIMARY KEY,
    user_id INTEGER NOT NULL UNIQUE REFERENCES users(id) ON DELETE CASCADE,
    expires_at TEXT NOT NULL,
    consumed INTEGER NOT NULL DEFAULT 0 CHECK(consumed IN (0,1))
);
CREATE TABLE IF NOT EXISTS security_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    kind TEXT NOT NULL,
    severity TEXT NOT NULL CHECK(severity IN ('low','medium','high','critical')),
    message TEXT NOT NULL,
    score REAL NOT NULL DEFAULT 0,
    simulated INTEGER NOT NULL DEFAULT 0,
    reviewed INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
