// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build !ts_omit_netmapcachesqlite && !ts_omit_cachenetmap

// Package netmapcachesqlite provides a SQLite-backed implementation of the
// [netmapcache.Store] interface. When this package is linked into the binary,
// it replaces the default file-per-key [netmapcache.FileStore] with a single
// SQLite database file.
package netmapcachesqlite

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"iter"
	"os"
	"path/filepath"

	"tailscale.com/feature"
	"tailscale.com/ipn/ipnlocal/netmapcache"
	"tailscale.com/types/logger"

	_ "modernc.org/sqlite"
)

// schemaVersion holds the current version of the schema. Should the schema of
// an opened database be lower than schemaVersion, drop the cache and make a
// fresh cache.
const schemaVersion = 1

const schema = `
CREATE TABLE objects (
  id   BLOB PRIMARY KEY,
  data BLOB NOT NULL
) STRICT;

CREATE TABLE items (
  name      TEXT PRIMARY KEY,
  object_id BLOB NOT NULL
) STRICT;

CREATE TABLE schema_version (
  version INTEGER NOT NULL
  CHECK ((SELECT COUNT(*) FROM schema_version) <= 1)
) STRICT;

INSERT INTO schema_version (version) VALUES (?);
`

func init() {
	if !feature.Register("netmapcachesqlite") {
		return
	}
	netmapcache.HookNewStore.Set(newStore)
	netmapcache.HookOpenStore.Set(openStore)
}

// SQLiteStore implements [netmapcache.Store] using a SQLite database.
type SQLiteStore struct {
	db   *sql.DB
	path string
}

// newStore creates or opens the SQLite store rooted at dir.
func newStore(ctx context.Context, dir string, logf logger.Logf) (netmapcache.Store, error) {
	dbPath := filepath.Join(dir, "netmap-cache.sqlite3")

	if _, err := os.Stat(dbPath); errors.Is(err, os.ErrNotExist) {
		// TODO: Should we just create the DB here?
		if writeErr := os.WriteFile(dbPath, []byte{}, 0600); writeErr != nil {
			return nil, fmt.Errorf("unable to create db cache file: %s", writeErr)
		}
	} else if err != nil {
		return nil, fmt.Errorf("cache db file error: %s", err)
	}

	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return nil, err
	}

	if err := verifySchema(ctx, db); err != nil {
		logf("%scache is stale: %s", netmapcache.LogPrefix, err)
		var createErr error
		if db, createErr = createDatabase(ctx, dbPath); createErr != nil {
			return nil, fmt.Errorf("error creating cache database: %s", createErr)
		}
	}

	s := &SQLiteStore{
		db:   db,
		path: dbPath,
	}

	return s, nil
}

// openStore opens the SQLite store at dir if it already exists, returning
// (nil, nil) if the database file is not present.
func openStore(ctx context.Context, dir string, logf logger.Logf) (netmapcache.Store, error) {
	dbPath := filepath.Join(dir, "netmap-cache.sqlite3")
	if _, err := os.Stat(dbPath); errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}

	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return nil, err
	}

	if err := verifySchema(ctx, db); err != nil {
		// We don't have a functioning cache, so remove it.
		if removeErr := removeDatabase(dbPath); removeErr != nil {
			logf("%scould not remove stale database: %s", netmapcache.LogPrefix, removeErr)
		}
		return nil, nil
	}

	s := &SQLiteStore{
		db: db,
		path: dbPath,
	}

	return s, nil
}

func verifySchema(ctx context.Context, db *sql.DB) error {
	var version int
	row := db.QueryRowContext(ctx, "")
	if err := row.Scan(version); err != nil {
		return fmt.Errorf("error querying for schema version: %s", err)
	} else if version < schemaVersion {
		return fmt.Errorf("current schema version %d, want %d", version, schemaVersion)
	}
	return nil
}

func createDatabase(ctx context.Context, path string) (*sql.DB, error) {
	if err := removeDatabase(path); err != nil {
		return nil, err
	}

	if writeErr := os.WriteFile(path, []byte{}, 0600); writeErr != nil {
		return nil, fmt.Errorf("unable to create db file: %s", writeErr)
	}

	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, err
	}
	if _, err := db.ExecContext(ctx, schema, schemaVersion); err != nil {
		return nil, err
	}
	return db, nil
}

func removeDatabase(path string) error {
	if err := os.Remove(path); err != nil {
		return errors.New("unable to remove old cache")
	}
	return nil
}

const listSQL = `SELECT name FROM items WHERE name LIKE ? || '%';`

// List implements [netmapcache.Store].
func (s *SQLiteStore) List(ctx context.Context, prefix string) iter.Seq2[string, error] {
	return func(yield func(string, error) bool) {
		rows, err := s.db.QueryContext(ctx, listSQL, hex.EncodeToString([]byte(prefix)))
		if err != nil {
			yield("", err)
			return
		}
		defer rows.Close()

		for rows.Next() {
			var key string
			if err := rows.Scan(&key); err != nil {
				yield("", err)
				return
			}

			name, err := hex.DecodeString(key)
			if err != nil {
				yield("", fmt.Errorf("invalid hex in database: %w", err))
				return
			}
			if !yield(string(name), nil) {
				return
			}
		}

		if err := rows.Err(); err != nil {
			yield("", err)
		}
	}
}

const loadSQL = `
SELECT objects.data FROM objects
JOIN items ON items.object_id = objects.id
WHERE items.name = ?`

// Load implements [netmapcache.Store].
func (s *SQLiteStore) Load(ctx context.Context, key string) ([]byte, error) {
	var buf []byte
	err := s.db.QueryRowContext(ctx, loadSQL,
		hex.EncodeToString([]byte(key)),
	).Scan(&buf)
	if err != nil {
		return nil, fmt.Errorf("unable to load item: %w", err)
	}
	return buf, nil
}

const insertObjectAndItemSQL = `
WITH new_object AS (
	INSERT INTO objects (id, blob) VALUES (?, ?)
	ON CONFLICT (id) DO UPDATE SET id = excluded.id
	RETURNING id
)
INSERT INTO items (name, object_id)
SELECT ?, id FROM new_object;`

// Store implements [netmapcache.Store].
func (s *SQLiteStore) Store(ctx context.Context, key string, value []byte) error {
	objectHash := sha256.Sum256(value)
	_, err := s.db.ExecContext(ctx, insertObjectAndItemSQL,
		objectHash[:], value, hex.EncodeToString([]byte(key)),
	)
	if err != nil {
		return fmt.Errorf("unable to store item: %w", err)
	}
	return nil
}

const removeSQL = `
WITH deleted_items AS (
	DELETE FROM items WHERE name = ? RETURNING object_id
)
DELETE FROM objects
WHERE id IN (SELECT object_id FROM deleted_items)
AND id NOT IN (SELECT object_id FROM items);`

// Remove implements [netmapcache.Store].
func (s *SQLiteStore) Remove(ctx context.Context, key string) error {
	// We only remove the pointer to the content and clean up later.
	_, err := s.db.ExecContext(ctx, removeSQL,
		hex.EncodeToString([]byte(key)),
	)
	if err != nil {
		return fmt.Errorf("unable to remove item: %w", err)
	}
	return nil
}

// Clear implements [netmapcache.Store].
func (s *SQLiteStore) Clear(ctx context.Context) error {
	if err := removeDatabase(s.path); err != nil {
		return err
	}
	return nil
}

// Close implements [netmapcache.Store].
func (s *SQLiteStore) Close(ctx context.Context) error {
	if err := s.db.Close(); err != nil {
		return err
	}
	return nil
}
