package db

import (
	"context"
	"database/sql"
	"embed"
	"fmt"
	"log"
	"sync"
	"time"

	_ "modernc.org/sqlite"
)

//go:embed schema.sql
var schemaFS embed.FS

// DB wraps the SQL database connection with thread-safe access
type DB struct {
	*sql.DB
	mu sync.RWMutex
}

// Open opens a SQLite database at the given path and runs migrations
func Open(path string) (*DB, error) {
	dsn := path + "?_journal_mode=WAL&_busy_timeout=5000&_foreign_keys=ON"
	sqlDB, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %w", err)
	}

	// Set connection pool settings for SQLite
	sqlDB.SetMaxOpenConns(1) // SQLite handles concurrency via WAL
	sqlDB.SetMaxIdleConns(1)
	sqlDB.SetConnMaxLifetime(0)

	db := &DB{DB: sqlDB}
	if err := db.migrate(); err != nil {
		sqlDB.Close()
		return nil, fmt.Errorf("failed to migrate database: %w", err)
	}

	return db, nil
}

// migrate runs the embedded schema.sql
func (db *DB) migrate() error {
	schema, err := schemaFS.ReadFile("schema.sql")
	if err != nil {
		return fmt.Errorf("failed to read schema: %w", err)
	}

	db.mu.Lock()
	defer db.mu.Unlock()

	_, err = db.Exec(string(schema))
	if err != nil {
		return fmt.Errorf("failed to execute schema: %w", err)
	}

	return nil
}

// StartCleanupRoutine starts a background goroutine that periodically cleans up
// expired sessions and orders
func (db *DB) StartCleanupRoutine(ctx context.Context) {
	go func() {
		ticker := time.NewTicker(1 * time.Minute)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				if err := db.cleanupExpired(); err != nil {
					log.Printf("Cleanup error: %v", err)
				}
			}
		}
	}()
}

// cleanupExpired removes expired sessions and orders
func (db *DB) cleanupExpired() error {
	db.mu.Lock()
	defer db.mu.Unlock()

	now := time.Now().UTC().Format(time.RFC3339)

	// Clean expired activation sessions
	result, err := db.Exec("DELETE FROM activation_sessions WHERE expires_at < ?", now)
	if err != nil {
		return fmt.Errorf("failed to cleanup sessions: %w", err)
	}
	if rows, _ := result.RowsAffected(); rows > 0 {
		log.Printf("Cleaned up %d expired activation sessions", rows)
	}

	// Clean expired ACME orders (keep for 24h after expiry for debugging)
	expiredCutoff := time.Now().Add(-24 * time.Hour).UTC().Format(time.RFC3339)
	result, err = db.Exec("DELETE FROM acme_orders WHERE expires_at < ?", expiredCutoff)
	if err != nil {
		return fmt.Errorf("failed to cleanup orders: %w", err)
	}
	if rows, _ := result.RowsAffected(); rows > 0 {
		log.Printf("Cleaned up %d expired ACME orders", rows)
	}

	return nil
}

// Close closes the database connection
func (db *DB) Close() error {
	return db.DB.Close()
}

// Transaction executes a function within a database transaction
func (db *DB) Transaction(ctx context.Context, fn func(*sql.Tx) error) error {
	db.mu.Lock()
	defer db.mu.Unlock()

	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}

	if err := fn(tx); err != nil {
		tx.Rollback()
		return err
	}

	return tx.Commit()
}
