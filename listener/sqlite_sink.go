package listener

import (
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sync"
	"time"

	_ "modernc.org/sqlite"
)

// SQLiteSink writes each completed Flow into a SQLite table. This is the
// structured counterpart to JSONFlowSink: JSON is best for humans reading
// a tail with `tail -f`, SQLite is best for programmatic querying
// (`SELECT * FROM flows WHERE target LIKE '%google.com' ORDER BY ts DESC
// LIMIT 20`). Both implement FlowSink; operators can wire both to
// receive every Flow.
//
// Concurrency: the driver is safe for concurrent use but we still guard
// the db handle with a mutex because writes from many goroutines (one
// per client conn) into a single WAL-mode SQLite is much faster
// serialized than parallel — the write-ahead log is single-writer.
// Reads are unrestricted.
//
// Storage format:
//   - Timestamp → RFC3339Nano string (SQLite stores it as TEXT).
//   - Duration  → int64 nanoseconds (portable across SQL clients).
//   - Headers   → JSON array of "Name: value" strings (lossless round-trip).
//   - Bodies    → base64 TEXT (binary-safe; a nil body stays NULL).
//   - Intercepted → INTEGER (SQLite has no bool).
type SQLiteSink struct {
	db *sql.DB
	mu sync.Mutex
}

// NewSQLiteSink opens (or creates) a SQLite database at path, creates the
// flows table if absent, and enables WAL mode for concurrent readers. The
// parent directory is created if missing.
func NewSQLiteSink(path string) (*SQLiteSink, error) {
	if path == "" {
		return nil, fmt.Errorf("sqlite sink: path required")
	}
	if dir := filepath.Dir(path); dir != "." && dir != "" {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return nil, fmt.Errorf("sqlite sink: mkdir %s: %w", dir, err)
		}
	}
	// _busy_timeout=5000 lets a slow writer wait for the WAL to free up
	// instead of returning SQLITE_BUSY immediately.
	dsn := path + "?_pragma=journal_mode=WAL&_pragma=busy_timeout=5000&_pragma=synchronous=NORMAL"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("sqlite sink: open: %w", err)
	}
	// sqlite's driver holds 1 connection max by default; 4 is a good
	// middle for our write pattern.
	db.SetMaxOpenConns(4)
	// Create the flows table if it doesn't exist. Idempotent.
	if _, err := db.Exec(`CREATE TABLE IF NOT EXISTS flows (
		id TEXT PRIMARY KEY,
		ts TEXT NOT NULL,
		protocol TEXT,
		target TEXT,
		client_addr TEXT,
		method TEXT,
		path TEXT,
		full_url TEXT,
		proxy_name TEXT,
		response_status INTEGER,
		response_proto TEXT,
		error TEXT,
		duration_ns INTEGER,
		request_bytes INTEGER,
		response_bytes INTEGER,
		intercepted INTEGER,
		request_proto TEXT,
		request_headers TEXT,
		response_headers TEXT,
		request_body TEXT,
		response_body TEXT
	)`); err != nil {
		db.Close()
		return nil, fmt.Errorf("sqlite sink: create table: %w", err)
	}
	// Convenience indexes for the two most common queries.
	if _, err := db.Exec(`CREATE INDEX IF NOT EXISTS idx_flows_ts ON flows(ts DESC)`); err != nil {
		db.Close()
		return nil, fmt.Errorf("sqlite sink: create index ts: %w", err)
	}
	if _, err := db.Exec(`CREATE INDEX IF NOT EXISTS idx_flows_target ON flows(target)`); err != nil {
		db.Close()
		return nil, fmt.Errorf("sqlite sink: create index target: %w", err)
	}
	return &SQLiteSink{db: db}, nil
}

// Write INSERTs the Flow. Concurrent callers are serialized by mu; a
// slow disk is not supposed to block request handling, so the caller
// sees the INSERT return as soon as SQLite commits. Failures are logged
// but not returned — the sink pattern says "best effort", a failing
// sink must never take down the proxy.
func (s *SQLiteSink) Write(f *Flow) {
	if s == nil || s.db == nil || f == nil {
		return
	}
	f.Finalize()
	reqHdr, err := json.Marshal(f.RequestHeaders)
	if err != nil {
		reqHdr = []byte("[]")
	}
	respHdr, err := json.Marshal(f.ResponseHeaders)
	if err != nil {
		respHdr = []byte("[]")
	}
	reqBody := nullableBase64(f.RequestBody)
	respBody := nullableBase64(f.ResponseBody)
	intercepted := 0
	if f.Intercepted {
		intercepted = 1
	}
	ts := f.Timestamp.UTC().Format(time.RFC3339Nano)
	s.mu.Lock()
	_, err = s.db.Exec(`INSERT OR REPLACE INTO flows (
		id, ts, protocol, target, client_addr, method, path, full_url, proxy_name,
		response_status, response_proto, error, duration_ns, request_bytes, response_bytes,
		intercepted, request_proto, request_headers, response_headers, request_body, response_body
	) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		f.ID, ts, f.Protocol, f.Target, f.ClientAddr, f.Method, f.Path, f.FullURL, f.ProxyName,
		f.ResponseStatus, f.ResponseProto, f.Error, f.Duration.Nanoseconds(), f.RequestBytes, f.ResponseBytes,
		intercepted, f.RequestProto, string(reqHdr), string(respHdr), reqBody, respBody,
	)
	s.mu.Unlock()
	if err != nil {
		log.Printf("sqlite sink: insert flow %s: %v", f.ID, err)
	}
}

// Close flushes and closes the underlying database.
func (s *SQLiteSink) Close() error {
	if s == nil || s.db == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.db.Close()
}

// nullableBase64 encodes a []byte as base64, or returns NULL when the
// input is nil/empty. Empty bodies and present-but-empty bodies are
// indistinguishable at the SQLite layer; that matches the JSON
// representation (omitempty drops both).
func nullableBase64(b []byte) any {
	if len(b) == 0 {
		return nil
	}
	return base64.StdEncoding.EncodeToString(b)
}
