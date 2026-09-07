package listener

import (
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"path/filepath"
	"testing"
	"time"
)

// TestSQLiteSinkWriteAndQuery verifies the SQLiteSink creates the table,
// INSERTs a Flow with populated headers, and lets a downstream reader
// pull the row back by id. Uses a temp dir DB so the test can run
// serial or parallel without clashing with a real flows.sqlite.
func TestSQLiteSinkWriteAndQuery(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "flows.sqlite")
	s, err := NewSQLiteSink(dbPath)
	if err != nil {
		t.Fatalf("NewSQLiteSink: %v", err)
	}
	defer s.Close()

	fl := NewFlow("https-mitm", "example.com:443", "127.0.0.1:54321")
	fl.Method = "GET"
	fl.Path = "/api/status"
	fl.RequestHeaders = []string{
		"Host: example.com",
		"Cookie: sid=abc123; uid=42",
		"User-Agent: test",
	}
	fl.ResponseHeaders = []string{
		"Content-Type: application/json",
		"Cache-Control: no-store",
	}
	fl.ResponseStatus = 200
	fl.ResponseProto = "HTTP/1.1"
	fl.RequestBytes = 123
	fl.ResponseBytes = 456
	fl.Intercepted = true
	s.Write(fl)

	// Query the row back via a fresh connection — proves the INSERT
	// actually committed and the columns round-trip as expected.
	conn, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	defer conn.Close()

	var (
		id, ts, protocol, target, method, path, reqHeaders, respHeaders string
		status, intercepted                                             int
		reqBytes, respBytes, durationNs                                 int64
	)
	err = conn.QueryRow(`
		SELECT id, ts, protocol, target, method, path, response_status,
		       request_bytes, response_bytes, intercepted,
		       request_headers, response_headers, duration_ns
		FROM flows WHERE id = ?`, fl.ID).
		Scan(&id, &ts, &protocol, &target, &method, &path, &status,
			&reqBytes, &respBytes, &intercepted, &reqHeaders, &respHeaders, &durationNs)
	if err != nil {
		t.Fatalf("query flow: %v", err)
	}
	if id != fl.ID || protocol != "https-mitm" || target != "example.com:443" ||
		method != "GET" || path != "/api/status" || status != 200 ||
		reqBytes != 123 || respBytes != 456 || intercepted != 1 {
		t.Errorf("round-trip mismatch: id=%s protocol=%s target=%s method=%s path=%s status=%d req=%d resp=%d int=%d",
			id, protocol, target, method, path, status, reqBytes, respBytes, intercepted)
	}
	if ts == "" {
		t.Error("ts column empty")
	}
	if _, err := time.Parse(time.RFC3339Nano, ts); err != nil {
		t.Errorf("ts not RFC3339Nano: %v (value=%q)", err, ts)
	}
	var reqHdr, respHdr []string
	if err := json.Unmarshal([]byte(reqHeaders), &reqHdr); err != nil {
		t.Fatalf("request_headers not valid JSON: %v", err)
	}
	if err := json.Unmarshal([]byte(respHeaders), &respHdr); err != nil {
		t.Fatalf("response_headers not valid JSON: %v", err)
	}
	if len(reqHdr) != 3 || reqHdr[1] != "Cookie: sid=abc123; uid=42" {
		t.Errorf("request_headers round-trip wrong: %v", reqHdr)
	}
	if len(respHdr) != 2 || respHdr[0] != "Content-Type: application/json" {
		t.Errorf("response_headers round-trip wrong: %v", respHdr)
	}
}

// TestSQLiteSinkCreatesIndexes checks the two convenience indexes exist
// after NewSQLiteSink runs — they are the "common queries" contract
// (recent flows by time, lookups by target).
func TestSQLiteSinkCreatesIndexes(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "flows.sqlite")
	s, err := NewSQLiteSink(dbPath)
	if err != nil {
		t.Fatalf("NewSQLiteSink: %v", err)
	}
	defer s.Close()
	conn, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer conn.Close()
	rows, err := conn.Query(`SELECT name FROM sqlite_master WHERE type='index' AND tbl_name='flows' ORDER BY name`)
	if err != nil {
		t.Fatalf("query indexes: %v", err)
	}
	defer rows.Close()
	var names []string
	for rows.Next() {
		var n string
		if err := rows.Scan(&n); err != nil {
			t.Fatalf("scan: %v", err)
		}
		names = append(names, n)
	}
	if len(names) < 2 {
		t.Fatalf("expected at least 2 indexes (ts, target), got %v", names)
	}
	hasTs, hasTarget := false, false
	for _, n := range names {
		if n == "idx_flows_ts" {
			hasTs = true
		}
		if n == "idx_flows_target" {
			hasTarget = true
		}
	}
	if !hasTs || !hasTarget {
		t.Errorf("missing indexes: hasTs=%v hasTarget=%v (all=%v)", hasTs, hasTarget, names)
	}
}

// TestSQLiteSinkBodyRoundTrip exercises the base64 body encoding: a nil
// body must stay NULL in SQLite, a non-nil body must round-trip to the
// exact same bytes via base64 decode.
func TestSQLiteSinkBodyRoundTrip(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "flows.sqlite")
	s, err := NewSQLiteSink(dbPath)
	if err != nil {
		t.Fatalf("NewSQLiteSink: %v", err)
	}
	defer s.Close()

	fl := NewFlow("http", "example.com:80", "127.0.0.1:54321")
	fl.RequestBody = []byte("hello body")
	s.Write(fl)

	conn, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer conn.Close()

	var reqBody *string
	err = conn.QueryRow(`SELECT request_body FROM flows WHERE id = ?`, fl.ID).Scan(&reqBody)
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	if reqBody == nil {
		t.Fatal("expected request_body to be non-NULL when body is set")
	}
	// Decode and compare — base64 round-trip must be byte-exact.
	decoded, err := base64.StdEncoding.DecodeString(*reqBody)
	if err != nil {
		t.Fatalf("decode base64: %v", err)
	}
	if string(decoded) != "hello body" {
		t.Errorf("body round-trip mismatch: got %q want %q", decoded, "hello body")
	}

	// Empty body → NULL.
	fl2 := NewFlow("http", "example.com:80", "127.0.0.1:54322")
	s.Write(fl2)
	var emptyBody *string
	if err := conn.QueryRow(`SELECT request_body FROM flows WHERE id = ?`, fl2.ID).Scan(&emptyBody); err != nil {
		t.Fatalf("query empty: %v", err)
	}
	if emptyBody != nil {
		t.Errorf("expected request_body to be NULL for empty body, got %q", *emptyBody)
	}
}
