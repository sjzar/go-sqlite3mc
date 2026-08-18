// Package sqlite3mc provides a small cgo wrapper for SQLite3 Multiple Ciphers
// databases configured with AES-128-CBC encryption.
package sqlite3mc

/*
#cgo CFLAGS: -DSQLITE_HAS_CODEC=1 -DCODEC_TYPE=CODEC_TYPE_AES128 -DSQLITE_ENABLE_COLUMN_METADATA=1 -DSQLITE_THREADSAFE=1
#cgo darwin LDFLAGS: -lm
#cgo linux LDFLAGS: -lm -ldl -lpthread

#include "sqlite3mc_amalgamation.h"
#include <stdlib.h>
*/
import "C"

import (
	"context"
	"encoding/hex"
	"fmt"
	"sync"
	"unsafe"
)

// DB is a serialized handle to an encrypted SQLite database.
//
// A DB may be shared by multiple goroutines. Close is idempotent. A DB opened
// with Open is read-only; use OpenReadWrite when writes are required.
type DB struct {
	mu sync.Mutex
	db *C.sqlite3
}

// Row contains one query result keyed by column name. SQLite integer values
// are returned as int64, real values as float64, text as string, and blobs as
// []byte. SQL NULL values are returned as nil.
type Row map[string]any

// Open opens an existing encrypted SQLite database in read-only mode.
// rawKeyHex must contain the 16-byte database key encoded as 32 hexadecimal
// characters.
func Open(path, rawKeyHex string) (*DB, error) {
	key, err := hex.DecodeString(rawKeyHex)
	if err != nil || len(key) != 16 {
		return nil, fmt.Errorf("invalid raw key: must be 32 hex characters")
	}
	cPath := C.CString(path)
	defer C.free(unsafe.Pointer(cPath))
	var handle *C.sqlite3
	const readonlyURI = C.int(0x00000001 | 0x00000040)
	if rc := C.sqlite3_open_v2(cPath, &handle, readonlyURI, nil); rc != 0 {
		return nil, openError(handle, rc)
	}
	if err := configure(handle, key, true); err != nil {
		C.sqlite3_close(handle)
		return nil, err
	}
	return &DB{db: handle}, nil
}

// OpenReadWrite opens an encrypted SQLite database for reading and writing.
// It creates the database when path does not exist. rawKeyHex must contain the
// 16-byte database key encoded as 32 hexadecimal characters.
func OpenReadWrite(path, rawKeyHex string) (*DB, error) {
	key, err := hex.DecodeString(rawKeyHex)
	if err != nil || len(key) != 16 {
		return nil, fmt.Errorf("invalid raw key: must be 32 hex characters")
	}
	cPath := C.CString(path)
	defer C.free(unsafe.Pointer(cPath))
	var handle *C.sqlite3
	if rc := C.sqlite3_open_v2(cPath, &handle, C.int(0x00000002|0x00000004), nil); rc != 0 {
		return nil, openError(handle, rc)
	}
	if err := configure(handle, key, false); err != nil {
		C.sqlite3_close(handle)
		return nil, err
	}
	return &DB{db: handle}, nil
}

func configure(handle *C.sqlite3, key []byte, readonly bool) error {
	if err := exec(handle, "PRAGMA cipher = aes128cbc"); err != nil {
		return fmt.Errorf("set cipher: %w", err)
	}
	fullKey := append([]byte("raw:"), key...)
	cKey := C.CBytes(fullKey)
	rc := C.sqlite3_key(handle, cKey, C.int(len(fullKey)))
	C.free(cKey)
	if rc != 0 {
		return fmt.Errorf("sqlite3_key failed: rc=%d", rc)
	}
	if readonly {
		if err := exec(handle, "PRAGMA query_only = ON"); err != nil {
			return fmt.Errorf("enable query_only: %w", err)
		}
	}
	if err := exec(handle, "PRAGMA busy_timeout = 5000"); err != nil {
		return fmt.Errorf("set busy timeout: %w", err)
	}
	if _, err := query(context.Background(), handle, "SELECT count(*) FROM sqlite_master"); err != nil {
		return fmt.Errorf("key verification: %w", err)
	}
	return nil
}

// Exec executes one SQL statement with optional positional arguments.
func (d *DB) Exec(statement string, args ...any) error {
	if d == nil {
		return fmt.Errorf("database is closed")
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.db == nil {
		return fmt.Errorf("database is closed")
	}
	cStatement := C.CString(statement)
	defer C.free(unsafe.Pointer(cStatement))
	var stmt *C.sqlite3_stmt
	if rc := C.sqlite3_prepare_v2(d.db, cStatement, -1, &stmt, nil); rc != 0 {
		return sqliteError(d.db, "prepare", rc)
	}
	defer C.sqlite3_finalize(stmt)
	for index, arg := range args {
		if err := bind(stmt, index+1, arg); err != nil {
			return err
		}
	}
	if rc := C.sqlite3_step(stmt); rc != C.int(101) {
		return sqliteError(d.db, "exec", rc)
	}
	return nil
}

// Query executes a SQL query with optional positional arguments and returns
// all result rows. The context is checked between SQLite rows.
func (d *DB) Query(ctx context.Context, statement string, args ...any) ([]Row, error) {
	if d == nil {
		return nil, fmt.Errorf("database is closed")
	}
	if ctx == nil {
		return nil, fmt.Errorf("nil context")
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.db == nil {
		return nil, fmt.Errorf("database is closed")
	}
	return query(ctx, d.db, statement, args...)
}

// Tables returns table names in lexical order.
func (d *DB) Tables(ctx context.Context) ([]string, error) {
	rows, err := d.Query(ctx, "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")
	if err != nil {
		return nil, err
	}
	result := make([]string, 0, len(rows))
	for _, row := range rows {
		if name, ok := row["name"].(string); ok {
			result = append(result, name)
		}
	}
	return result, nil
}

// Close releases the underlying SQLite handle. It is safe to call Close more
// than once.
func (d *DB) Close() error {
	if d == nil {
		return nil
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.db != nil {
		C.sqlite3_close(d.db)
		d.db = nil
	}
	return nil
}

func query(ctx context.Context, handle *C.sqlite3, statement string, args ...any) ([]Row, error) {
	cStatement := C.CString(statement)
	defer C.free(unsafe.Pointer(cStatement))
	var stmt *C.sqlite3_stmt
	if rc := C.sqlite3_prepare_v2(handle, cStatement, -1, &stmt, nil); rc != 0 {
		return nil, sqliteError(handle, "prepare", rc)
	}
	defer C.sqlite3_finalize(stmt)
	for index, arg := range args {
		if err := bind(stmt, index+1, arg); err != nil {
			return nil, err
		}
	}
	count := int(C.sqlite3_column_count(stmt))
	columns := make([]string, count)
	for i := range count {
		columns[i] = C.GoString(C.sqlite3_column_name(stmt, C.int(i)))
	}
	var rows []Row
	for {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}
		rc := C.sqlite3_step(stmt)
		switch rc {
		case C.int(101):
			return rows, nil
		case C.int(100):
			row := make(Row, count)
			for i, name := range columns {
				row[name] = columnValue(stmt, i)
			}
			rows = append(rows, row)
		default:
			return nil, sqliteError(handle, "step", rc)
		}
	}
}

func bind(stmt *C.sqlite3_stmt, index int, value any) error {
	var rc C.int
	switch v := value.(type) {
	case nil:
		rc = C.sqlite3_bind_null(stmt, C.int(index))
	case int:
		rc = C.sqlite3_bind_int64(stmt, C.int(index), C.sqlite3_int64(v))
	case int8:
		rc = C.sqlite3_bind_int64(stmt, C.int(index), C.sqlite3_int64(v))
	case int16:
		rc = C.sqlite3_bind_int64(stmt, C.int(index), C.sqlite3_int64(v))
	case int32:
		rc = C.sqlite3_bind_int64(stmt, C.int(index), C.sqlite3_int64(v))
	case int64:
		rc = C.sqlite3_bind_int64(stmt, C.int(index), C.sqlite3_int64(v))
	case uint:
		rc = C.sqlite3_bind_int64(stmt, C.int(index), C.sqlite3_int64(v))
	case uint32:
		rc = C.sqlite3_bind_int64(stmt, C.int(index), C.sqlite3_int64(v))
	case uint64:
		rc = C.sqlite3_bind_int64(stmt, C.int(index), C.sqlite3_int64(v))
	case float32:
		rc = C.sqlite3_bind_double(stmt, C.int(index), C.double(v))
	case float64:
		rc = C.sqlite3_bind_double(stmt, C.int(index), C.double(v))
	case string:
		cValue := C.CString(v)
		defer C.free(unsafe.Pointer(cValue))
		rc = C.sqlite3_bind_text(stmt, C.int(index), cValue, C.int(len(v)), (*[0]byte)(C.SQLITE_TRANSIENT))
	case []byte:
		ptr := C.CBytes(v)
		defer C.free(ptr)
		rc = C.sqlite3_bind_blob(stmt, C.int(index), ptr, C.int(len(v)), (*[0]byte)(C.SQLITE_TRANSIENT))
	default:
		return fmt.Errorf("unsupported sqlite argument type %T", value)
	}
	if rc != 0 {
		return fmt.Errorf("bind argument %d failed: rc=%d", index, rc)
	}
	return nil
}

func columnValue(stmt *C.sqlite3_stmt, index int) any {
	switch C.sqlite3_column_type(stmt, C.int(index)) {
	case C.int(1):
		return int64(C.sqlite3_column_int64(stmt, C.int(index)))
	case C.int(2):
		return float64(C.sqlite3_column_double(stmt, C.int(index)))
	case C.int(3):
		length := C.sqlite3_column_bytes(stmt, C.int(index))
		return C.GoStringN((*C.char)(unsafe.Pointer(C.sqlite3_column_text(stmt, C.int(index)))), length)
	case C.int(4):
		length := C.sqlite3_column_bytes(stmt, C.int(index))
		if length == 0 {
			return []byte{}
		}
		ptr := C.sqlite3_column_blob(stmt, C.int(index))
		return C.GoBytes(ptr, length)
	default:
		return nil
	}
}

func exec(handle *C.sqlite3, statement string) error {
	cStatement := C.CString(statement)
	defer C.free(unsafe.Pointer(cStatement))
	var message *C.char
	rc := C.sqlite3_exec(handle, cStatement, nil, nil, &message)
	if rc == 0 {
		return nil
	}
	if message != nil {
		defer C.sqlite3_free(unsafe.Pointer(message))
		return fmt.Errorf("%s (rc=%d)", C.GoString(message), rc)
	}
	return fmt.Errorf("sqlite error (rc=%d)", rc)
}

func openError(handle *C.sqlite3, rc C.int) error {
	if handle == nil {
		return fmt.Errorf("sqlite3_open failed: rc=%d", rc)
	}
	defer C.sqlite3_close(handle)
	return sqliteError(handle, "open", rc)
}

func sqliteError(handle *C.sqlite3, operation string, rc C.int) error {
	message := "unknown sqlite error"
	if handle != nil {
		message = C.GoString(C.sqlite3_errmsg(handle))
	}
	return fmt.Errorf("sqlite3 %s: %s (rc=%d)", operation, message, rc)
}
