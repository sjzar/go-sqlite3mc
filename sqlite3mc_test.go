package sqlite3mc

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

const testKey = "0123456789abcdef0123456789abcdef"

func TestOpenReadWriteRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "fixture.db")
	db, err := OpenReadWrite(path, testKey)
	if err != nil {
		t.Fatal(err)
	}
	if err := db.Exec("CREATE TABLE MESSAGE (LID INTEGER PRIMARY KEY, content TEXT)"); err != nil {
		t.Fatal(err)
	}
	if err := db.Exec("INSERT INTO MESSAGE(LID,content) VALUES(?,?)", int64(1), "hello"); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}

	readDB, err := Open(path, testKey)
	if err != nil {
		t.Fatal(err)
	}
	defer readDB.Close()
	if err := readDB.Exec("INSERT INTO MESSAGE(LID,content) VALUES(?,?)", int64(2), "read-only"); err == nil {
		t.Fatal("Open returned a writable database")
	}
	rows, err := readDB.Query(context.Background(), "SELECT LID,content FROM MESSAGE")
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 || rows[0]["LID"] != int64(1) || rows[0]["content"] != "hello" {
		t.Fatalf("unexpected rows: %#v", rows)
	}
}

func TestInvalidKey(t *testing.T) {
	if _, err := OpenReadWrite(filepath.Join(t.TempDir(), "fixture.db"), "not-a-key"); err == nil {
		t.Fatal("OpenReadWrite accepted an invalid key")
	}
}

func TestClosedDB(t *testing.T) {
	db, err := OpenReadWrite(filepath.Join(t.TempDir(), "fixture.db"), testKey)
	if err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	if err := db.Exec("SELECT 1"); err == nil {
		t.Fatal("Exec on a closed database succeeded")
	}
	if _, err := db.Query(context.Background(), "SELECT 1"); err == nil {
		t.Fatal("Query on a closed database succeeded")
	}
}

func TestOpenLiveEncryptedDatabase(t *testing.T) {
	path := os.Getenv("SQLITE3MC_TEST_DB")
	key := os.Getenv("SQLITE3MC_TEST_KEY")
	if path == "" || key == "" {
		t.Skip("set SQLITE3MC_TEST_DB and SQLITE3MC_TEST_KEY for a live encrypted database check")
	}
	db, err := Open(path, key)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	rows, err := db.Query(context.Background(), "SELECT count(*) AS count FROM sqlite_master")
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 {
		t.Fatalf("got %d rows, want 1", len(rows))
	}
	if _, ok := rows[0]["count"].(int64); !ok {
		t.Fatalf("count has type %T, want int64", rows[0]["count"])
	}
}
