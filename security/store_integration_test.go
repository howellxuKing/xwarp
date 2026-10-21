package security

import (
	"crypto/sha1"
	"database/sql"
	"encoding/base64"
	_ "github.com/go-sql-driver/mysql"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestStoreIntegration(t *testing.T) {
	dsn := os.Getenv("XWARP_TEST_MYSQL_DSN")
	if dsn == "" {
		t.Skip("isolated MySQL integration environment not provided")
	}
	if !strings.Contains(dsn, "/xwarp_security_test") {
		t.Fatal("refusing to run against a non-test database")
	}
	db, err := sql.Open("mysql", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	for i := 0; i < 30; i++ {
		if err = db.Ping(); err == nil {
			break
		}
		time.Sleep(time.Second)
	}
	if err != nil {
		t.Fatal(err)
	}
	for _, stmt := range []string{"DROP TABLE IF EXISTS account_security", "DROP TABLE IF EXISTS account", `CREATE TABLE account(id BIGINT UNSIGNED PRIMARY KEY AUTO_INCREMENT,username VARCHAR(20),pass VARCHAR(64),hash VARCHAR(56),deleted TINYINT DEFAULT 0) ENGINE=InnoDB`} {
		if _, err = db.Exec(stmt); err != nil {
			t.Fatal(err)
		}
	}
	salt := make([]byte, 16)
	h := sha1.New()
	h.Write(salt)
	h.Write([]byte("sysadminold-password"))
	legacy := base64.URLEncoding.EncodeToString(h.Sum(salt))
	if _, err = db.Exec("INSERT INTO account(username,pass) VALUES ('sysadmin',?),('other','node-credential-2')", legacy); err != nil {
		t.Fatal(err)
	}
	s := &Store{DB: db, Key: make([]byte, 32)}
	if err = s.Init(); err != nil {
		t.Fatal(err)
	}
	if err = s.CheckPassword(1, "sysadmin", legacy, "old-password"); err != nil {
		t.Fatal("legacy migration failed", err)
	}
	if err = s.CheckPassword(1, "sysadmin", legacy, "wrong"); err == nil {
		t.Fatal("wrong password accepted")
	}
	if err = s.SetPassword(1, "new-long-password"); err != nil {
		t.Fatal(err)
	}
	if err = s.CheckPassword(1, "sysadmin", legacy, "old-password"); err == nil {
		t.Fatal("old login password retained")
	}
	if err = s.CheckPassword(1, "sysadmin", legacy, "new-long-password"); err != nil {
		t.Fatal(err)
	}
	var node string
	db.QueryRow("SELECT pass FROM account WHERE id=1").Scan(&node)
	if node != legacy {
		t.Fatal("login change modified node credential")
	}
	token, err := s.Subscription(1, false)
	if err != nil {
		t.Fatal(err)
	}
	id, node, err := s.ResolveSubscription(token)
	if err != nil || id != 1 || node != legacy {
		t.Fatal("new subscription invalid")
	}
	if !s.LegacySubscriptionAllowed(legacy) {
		t.Fatal("legacy compatibility lost before rotation")
	}
	again, _ := s.Subscription(1, false)
	if again != token {
		t.Fatal("reading subscription rotated it")
	}
	rotated, err := s.Subscription(1, true)
	if err != nil || rotated == token {
		t.Fatal("rotation failed")
	}
	if _, _, err = s.ResolveSubscription(token); err == nil {
		t.Fatal("revoked link still accepted")
	}
	if s.LegacySubscriptionAllowed(legacy) {
		t.Fatal("legacy link bypasses rotation")
	}
	if _, _, err = s.ResolveSubscription(rotated); err != nil {
		t.Fatal("rotated token invalid")
	}
	other, _ := s.Subscription(2, false)
	if other == rotated {
		t.Fatal("shared subscription token")
	}
	oldNode, err := s.RotateNodeCredentials(1)
	if err != nil || oldNode != legacy {
		t.Fatal("node rotation failed", err)
	}
	_, newNode, err := s.ResolveSubscription(rotated)
	if err != nil || newNode == oldNode || len(newNode) != 48 {
		t.Fatal("subscription did not receive new node credentials")
	}
	if err = s.CheckPassword(1, "sysadmin", newNode, "new-long-password"); err != nil {
		t.Fatal("node rotation changed login password", err)
	}
	var hash string
	if err = db.QueryRow("SELECT hash FROM account WHERE id=1").Scan(&hash); err != nil || len(hash) != 56 {
		t.Fatal("core SHA224 hash missing")
	}
	secret, _, err := s.BeginTOTP(1, "sysadmin")
	if err != nil {
		t.Fatal(err)
	}
	code, _ := TOTPCode(secret, time.Now().Unix()/30)
	codes, err := s.ConfirmTOTP(1, code)
	if err != nil || len(codes) != 8 {
		t.Fatal("MFA enrollment failed", err)
	}
	if err = s.CheckMFA(1, ""); err == nil {
		t.Fatal("MFA bypassed")
	}
	var successes int32
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if s.CheckMFA(1, codes[0]) == nil {
				atomic.AddInt32(&successes, 1)
			}
		}()
	}
	wg.Wait()
	if successes != 1 {
		t.Fatalf("recovery code consumed %d times", successes)
	}
	if err = s.CheckMFA(1, codes[1]); err != nil {
		t.Fatal("independent recovery code rejected")
	}
	r, err := s.Read(1)
	if err != nil || strings.Contains(r.TOTPCipher, secret) || strings.Contains(r.Recovery, codes[1]) {
		t.Fatal("secrets stored in plaintext")
	}
	if err = s.DisableTOTP(1); err != nil {
		t.Fatal(err)
	}
	if err = s.CheckMFA(1, ""); err != nil {
		t.Fatal("disabled MFA still required")
	}
	if _, err = db.Exec("UPDATE account SET deleted=1 WHERE id=1"); err != nil {
		t.Fatal(err)
	}
	if _, _, err = s.ResolveSubscription(rotated); err == nil {
		t.Fatal("disabled account subscribed")
	}
	if _, err = db.Exec("DELETE FROM account WHERE id=2"); err != nil {
		t.Fatal(err)
	}
	if _, _, err = s.ResolveSubscription(other); err == nil {
		t.Fatal("deleted account subscribed")
	}
}
