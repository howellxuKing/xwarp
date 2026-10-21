package security

import (
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestBootstrapPasswordMatchesExistingLoginAndNodeFormat(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix file permissions checked in Linux CI")
	}
	path := filepath.Join(t.TempDir(), "initial-admin-password.txt")
	seed := legacyAdminSeed + ",remaining columns);"
	result, err := PrepareAdminSeed(seed, path)
	if err != nil {
		t.Fatal(err)
	}
	password, _ := os.ReadFile(path)
	fields := strings.Split(result, "'")
	stored, err := base64.URLEncoding.DecodeString(fields[3])
	if err != nil || len(stored) != 36 {
		t.Fatal("invalid legacy login encoding")
	}
	h := sha1.New()
	h.Write(stored[:16])
	h.Write([]byte("sysadmin" + strings.TrimSpace(string(password))))
	if hex.EncodeToString(h.Sum(nil)) != hex.EncodeToString(stored[16:]) {
		t.Fatal("generated password cannot authenticate")
	}
	nodeHash := sha256.Sum224([]byte(fields[3]))
	if fields[5] != hex.EncodeToString(nodeHash[:]) {
		t.Fatal("node hash mismatch")
	}
	if !strings.HasSuffix(result, ",remaining columns);") {
		t.Fatal("unrelated seed data changed")
	}
	if _, err := PrepareAdminSeed(seed, path); err != nil {
		t.Fatal(err)
	}
	again, _ := os.ReadFile(path)
	if string(again) != string(password) {
		t.Fatal("bootstrap retry changed password")
	}
	info, _ := os.Stat(path)
	if info.Mode().Perm() != 0600 {
		t.Fatal("bootstrap password is not private")
	}
}

func TestBootstrapRefusesUnknownSeedAndUnsafeFile(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix file permissions checked in Linux CI")
	}
	path := filepath.Join(t.TempDir(), "password")
	if _, err := PrepareAdminSeed("unrecognized seed", path); err == nil {
		t.Fatal("unknown seed accepted")
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("password created for unknown seed")
	}
	if err := os.WriteFile(path, []byte("abcdefghijklmnop\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := PrepareAdminSeed(legacyAdminSeed, path); err == nil {
		t.Fatal("public password file accepted")
	}
}

func TestPasswordLengthBounds(t *testing.T) {
	for _, length := range []int{-1, 0, 15, 129} {
		if _, err := RandomPassword(length); err == nil {
			t.Fatal("invalid length accepted")
		}
	}
}
