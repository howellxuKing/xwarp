package security

import (
	"encoding/base32"
	"strings"
	"testing"
	"time"
)

func TestCipherAuthenticatesPurposeAndTampering(t *testing.T) {
	key := make([]byte, 32)
	value, err := Encrypt(key, "secret", "account-1")
	if err != nil {
		t.Fatal(err)
	}
	plain, err := Decrypt(key, value, "account-1")
	if err != nil || plain != "secret" {
		t.Fatal("round trip failed")
	}
	if _, err := Decrypt(key, value, "account-2"); err == nil {
		t.Fatal("cross-account substitution accepted")
	}
	if _, err := Decrypt(key, value[:len(value)/2], "account-1"); err == nil {
		t.Fatal("truncated ciphertext accepted")
	}
	wrong := make([]byte, 32)
	wrong[0] = 1
	if _, err := Decrypt(wrong, value, "account-1"); err == nil {
		t.Fatal("wrong key accepted")
	}
}

func TestTOTPStandardVectorAndReplay(t *testing.T) {
	secret := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString([]byte("12345678901234567890"))
	code, err := TOTPCode(secret, 1)
	if err != nil || code != "287082" {
		t.Fatalf("RFC6238 vector mismatch: %s", code)
	}
	counter, ok := MatchTOTP(secret, code, time.Unix(59, 0), -1)
	if !ok || counter != 1 {
		t.Fatal("valid code rejected")
	}
	if _, ok := MatchTOTP(secret, code, time.Unix(59, 0), counter); ok {
		t.Fatal("replayed code accepted")
	}
	if _, ok := MatchTOTP(secret, "not-code", time.Unix(59, 0), -1); ok {
		t.Fatal("malformed code accepted")
	}
}

func TestLimiterExpiryAndIndependentClients(t *testing.T) {
	l := NewLimiter()
	now := time.Unix(100, 0)
	if !l.Allow("first", 2, time.Minute, now) || !l.Allow("first", 2, time.Minute, now) {
		t.Fatal("initial requests rejected")
	}
	if l.Allow("first", 2, time.Minute, now.Add(59*time.Second)) {
		t.Fatal("limit bypassed")
	}
	if !l.Allow("second", 2, time.Minute, now) {
		t.Fatal("another client blocked")
	}
	if !l.Allow("first", 2, time.Minute, now.Add(time.Minute)) {
		t.Fatal("rejected requests extended expiry")
	}
}

func TestRealityRejectsMalformedShortID(t *testing.T) {
	key := "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	valid := `{"network":"tcp","security":"reality","realitySettings":{"dest":"swdist.apple.com:443","privateKey":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","serverNames":["swdist.apple.com"],"shortIds":["780909adfe4e0b36"]}}`
	if err := ValidateXray("vless", "xtls-rprx-vision", key, valid); err != nil {
		t.Fatal(err)
	}
	for _, encoded := range []string{strings.Replace(valid, "780909adfe4e0b36", "780909adfe4e0b36&#x20;", 1), strings.Replace(valid, "780909adfe4e0b36", "abc", 1), strings.Replace(valid, "swdist.apple.com:443", "https://swdist.apple.com", 1)} {
		if err := ValidateXray("vless", "xtls-rprx-vision", key, encoded); err == nil {
			t.Fatal("malformed REALITY accepted")
		}
	}
	if ValidPanelPath("/panel/../") || ValidPanelPath("//evil.example/") {
		t.Fatal("unsafe panel path accepted")
	}
}
