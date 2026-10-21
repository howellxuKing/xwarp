package security

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base32"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
	"os"
	"strings"
	"time"
)

func LoadKey(path string) ([]byte, error) {
	if info, err := os.Lstat(path); err == nil {
		if !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 {
			return nil, errors.New("security key must be a private regular file")
		}
		key, err := os.ReadFile(path)
		if err != nil || len(key) != 32 {
			return nil, errors.New("invalid security key")
		}
		return key, nil
	} else if !os.IsNotExist(err) {
		return nil, err
	}
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return nil, err
	}
	_, err = f.Write(key)
	if err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err != nil || closeErr != nil {
		os.Remove(path)
		return nil, errors.New("could not persist security key")
	}
	return key, nil
}

func Encrypt(key []byte, plain, purpose string) (string, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(gcm.Seal(nonce, nonce, []byte(plain), []byte(purpose))), nil
}

func Decrypt(key []byte, encoded, purpose string) (string, error) {
	data, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		return "", err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	if len(data) < gcm.NonceSize() {
		return "", errors.New("invalid encrypted value")
	}
	plain, err := gcm.Open(nil, data[:gcm.NonceSize()], data[gcm.NonceSize():], []byte(purpose))
	return string(plain), err
}

func Digest(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])
}

func LegacyPasswordMatch(stored, username, plain string) bool {
	data, err := base64.URLEncoding.DecodeString(stored)
	if err != nil || len(data) != 36 {
		return false
	}
	h := sha1.New()
	h.Write(data[:16])
	h.Write([]byte(username + plain))
	return subtle.ConstantTimeCompare(h.Sum(nil), data[16:]) == 1
}

func NewTOTP(username string) (string, string, error) {
	data := make([]byte, 20)
	if _, err := rand.Read(data); err != nil {
		return "", "", err
	}
	secret := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(data)
	uri := "otpauth://totp/" + url.PathEscape("XWarp:"+username) + "?" + url.Values{"secret": {secret}, "issuer": {"XWarp"}, "algorithm": {"SHA1"}, "digits": {"6"}, "period": {"30"}}.Encode()
	return secret, uri, nil
}

func TOTPCode(secret string, counter int64) (string, error) {
	key, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(secret)
	if err != nil {
		return "", err
	}
	buf := make([]byte, 8)
	binary.BigEndian.PutUint64(buf, uint64(counter))
	h := hmac.New(sha1.New, key)
	h.Write(buf)
	sum := h.Sum(nil)
	offset := sum[len(sum)-1] & 15
	number := (binary.BigEndian.Uint32(sum[offset:offset+4]) & 0x7fffffff) % 1000000
	return fmt.Sprintf("%06d", number), nil
}

// MatchTOTP allows one step of clock skew. A stored counter prevents reuse.
func MatchTOTP(secret, code string, now time.Time, last int64) (int64, bool) {
	if len(code) != 6 || strings.IndexFunc(code, func(r rune) bool { return r < '0' || r > '9' }) >= 0 {
		return 0, false
	}
	for _, delta := range []int64{0, -1, 1} {
		counter := now.Unix()/30 + delta
		if counter <= last {
			continue
		}
		expected, err := TOTPCode(secret, counter)
		if err == nil && subtle.ConstantTimeCompare([]byte(expected), []byte(code)) == 1 {
			return counter, true
		}
	}
	return 0, false
}
