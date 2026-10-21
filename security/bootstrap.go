package security

import (
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"math/big"
	"os"
	"strings"
)

const passwordAlphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
const legacyAdminSeed = "INSERT INTO `account` VALUES (1,'sysadmin','tFjD2X1F6i9FfWp2GDU5Vbi1conuaChDKIYbw9zMFrqvMoSz','4366294571b8b267d9cf15b56660f0a70659568a86fc270a52fdc9e5'"

// RandomPassword uses the operating system's cryptographic random source.
func RandomPassword(length int) (string, error) {
	if length < 16 || length > 128 {
		return "", fmt.Errorf("password length must be between 16 and 128")
	}
	result := make([]byte, length)
	for i := range result {
		index, err := rand.Int(rand.Reader, big.NewInt(int64(len(passwordAlphabet))))
		if err != nil {
			return "", err
		}
		result[i] = passwordAlphabet[index.Int64()]
	}
	return string(result), nil
}

// PrepareAdminSeed replaces the legacy seed only for an empty database.
// The password is kept in a private file, never printed to container logs.
func PrepareAdminSeed(seed, passwordFile string) (string, error) {
	if strings.Count(seed, legacyAdminSeed) != 1 {
		return "", fmt.Errorf("administrator seed not recognized; refusing default credentials")
	}
	password, err := loadOrCreatePassword(passwordFile)
	if err != nil {
		return "", err
	}
	// Preserve the existing login and node credential format until these are separated.
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	hasher := sha1.New()
	hasher.Write(salt)
	hasher.Write([]byte("sysadmin" + password))
	stored := base64.URLEncoding.EncodeToString(hasher.Sum(salt))
	nodeHash := sha256.Sum224([]byte(stored))
	replacement := fmt.Sprintf("INSERT INTO `account` VALUES (1,'sysadmin','%s','%s'", stored, hex.EncodeToString(nodeHash[:]))
	return strings.Replace(seed, legacyAdminSeed, replacement, 1), nil
}

func loadOrCreatePassword(path string) (string, error) {
	info, err := os.Lstat(path)
	if err == nil {
		if !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 {
			return "", fmt.Errorf("bootstrap password file must be a private regular file")
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return "", err
		}
		password := strings.TrimSuffix(string(data), "\n")
		if len(password) != 16 || strings.IndexFunc(password, func(r rune) bool {
			return !strings.ContainsRune(passwordAlphabet, r)
		}) >= 0 {
			return "", fmt.Errorf("invalid bootstrap password file")
		}
		return password, nil
	}
	if !os.IsNotExist(err) {
		return "", err
	}
	password, err := RandomPassword(16)
	if err != nil {
		return "", err
	}
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return "", err
	}
	_, writeErr := file.WriteString(password + "\n")
	syncErr := file.Sync()
	closeErr := file.Close()
	if writeErr != nil || syncErr != nil || closeErr != nil {
		os.Remove(path)
		return "", fmt.Errorf("could not save bootstrap password")
	}
	return password, nil
}
