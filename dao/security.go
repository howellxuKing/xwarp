package dao

import (
	"errors"
	"os"
	"path/filepath"
	"trojan-panel/model/constant"
	"trojan-panel/security"
)

var Security *security.Store

func InitSecurity() error {
	Security = &security.Store{DB: db}
	if err := Security.Init(); err != nil {
		return err
	}
	keyPath := filepath.Join(constant.ConfigPath, "security.key")
	var encrypted int
	if err := db.QueryRow("SELECT COUNT(*) FROM account_security WHERE subscription_cipher<>'' OR totp_cipher<>'' OR pending_cipher<>''").Scan(&encrypted); err != nil {
		return err
	}
	if _, err := os.Stat(keyPath); os.IsNotExist(err) && encrypted > 0 {
		return errors.New("security.key missing: restore the original configuration backup before starting")
	}
	key, err := security.LoadKey(keyPath)
	if err != nil {
		return err
	}
	Security.Key = key
	return nil
}

func SecurityAccount(id uint) (string, string, error) {
	var username, nodePassword string
	err := db.QueryRow("SELECT username,pass FROM account WHERE id=? AND deleted=0", id).Scan(&username, &nodePassword)
	return username, nodePassword, err
}

func RenameAccount(id uint, username, email *string) error {
	_, err := db.Exec("UPDATE account SET username=COALESCE(NULLIF(?,''),username),email=COALESCE(?,email) WHERE id=?", username, email, id)
	return err
}

func ResetAdministrator(plain string) (string, error) {
	var id uint
	var username string
	if err := db.QueryRow("SELECT id,username FROM account WHERE role_id=1 AND deleted=0 ORDER BY id LIMIT 1").Scan(&id, &username); err != nil {
		return "", err
	}
	if err := Security.SetPassword(id, plain); err != nil {
		return "", err
	}
	return username, Security.DisableTOTP(id)
}
