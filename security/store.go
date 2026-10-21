package security

import (
	"crypto/sha256"

	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"golang.org/x/crypto/bcrypt"
)

var ErrCredentials = errors.New("密码或动态验证码错误")

type Store struct {
	DB  *sql.DB
	Key []byte
}
type State struct {
	LoginHash          string
	SubscriptionHash   string
	SubscriptionCipher string
	LegacyAllowed      bool
	TOTPCipher         string
	PendingCipher      string
	PendingUntil       int64
	LastCounter        int64
	Recovery           string
}

const schema = `CREATE TABLE IF NOT EXISTS account_security (
 account_id BIGINT UNSIGNED NOT NULL PRIMARY KEY,
 login_hash VARCHAR(255) NOT NULL DEFAULT '',
 subscription_hash VARCHAR(64) NOT NULL DEFAULT '',
 subscription_cipher TEXT NOT NULL,
 legacy_allowed TINYINT NOT NULL DEFAULT 1,
 totp_cipher TEXT NOT NULL,
 pending_cipher TEXT NOT NULL,
 pending_until BIGINT NOT NULL DEFAULT 0,
 last_counter BIGINT NOT NULL DEFAULT -1,
 recovery_hashes TEXT NOT NULL,
 UNIQUE KEY subscription_hash_unique(subscription_hash, account_id),
 CONSTRAINT security_account_fk FOREIGN KEY (account_id) REFERENCES account(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4`

func (s *Store) Init() error {
	if _, err := s.DB.Exec(schema); err != nil {
		return err
	}
	_, err := s.DB.Exec(`INSERT IGNORE INTO account_security (account_id,subscription_cipher,totp_cipher,pending_cipher,recovery_hashes) SELECT id,'','','','[]' FROM account`)
	return err
}

func (s *Store) Ensure(id uint) error {
	_, err := s.DB.Exec(`INSERT IGNORE INTO account_security (account_id,subscription_cipher,totp_cipher,pending_cipher,recovery_hashes) VALUES (?,'','','','[]')`, id)
	return err
}

func scanState(row interface{ Scan(...interface{}) error }) (State, error) {
	var r State
	err := row.Scan(&r.LoginHash, &r.SubscriptionHash, &r.SubscriptionCipher, &r.LegacyAllowed, &r.TOTPCipher, &r.PendingCipher, &r.PendingUntil, &r.LastCounter, &r.Recovery)
	return r, err
}

const stateFields = "login_hash,subscription_hash,subscription_cipher,legacy_allowed,totp_cipher,pending_cipher,pending_until,last_counter,recovery_hashes"

func (s *Store) Read(id uint) (State, error) {
	if err := s.Ensure(id); err != nil {
		return State{}, err
	}
	return scanState(s.DB.QueryRow("SELECT "+stateFields+" FROM account_security WHERE account_id=?", id))
}

func (s *Store) CheckPassword(id uint, username, legacy, plain string) error {
	r, err := s.Read(id)
	if err != nil {
		return err
	}
	if r.LoginHash != "" {
		if bcrypt.CompareHashAndPassword([]byte(r.LoginHash), []byte(plain)) != nil {
			return ErrCredentials
		}
		return nil
	}
	if !LegacyPasswordMatch(legacy, username, plain) {
		return ErrCredentials
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(plain), bcrypt.DefaultCost)
	if err != nil {
		return err
	}
	result, err := s.DB.Exec("UPDATE account_security SET login_hash=? WHERE account_id=? AND login_hash=''", string(hash), id)
	if err != nil {
		return err
	}
	count, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if count == 0 {
		r, err := s.Read(id)
		if err != nil {
			return err
		}
		if bcrypt.CompareHashAndPassword([]byte(r.LoginHash), []byte(plain)) != nil {
			return ErrCredentials
		}
	}
	return nil
}

func (s *Store) SetPassword(id uint, plain string) error {
	if len(plain) < 16 || len(plain) > 72 {
		return errors.New("新密码须为16至72字节")
	}
	if err := s.Ensure(id); err != nil {
		return err
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(plain), bcrypt.DefaultCost)
	if err != nil {
		return err
	}
	_, err = s.DB.Exec("UPDATE account_security SET login_hash=? WHERE account_id=?", string(hash), id)
	return err
}

func (s *Store) NewAccount(id uint, plain string) error {
	// New login passwords are independent of node credentials.
	if err := s.Ensure(id); err != nil {
		return err
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(plain), bcrypt.DefaultCost)
	if err != nil {
		return err
	}
	_, err = s.DB.Exec("UPDATE account_security SET login_hash=?,legacy_allowed=0 WHERE account_id=?", string(hash), id)
	return err
}

func (s *Store) JWTKey() []byte {
	sum := sha256.Sum256(append([]byte("xwarp-jwt-v1:"), s.Key...))
	return sum[:]
}
func purpose(id uint, label string) string { return fmt.Sprintf("%d:%s", id, label) }

// Subscription rotation and legacy-link revocation are one transaction.
func (s *Store) Subscription(id uint, rotate bool) (string, error) {
	if err := s.Ensure(id); err != nil {
		return "", err
	}
	tx, err := s.DB.Begin()
	if err != nil {
		return "", err
	}
	defer tx.Rollback()
	r, err := scanState(tx.QueryRow("SELECT "+stateFields+" FROM account_security WHERE account_id=? FOR UPDATE", id))
	if err != nil {
		return "", err
	}
	if !rotate && r.SubscriptionCipher != "" {
		token, err := Decrypt(s.Key, r.SubscriptionCipher, purpose(id, "subscription"))
		if err != nil {
			return "", err
		}
		return token, tx.Commit()
	}
	token, err := RandomPassword(48)
	if err != nil {
		return "", err
	}
	encoded, err := Encrypt(s.Key, token, purpose(id, "subscription"))
	if err != nil {
		return "", err
	}
	_, err = tx.Exec("UPDATE account_security SET subscription_hash=?,subscription_cipher=?,legacy_allowed=IF(?,0,legacy_allowed) WHERE account_id=?", Digest(token), encoded, rotate, id)
	if err != nil {
		return "", err
	}
	return token, tx.Commit()
}

func (s *Store) ResolveSubscription(token string) (uint, string, error) {
	var id uint
	var nodePassword string
	err := s.DB.QueryRow(`SELECT a.id,a.pass FROM account a JOIN account_security s ON a.id=s.account_id WHERE s.subscription_hash=? AND a.deleted=0`, Digest(token)).Scan(&id, &nodePassword)
	return id, nodePassword, err
}

func (s *Store) LegacySubscriptionAllowed(nodePassword string) bool {
	var allowed bool
	return s.DB.QueryRow(`SELECT s.legacy_allowed FROM account_security s JOIN account a ON a.id=s.account_id WHERE a.pass=? AND a.deleted=0`, nodePassword).Scan(&allowed) == nil && allowed
}

func (s *Store) BeginTOTP(id uint, username string) (string, string, error) {
	r, err := s.Read(id)
	if err != nil {
		return "", "", err
	}
	if r.TOTPCipher != "" {
		return "", "", errors.New("两步验证已开启；先验证并关闭后才能重新绑定")
	}
	secret, uri, err := NewTOTP(username)
	if err != nil {
		return "", "", err
	}
	encoded, err := Encrypt(s.Key, secret, purpose(id, "totp"))
	if err != nil {
		return "", "", err
	}
	_, err = s.DB.Exec("UPDATE account_security SET pending_cipher=?,pending_until=? WHERE account_id=? AND totp_cipher=''", encoded, time.Now().Add(5*time.Minute).Unix(), id)
	return secret, uri, err
}

func (s *Store) ConfirmTOTP(id uint, code string) ([]string, error) {
	tx, err := s.DB.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	r, err := scanState(tx.QueryRow("SELECT "+stateFields+" FROM account_security WHERE account_id=? FOR UPDATE", id))
	if err != nil {
		return nil, err
	}
	if r.PendingCipher == "" || r.PendingUntil < time.Now().Unix() || r.TOTPCipher != "" {
		return nil, ErrCredentials
	}
	secret, err := Decrypt(s.Key, r.PendingCipher, purpose(id, "totp"))
	if err != nil {
		return nil, err
	}
	counter, valid := MatchTOTP(secret, code, time.Now(), -1)
	if !valid {
		return nil, ErrCredentials
	}
	codes := make([]string, 8)
	hashes := make([]string, 8)
	for i := range codes {
		codes[i], err = RandomPassword(16)
		if err != nil {
			return nil, err
		}
		hashes[i] = Digest(codes[i])
	}
	data, _ := json.Marshal(hashes)
	_, err = tx.Exec("UPDATE account_security SET totp_cipher=pending_cipher,pending_cipher='',pending_until=0,last_counter=?,recovery_hashes=? WHERE account_id=?", counter, string(data), id)
	if err != nil {
		return nil, err
	}
	return codes, tx.Commit()
}

// MFA consumption is serialized so a code cannot be replayed by concurrent logins.
func (s *Store) CheckMFA(id uint, code string) error {
	tx, err := s.DB.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	r, err := scanState(tx.QueryRow("SELECT "+stateFields+" FROM account_security WHERE account_id=? FOR UPDATE", id))
	if err != nil {
		return err
	}
	if r.TOTPCipher == "" {
		return tx.Commit()
	}
	secret, err := Decrypt(s.Key, r.TOTPCipher, purpose(id, "totp"))
	if err != nil {
		return err
	}
	counter, valid := MatchTOTP(secret, code, time.Now(), r.LastCounter)
	if valid {
		_, err = tx.Exec("UPDATE account_security SET last_counter=? WHERE account_id=?", counter, id)
	} else {
		var hashes []string
		if json.Unmarshal([]byte(r.Recovery), &hashes) != nil {
			return ErrCredentials
		}
		index := -1
		for i, h := range hashes {
			if h == Digest(code) {
				index = i
			}
		}
		if index < 0 {
			return ErrCredentials
		}
		hashes = append(hashes[:index], hashes[index+1:]...)
		data, _ := json.Marshal(hashes)
		_, err = tx.Exec("UPDATE account_security SET recovery_hashes=? WHERE account_id=?", string(data), id)
	}
	if err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) DisableTOTP(id uint) error {
	_, err := s.DB.Exec("UPDATE account_security SET totp_cipher='',pending_cipher='',pending_until=0,last_counter=-1,recovery_hashes='[]' WHERE account_id=?", id)
	return err
}

// RotateNodeCredentials changes future database authentications independently of login and subscription tokens.
// Existing core sessions/caches still require a coordinated node restart.
func (s *Store) RotateNodeCredentials(id uint) (string, error) {
	plain, err := RandomPassword(48)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum224([]byte(plain))
	tx, err := s.DB.Begin()
	if err != nil {
		return "", err
	}
	defer tx.Rollback()
	var old string
	if err = tx.QueryRow("SELECT pass FROM account WHERE id=? AND deleted=0 FOR UPDATE", id).Scan(&old); err != nil {
		return "", err
	}
	if _, err = tx.Exec("UPDATE account SET pass=?,hash=? WHERE id=?", plain, hex.EncodeToString(digest[:]), id); err != nil {
		return "", err
	}
	if _, err = tx.Exec("UPDATE account_security SET legacy_allowed=0 WHERE account_id=?", id); err != nil {
		return "", err
	}
	return old, tx.Commit()
}
