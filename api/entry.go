package api

import (
	"crypto/subtle"
	"encoding/json"
	"github.com/gin-gonic/gin"
	"net/http"
	"os"
	"strings"
	"time"
	"trojan-panel/dao"
	"trojan-panel/security"
)

type entryTicket struct {
	Expires int64  `json:"expires"`
	KeyHash string `json:"keyHash"`
}

func entryKey() (string, error) {
	path := os.Getenv("XWARP_ENTRY_KEY_FILE")
	if path == "" {
		path = "config/entry.key"
	}
	data, err := os.ReadFile(path)
	return strings.TrimSpace(string(data)), err
}

func EntryOpen(c *gin.Context) {
	key, err := entryKey()
	given := c.Query("key")
	if given == "" {
		given = c.PostForm("key")
	}
	if err != nil || len(key) < 32 || subtle.ConstantTimeCompare([]byte(security.Digest(given)), []byte(security.Digest(key))) != 1 {
		c.AbortWithStatus(404)
		return
	}
	base := security.RuntimeGateway().PanelPath
	if base == "" {
		base = "/"
	}
	if !security.ValidPanelPath(base) {
		c.AbortWithStatus(500)
		return
	}
	data, _ := json.Marshal(entryTicket{Expires: time.Now().Add(12 * time.Hour).Unix(), KeyHash: security.Digest(key)})
	ticket, err := security.Encrypt(dao.Security.Key, string(data), "panel-entry")
	if err != nil {
		c.AbortWithStatus(500)
		return
	}
	http.SetCookie(c.Writer, &http.Cookie{Name: "xwarp_entry", Value: ticket, Path: base, MaxAge: 43200, Secure: true, HttpOnly: true, SameSite: http.SameSiteStrictMode})
	c.Header("Cache-Control", "no-store")
	c.Header("Referrer-Policy", "no-referrer")
	c.Redirect(303, base)
}

// Used exclusively by the private gateway's internal auth_request location.
func EntryVerify(c *gin.Context) {
	key, err := entryKey()
	// This endpoint is called only by an enabled gateway gate. A missing key must fail closed.
	if err != nil || len(key) < 32 {
		c.AbortWithStatus(403)
		return
	}
	encoded, err := c.Cookie("xwarp_entry")
	if err != nil {
		c.AbortWithStatus(403)
		return
	}
	plain, err := security.Decrypt(dao.Security.Key, encoded, "panel-entry")
	var ticket entryTicket
	if err != nil || json.Unmarshal([]byte(plain), &ticket) != nil || ticket.Expires <= time.Now().Unix() || ticket.KeyHash != security.Digest(key) {
		c.AbortWithStatus(403)
		return
	}
	c.Status(204)
}
