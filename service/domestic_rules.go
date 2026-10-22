package service

import (
	"context"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
	"trojan-panel/domesticrules"
	"trojan-panel/model/constant"
)

var domesticOnce sync.Once
var domesticStore *domesticrules.Store

func getDomesticStore() *domesticrules.Store {
	domesticOnce.Do(func() {
		domesticStore = domesticrules.Open(filepath.Join(constant.ConfigPath, "domestic-rules.json"))
	})
	return domesticStore
}

// DefaultClashRules is local-only, including when upstream is unavailable.
func DefaultClashRules() string {
	return getDomesticStore().Apply(constant.ClashRules)
}

func CronRefreshDomesticRules() {
	if os.Getenv("XWARP_DISABLE_RULE_UPDATES") == "1" {
		return
	}
	store := getDomesticStore()
	if store.Fresh(time.Now()) {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	client := &http.Client{
		Timeout:       15 * time.Second,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse },
	}
	if err := store.Refresh(ctx, client, domesticrules.SourceURL); err != nil {
		logrus.Warnf("Domestic rule update failed; keeping last good snapshot: %v", err)
		return
	}
	logrus.Infof("Domestic routing snapshot active: %s", store.Version())
}
