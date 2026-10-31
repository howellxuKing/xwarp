package domesticrules

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"gopkg.in/yaml.v3"
	"trojan-panel/model/constant"
)

const testTemplate = "rules:\n  - DOMAIN-SUFFIX,openai.com,PROXY\n  - DOMAIN-SUFFIX,google.com,PROXY\n  - DOMAIN-SUFFIX,youtube.com,PROXY\n  # @XWARP-DOMESTIC@\n  - GEOIP,cn,DIRECT,no-resolve\n  - MATCH,PROXY\n"

func mustApply(t *testing.T, store *Store, base string) string {
	t.Helper()
	applied, err := store.Apply(base, false)
	if err != nil {
		t.Fatalf("apply domestic rules: %v", err)
	}
	return applied
}

func TestOfflineDefaultAndUpdateRecovery(t *testing.T) {
	path := filepath.Join(t.TempDir(), "domestic.json")
	store := Open(path)
	base := testTemplate
	before := mustApply(t, store, base)
	if strings.Contains(before, "DOMAIN-SUFFIX,baidu,DIRECT") || strings.Contains(before, "DOMAIN-SUFFIX,com,DIRECT") {
		t.Fatal("an entire top-level domain became direct")
	}
	if !strings.Contains(before, "DOMAIN-SUFFIX,douyin.com,DIRECT") || !strings.HasSuffix(before, "MATCH,PROXY\n") {
		t.Fatal("offline bundled routing unavailable")
	}
	if strings.Index(before, "openai.com,PROXY") > strings.Index(before, "douyin.com,DIRECT") || strings.Index(before, "douyin.com,DIRECT") > strings.Index(before, "GEOIP,cn") {
		t.Fatal("domestic rules bypassed explicit overseas policy or IP fallback")
	}
	var body atomic.Value
	body.Store(bundled + "\n+.new-fixture.example\n")
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte(body.Load().(string))) }))
	defer server.Close()
	if err := store.Refresh(context.Background(), server.Client(), server.URL); err != nil {
		t.Fatal(err)
	}
	after := mustApply(t, store, base)
	if !strings.Contains(after, "DOMAIN-SUFFIX,new-fixture.example,DIRECT") || store.Version() == Open("").Version() {
		t.Fatal("accepted update did not become active")
	}
	if mustApply(t, Open(path), base) != after {
		t.Fatal("restart did not recover persisted snapshot")
	}
	for _, invalid := range []string{"<html>upstream error</html>", "+.com\n", bundled + "\n+.bad.example,PROXY\n", strings.Repeat("x", maxBytes+1)} {
		body.Store(invalid)
		if store.Refresh(context.Background(), server.Client(), server.URL) == nil {
			t.Fatal("invalid upstream update accepted")
		}
		if mustApply(t, store, base) != after || mustApply(t, Open(path), base) != after {
			t.Fatal("failed refresh replaced last good rules")
		}
	}
	if err := os.WriteFile(path, []byte("broken cache"), 0600); err != nil {
		t.Fatal(err)
	}
	if mustApply(t, Open(path), base) != before {
		t.Fatal("corrupt cache prevented bundled fallback")
	}
}

func TestApplyRequiresStandalonePlaceholder(t *testing.T) {
	store := Open(filepath.Join(t.TempDir(), "domestic.json"))
	for _, template := range []string{
		"rules:\n  - MATCH,PROXY\n",
		"rules:\n  - DOMAIN-SUFFIX,openai.com,PROXY # @XWARP-DOMESTIC@\n  - MATCH,PROXY\n",
		"rules:\n  # @XWARP-DOMESTIC@ trailing\n  - MATCH,PROXY\n",
	} {
		if _, err := store.Apply(template, false); err == nil {
			t.Fatalf("template without a standalone placeholder was accepted: %q", template)
		}
	}
}

func TestApplyGeoSite(t *testing.T) {
	store := Open(filepath.Join(t.TempDir(), "domestic.json"))
	applied, err := store.Apply(testTemplate, true)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(applied, "GEOSITE,geolocation-cn,DIRECT") || strings.Contains(applied, "DOMAIN-SUFFIX,douyin.com,DIRECT") {
		t.Fatal("geoSite mode did not replace the expanded block")
	}
	if strings.Index(applied, "GEOSITE,geolocation-cn") > strings.Index(applied, "GEOIP,cn") {
		t.Fatal("geoSite rule must precede the GEOIP fallback")
	}
}

func TestBundledTemplateKeepsRoutingOrder(t *testing.T) {
	store := Open(filepath.Join(t.TempDir(), "domestic.json"))
	for _, geoSite := range []bool{false, true} {
		applied, err := store.Apply(testTemplate, geoSite)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(applied, constant.ClashDomesticMarker) {
			t.Fatal("placeholder was not expanded")
		}
		var document map[string][]string
		if err := yaml.Unmarshal([]byte(applied), &document); err != nil {
			t.Fatalf("expanded template is not valid YAML: %v", err)
		}
		rules := document["rules"]
		if !geoSite && len(rules) < 5000 {
			t.Fatalf("unexpected rule count: %d", len(rules))
		}
		if geoSite && len(rules) > 100 {
			t.Fatalf("geoSite mode should not expand the domain block, got %d rules", len(rules))
		}
		if rules[len(rules)-1] != "MATCH,PROXY" {
			t.Fatalf("MATCH,PROXY must stay last, got %q", rules[len(rules)-1])
		}
		indexOf := func(prefix string) int {
			for index, rule := range rules {
				if strings.HasPrefix(rule, prefix) {
					return index
				}
			}
			return -1
		}
		// 国外代理规则必须在大陆直连之前，这正是 v2.3.x 把 YouTube 判成直连的原因
		overseas := indexOf("DOMAIN-SUFFIX,google.com,PROXY")
		fallback := indexOf("GEOIP,cn,DIRECT")
		if overseas < 0 || fallback < 0 || overseas > fallback {
			t.Fatalf("overseas rules must precede the GEOIP fallback: overseas=%d fallback=%d", overseas, fallback)
		}
		if geoSite {
			geoSiteIndex := indexOf("GEOSITE,geolocation-cn,DIRECT")
			if geoSiteIndex < 0 || geoSiteIndex > fallback {
				t.Fatalf("geoSite block must precede the GEOIP fallback: geoSite=%d fallback=%d", geoSiteIndex, fallback)
			}
			continue
		}
		domestic := indexOf("DOMAIN-SUFFIX,douyin.com,DIRECT")
		if domestic < 0 || !(overseas < domestic && domestic < fallback) {
			t.Fatalf("routing order is wrong: overseas=%d domestic=%d fallback=%d", overseas, domestic, fallback)
		}
	}
}

func TestDomesticGeoIPMustNotResolveDomains(t *testing.T) {
	store := Open(filepath.Join(t.TempDir(), "domestic.json"))
	applied, err := store.Apply(testTemplate, false)
	if err != nil {
		t.Fatal(err)
	}
	var document map[string][]string
	if err := yaml.Unmarshal([]byte(applied), &document); err != nil {
		t.Fatalf("expanded template is not valid YAML: %v", err)
	}
	var hasDomesticGeoIP bool
	for _, rule := range document["rules"] {
		// 不带 no-resolve 时，未列入域名块的国外站点也会被解析，只要解析结果落在大陆 IP
		// 就会被判成直连而打不开；域名连接必须只由域名规则或 MATCH,PROXY 决定。
		if rule == "GEOIP,cn,DIRECT" {
			t.Fatal("GEOIP,cn must carry no-resolve or foreign domains get matched by their resolved IP")
		}
		if rule == "GEOIP,cn,DIRECT,no-resolve" {
			hasDomesticGeoIP = true
		}
		// mihomo 只对 "lan" 做特殊处理，GEOIP,private 在 geodata 模式下会导致整份配置加载失败。
		if strings.HasPrefix(rule, "GEOIP,private,") {
			t.Fatalf("unsupported GEOIP country in rule: %q", rule)
		}
	}
	if !hasDomesticGeoIP {
		t.Fatal("missing GEOIP,cn,DIRECT,no-resolve fallback")
	}
}

func TestFailedPersistenceAndConcurrentRead(t *testing.T) {
	path := filepath.Join(t.TempDir(), "not-a-directory")
	if err := os.WriteFile(path, nil, 0600); err != nil {
		t.Fatal(err)
	}
	store := Open(filepath.Join(path, "cache.json"))
	before := store.Version()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(bundled + "\n+.new-fixture.example\n"))
	}))
	defer server.Close()
	if store.Refresh(context.Background(), server.Client(), server.URL) == nil || store.Version() != before {
		t.Fatal("failed persistence activated an unpersisted update")
	}
	store = Open(filepath.Join(t.TempDir(), "cache.json"))
	var readers sync.WaitGroup
	for i := 0; i < 8; i++ {
		readers.Add(1)
		go func() {
			defer readers.Done()
			for j := 0; j < 100; j++ {
				if !strings.HasSuffix(mustApply(t, store, testTemplate), "MATCH,PROXY\n") {
					t.Error("concurrent read returned incomplete subscription")
				}
			}
		}()
	}
	if err := store.Refresh(context.Background(), server.Client(), server.URL); err != nil {
		t.Fatal(err)
	}
	readers.Wait()
}
