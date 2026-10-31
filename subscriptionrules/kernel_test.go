package subscriptionrules

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"gopkg.in/yaml.v3"
	"trojan-panel/model/bo"
	"trojan-panel/model/constant"
)

// Optional local proof uses the installed core in test-only mode, with an isolated home.
// Provider caches are preseeded, so parser verification does not require external downloads.
func TestClashVergeKernelAcceptsCloudDefaults(t *testing.T) {
	core := os.Getenv("XWARP_TEST_MIHOMO")
	if core == "" {
		t.Skip("set XWARP_TEST_MIHOMO for an isolated installed-core check")
	}
	dir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, "ruleset"), 0700); err != nil {
		t.Fatal(err)
	}
	for name, payload := range map[string]string{
		"xwarp-direct.yaml": "payload:\n  - '+.qq.com'\n  - '+.taobao.com'\n",
		"xwarp-cncidr.yaml": "payload:\n  - 223.5.5.0/24\n",
	} {
		if err := os.WriteFile(filepath.Join(dir, "ruleset", name), []byte(payload), 0600); err != nil {
			t.Fatal(err)
		}
	}
	config := bo.ClashConfig{Mode: "rule", Proxies: []interface{}{bo.Socks{Name: "candidate", Type: "socks5", Server: "127.0.0.1", Port: 9}}, ProxyGroups: []bo.ProxyGroup{{Name: "PROXY", Type: "select", Proxies: []string{"candidate"}}}}
	prefix, err := yaml.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}
	rules, err := Compose(constant.ClashRules, "", constant.ClashLocalRules)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path, append(prefix, []byte(rules)...), 0600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()
	output, err := exec.CommandContext(ctx, core, "-t", "-d", dir, "-f", path).CombinedOutput()
	if err != nil {
		t.Fatalf("Mihomo rejected candidate: %v\n%s", err, output)
	}
	t.Log("Installed Mihomo accepted the complete cloud-provider subscription in an isolated directory")
}
