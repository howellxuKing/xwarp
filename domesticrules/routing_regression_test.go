package domesticrules

import (
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
	"trojan-panel/model/constant"
	"trojan-panel/subscriptionrules"
)

// Domain-only HTTP/SOCKS requests have not necessarily performed a local DNS lookup.
// Their rules must not depend on no-resolve GEOIP discovering an address for them.
func TestCommonMainlandDomainsStayDirect(t *testing.T) {
	base, err := Open("").Apply(constant.ClashRules, false)
	if err != nil {
		t.Fatal(err)
	}
	full, err := subscriptionrules.Compose(base, "", constant.ClashLocalRules)
	if err != nil {
		t.Fatal(err)
	}
	var config struct {
		Rules []string `yaml:"rules"`
	}
	if err := yaml.Unmarshal([]byte(full), &config); err != nil {
		t.Fatal(err)
	}
	for _, domain := range []string{"www.qq.com", "www.taobao.com", "www.alipay.com", "www.jd.com", "www.bilibili.com", "www.baidu.com", "www.douyin.com"} {
		t.Run(domain, func(t *testing.T) {
			for _, rule := range config.Rules {
				parts := strings.Split(rule, ",")
				match := parts[0] == "MATCH"
				if len(parts) >= 3 {
					match = match || parts[0] == "DOMAIN" && domain == parts[1] || parts[0] == "DOMAIN-SUFFIX" && (domain == parts[1] || strings.HasSuffix(domain, "."+parts[1]))
				}
				if match {
					policy := parts[len(parts)-1]
					if policy != "DIRECT" {
						t.Errorf("domain-only request reaches %s; expected DIRECT", rule)
					}
					return
				}
			}
			t.Fatal("no terminal rule")
		})
	}
}
