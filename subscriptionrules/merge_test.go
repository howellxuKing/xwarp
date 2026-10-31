package subscriptionrules

import (
	"reflect"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"

	"trojan-panel/model/constant"
)

func TestPrepend(t *testing.T) {
	for _, base := range []string{
		"rules:\n  - GEOIP,CN,DIRECT\n  - MATCH,PROXY\n",
		"# administrator template\nrules: [\"GEOIP,CN,DIRECT\", \"MATCH,PROXY\"]\ndns:\n  enable: true\n",
		"dns:\n  enable: true\nrules:\r\n  - GEOIP,CN,DIRECT\r\n  - MATCH,PROXY\r\n",
	} {
		for _, custom := range []string{
			"  - DOMAIN-SUFFIX,0996zp.com,DIRECT\n",
			"  - DOMAIN-SUFFIX,example.org,PROXY\n  - DOMAIN-SUFFIX,0996zp.com,DIRECT\n",
		} {
			merged, err := Prepend(base, custom)
			if err != nil {
				t.Fatal(err)
			}
			// Parse the full shape returned to a client, including node/group definitions.
			prefix := "proxies: [{name: fixture, type: socks5, server: 127.0.0.1, port: 1080}]\nproxy-groups: [{name: PROXY, type: select, proxies: [fixture]}]\n"
			var config map[string]interface{}
			if err := yaml.Unmarshal([]byte(prefix+merged), &config); err != nil {
				t.Fatalf("invalid client subscription: %v", err)
			}
			var original map[string]interface{}
			if err := yaml.Unmarshal([]byte(base), &original); err != nil {
				t.Fatal(err)
			}
			var expected []interface{}
			if err := yaml.Unmarshal([]byte(custom), &expected); err != nil {
				t.Fatal(err)
			}
			expected = append(expected, original["rules"].([]interface{})...)
			if !reflect.DeepEqual(config["rules"], expected) || config["proxies"] == nil || config["proxy-groups"] == nil {
				t.Fatal("rules order or node/group definitions changed")
			}
			if !reflect.DeepEqual(config["dns"], original["dns"]) {
				t.Fatal("administrator DNS configuration changed")
			}
		}
		got, err := Prepend(base, " \r\n")
		if err != nil || got != base {
			t.Fatal("empty custom list changed base template")
		}
	}
}

func TestPrependRejectsInvalidTemplates(t *testing.T) {
	for _, pair := range [][2]string{
		{"rules: [", "- MATCH,PROXY"},
		{"rules: wrong", "- MATCH,PROXY"},
		{"dns: {}", "- MATCH,PROXY"},
		{"rules: []\nrules: []", "- MATCH,PROXY"},
		{"rules: []", "rules: []"},
		{"rules: []", "- {invalid: mapping}"},
	} {
		if _, err := Prepend(pair[0], pair[1]); err == nil {
			t.Fatalf("accepted invalid rule template: %q", strings.Join(pair[:], " / "))
		}
	}
}

func TestComposeHonoursManualExceptionsAfterLocal(t *testing.T) {
	// A template imported from a third-party rule project: mainland first, direct fallback.
	base := "rules:\n  - DOMAIN-SUFFIX,youtube.com,PROXY\n  - MATCH,PROXY\n"
	// The panel's own custom domain list can hijack YouTube the same way.
	custom := "  - DOMAIN-SUFFIX,youtube.com,DIRECT\n"
	composed, err := Compose(base, custom, constant.ClashLocalRules)
	if err != nil {
		t.Fatal(err)
	}
	var document map[string][]string
	if err := yaml.Unmarshal([]byte(composed), &document); err != nil {
		t.Fatalf("invalid composed rules: %v", err)
	}
	rules := document["rules"]
	position := func(rule string) int {
		for i, item := range rules {
			if item == rule {
				return i
			}
		}
		return -1
	}
	proxy, hijack := position("DOMAIN-SUFFIX,youtube.com,PROXY"), position("DOMAIN-SUFFIX,youtube.com,DIRECT")
	if proxy < 0 || hijack < 0 || hijack > proxy {
		t.Fatalf("administrator exception did not win over the template: proxy=%d direct=%d", proxy, hijack)
	}
	if rules[0] != "DOMAIN,localhost,DIRECT" {
		t.Fatalf("local block is not first: %q", rules[0])
	}
}

func TestDefaultTemplateDigest(t *testing.T) {
	if got := CanonicalDigest(constant.ClashRules); got != constant.ClashRulesV3SHA256 {
		t.Fatalf("update ClashRulesV3SHA256 after editing the default template: got %s", got)
	}
	// A saved copy is compared after CRLF normalization, so either line ending must match.
	saved := strings.ReplaceAll(constant.ClashRules, "\n", "\r\n") + "\r\n"
	if got := CanonicalDigest(saved); got != constant.ClashRulesV3SHA256 {
		t.Fatalf("CRLF copy did not match: got %s", got)
	}
}
