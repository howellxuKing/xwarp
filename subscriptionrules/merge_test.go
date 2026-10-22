package subscriptionrules

import (
	"reflect"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
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
