package subscriptionrules

import (
	"reflect"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"

	"trojan-panel/model/bo"
	"trojan-panel/model/constant"
)

func TestProxyGroupsOfferAutomaticAndManualSelection(t *testing.T) {
	groups := ProxyGroups([]string{"u1", "u2"})
	if len(groups) != 3 || groups[0].Name != "PROXY" || groups[0].Type != "select" || !reflect.DeepEqual(groups[0].Proxies, []string{"u1", "u2", "AUTO", "FALLBACK"}) {
		t.Fatalf("manual selection must retain nodes and offer AUTO and FALLBACK: %+v", groups)
	}
	// Select uses the first member when the client has no saved choice.
	// FALLBACK is last so that default stays u1.
	if groups[0].Proxies[0] != "u1" {
		t.Fatalf("default selected member changed: %+v", groups[0].Proxies)
	}
	auto := groups[1]
	if auto.Name != "AUTO" || auto.Type != "url-test" || !reflect.DeepEqual(auto.Proxies, []string{"u1", "u2"}) || auto.Url != "https://www.gstatic.com/generate_204" || auto.Interval != 300 || auto.Tolerance != 0 {
		t.Fatalf("AUTO must test actual nodes every five minutes: %+v", auto)
	}
	fallback := groups[2]
	// 60s, not AUTO's 300s. Fallback moves only after a health check, so the
	// interval is the failover bound: about a minute, still one probe per node
	// per minute rather than a tight loop.
	if fallback.Name != "FALLBACK" || fallback.Type != "fallback" || !reflect.DeepEqual(fallback.Proxies, []string{"u1", "u2"}) || fallback.Url != auto.Url || fallback.Interval != 60 || fallback.Tolerance != 0 {
		t.Fatalf("FALLBACK must probe the same nodes every 60s: %+v", fallback)
	}
}

func TestProxyGroupsWithoutNodesReject(t *testing.T) {
	for _, nodes := range [][]string{nil, {}} {
		groups := ProxyGroups(nodes)
		if len(groups) != 1 || groups[0].Name != "PROXY" || groups[0].Type != "select" || !reflect.DeepEqual(groups[0].Proxies, []string{"REJECT"}) {
			t.Fatalf("empty subscriptions must not offer an empty AUTO or FALLBACK group: %+v", groups)
		}
	}
}

func TestProxyGroupsAvoidAutomaticNameCollision(t *testing.T) {
	groups := ProxyGroups([]string{"AUTO", "AUTO-2", "u1"})
	if groups[1].Name != "AUTO-3" || groups[0].Proxies[3] != "AUTO-3" {
		t.Fatalf("automatic group must not collide with a node name: %+v", groups)
	}
	if groups[2].Name != "FALLBACK" || groups[0].Proxies[4] != "FALLBACK" {
		t.Fatalf("an AUTO node name must not rename FALLBACK: %+v", groups)
	}
}

func TestProxyGroupsAvoidFallbackNameCollision(t *testing.T) {
	groups := ProxyGroups([]string{"FALLBACK", "FALLBACK-2", "u1"})
	if groups[1].Name != "AUTO" || groups[2].Name != "FALLBACK-3" {
		t.Fatalf("FALLBACK must use FALLBACK, then FALLBACK-2, ... like AUTO: %+v", groups)
	}
	if !reflect.DeepEqual(groups[0].Proxies, []string{"FALLBACK", "FALLBACK-2", "u1", "AUTO", "FALLBACK-3"}) {
		t.Fatalf("PROXY must list the node and the renamed group once each: %+v", groups[0].Proxies)
	}
	if !reflect.DeepEqual(groups[2].Proxies, []string{"FALLBACK", "FALLBACK-2", "u1"}) {
		t.Fatalf("FALLBACK members must stay the nodes, in subscription order: %+v", groups[2].Proxies)
	}

	// A later suffix on its own does not consume the base name. AUTO behaves
	// the same way: a node named AUTO-2 leaves the group named AUTO.
	kept := ProxyGroups([]string{"FALLBACK-2", "u1"})
	if kept[2].Name != "FALLBACK" || kept[0].Proxies[len(kept[0].Proxies)-1] != "FALLBACK" {
		t.Fatalf("FALLBACK-2 node must not rename the group: %+v", kept)
	}
}

func TestProxyGroupsRenameBothAutomaticGroups(t *testing.T) {
	groups := ProxyGroups([]string{"AUTO", "AUTO-2", "FALLBACK", "FALLBACK-2"})
	if groups[1].Name != "AUTO-3" || groups[2].Name != "FALLBACK-3" {
		t.Fatalf("each automatic name is renamed on its own: %+v", groups)
	}
	if !reflect.DeepEqual(groups[0].Proxies, []string{"AUTO", "AUTO-2", "FALLBACK", "FALLBACK-2", "AUTO-3", "FALLBACK-3"}) {
		t.Fatalf("PROXY lost a renamed group: %+v", groups[0].Proxies)
	}
}

func TestSubscriptionYAMLListsFallbackWithoutRewritingRules(t *testing.T) {
	rules, err := Compose(constant.ClashRules, "", constant.ClashLocalRules)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := yaml.Marshal(&bo.ClashConfig{
		Mode:        "rule",
		Proxies:     []interface{}{bo.Socks{Name: "u1", Type: "socks5", Server: "127.0.0.1", Port: 1}},
		ProxyGroups: ProxyGroups([]string{"u1", "u2"}),
	})
	if err != nil {
		t.Fatal(err)
	}
	// Same join as the subscription response: group document, then the rules.
	document := string(raw) + "\n" + rules
	if !strings.Contains(document, rules) {
		t.Fatal("subscription dropped the composed rules")
	}
	for _, rule := range []string{
		constant.ClashProcessDirectRule360ChromeX,
		constant.ClashProcessDirectRuleWeChat,
		constant.ClashProcessDirectRuleWeixin,
		constant.ClashIPv6NoEgressRule,
		"MATCH,PROXY",
	} {
		if !strings.Contains(rules, rule) || !strings.Contains(document, rule) {
			t.Fatalf("subscription no longer contains %s", rule)
		}
	}
	if strings.Contains(rules, ",AUTO") || strings.Contains(rules, ",FALLBACK") || strings.HasSuffix(strings.TrimSpace(rules), "MATCH,FALLBACK") {
		t.Fatalf("routing policy moved off PROXY:\n%s", rules)
	}

	var parsed struct {
		Mode        string          `yaml:"mode"`
		ProxyGroups []bo.ProxyGroup `yaml:"proxy-groups"`
		Rules       []string        `yaml:"rules"`
	}
	if err := yaml.Unmarshal([]byte(document), &parsed); err != nil {
		t.Fatalf("subscription YAML is invalid: %v\n%s", err, document)
	}
	if parsed.Mode != "rule" || len(parsed.ProxyGroups) != 3 {
		t.Fatalf("group document changed: mode=%s groups=%+v", parsed.Mode, parsed.ProxyGroups)
	}
	proxy, auto, fallback := parsed.ProxyGroups[0], parsed.ProxyGroups[1], parsed.ProxyGroups[2]
	if proxy.Name != "PROXY" || proxy.Type != "select" || !reflect.DeepEqual(proxy.Proxies, []string{"u1", "u2", "AUTO", "FALLBACK"}) {
		t.Fatalf("PROXY selector: %+v", proxy)
	}
	if auto.Type != "url-test" || auto.Interval != 300 || auto.Url != healthCheckURL {
		t.Fatalf("AUTO YAML: %+v", auto)
	}
	if fallback.Name != "FALLBACK" || fallback.Type != "fallback" || fallback.Interval != 60 || fallback.Url != healthCheckURL || !reflect.DeepEqual(fallback.Proxies, []string{"u1", "u2"}) {
		t.Fatalf("FALLBACK YAML: %+v", fallback)
	}
	if parsed.Rules[len(parsed.Rules)-1] != "MATCH,PROXY" {
		t.Fatalf("terminal rule = %s", parsed.Rules[len(parsed.Rules)-1])
	}
	if !strings.Contains(string(raw), "type: fallback") || !strings.Contains(string(raw), "interval: 60") {
		t.Fatalf("marshaled groups omitted fallback fields:\n%s", raw)
	}

	empty, err := yaml.Marshal(&bo.ClashConfig{Mode: "rule", ProxyGroups: ProxyGroups(nil)})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(empty), "name: AUTO") || strings.Contains(string(empty), "name: FALLBACK") || strings.Contains(string(empty), "type: fallback") {
		t.Fatalf("empty subscription emitted an automatic group:\n%s", empty)
	}
	if !strings.Contains(string(empty), "REJECT") {
		t.Fatalf("empty subscription lost REJECT:\n%s", empty)
	}
}
