package subscriptionrules

import (
	"net"
	"os"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
	"trojan-panel/model/constant"
)

func TestNewDefaultSubscriptionDirectsTheThreeProcesses(t *testing.T) {
	assertProcessBlock(t, ruleList(t, constant.ClashRules))
	composed := mustCompose(t, constant.ClashRules, "")
	rules := ruleList(t, composed)
	assertProcessBlock(t, rules)
	assertNoVergeOverride(t, composed)

	if got := policyFor(rules, conn{host: "www.qq.com"}); got != "DIRECT" {
		t.Fatalf("mainland qq.com = %s, want DIRECT", got)
	}
	if got := policyFor(rules, conn{host: "www.google.com"}); got != "PROXY" {
		t.Fatalf("foreign google.com = %s, want PROXY", got)
	}
	for _, process := range []string{"360ChromeX.exe", "WeChat.exe", "Weixin.exe"} {
		if got := policyFor(rules, conn{process: process, host: "www.google.com"}); got != "DIRECT" {
			t.Fatalf("%s to google.com = %s, want DIRECT", process, got)
		}
	}
	if got := policyFor(rules, conn{process: "chrome.exe", host: "www.google.com"}); got != "PROXY" {
		t.Fatalf("unrelated browser = %s, want PROXY", got)
	}
	if got := policyFor(rules, conn{process: "WeChat.exe", ip: "240e:1234::1"}); got != "REJECT" {
		t.Fatalf("WeChat IPv6 = %s, want REJECT so a line without IPv6 still fails fast", got)
	}
	if got := policyFor(rules, conn{process: "WeChat.exe", ip: "192.168.1.8"}); got != "DIRECT" {
		t.Fatalf("WeChat LAN = %s, want DIRECT", got)
	}
	if got := policyFor(rules, conn{process: "360ChromeX.exe", ip: "fe80::1"}); got != "DIRECT" {
		t.Fatalf("link-local IPv6 = %s, want DIRECT", got)
	}
}

func TestSavedV4TemplateUpgradesAndOldTextStillGainsProcessRules(t *testing.T) {
	old, err := os.ReadFile("testdata/clash_rules_v4.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(old), "PROCESS-NAME") {
		t.Fatal("v4 fixture already contains process rules; it no longer represents the previous default")
	}
	if got := CanonicalDigest(string(old)); got != constant.ClashRulesV4SHA256 {
		t.Fatalf("v4 fixture digest = %s", got)
	}
	crlf := strings.ReplaceAll(string(old), "\n", "\r\n") + "\r\n"
	if !IsBuiltinTemplate(string(old)) || !IsBuiltinTemplate(crlf) {
		t.Fatal("saved unmodified v4 template would stay in place after the default text changes")
	}
	if !IsBuiltinTemplate(constant.ClashRules) || !IsBuiltinTemplate("rules:\n  - GEOIP,CN,DIRECT\n  - MATCH,PROXY\n") {
		t.Fatal("current default or the ancient two-line template is no longer recognized")
	}
	custom := "rules:\n  - DOMAIN-SUFFIX,keep.example,DIRECT\n  - MATCH,PROXY\n"
	if IsBuiltinTemplate(custom) {
		t.Fatal("custom template classified as a shipped default")
	}

	builtin := constant.ClashRules
	if got := ResolveBase(string(old), nil, builtin, nil, ValidatePolicy); got != builtin {
		t.Fatal("saved v4 template was not replaced by the current default")
	}
	if got := ResolveBase(crlf, nil, builtin, nil, ValidatePolicy); got != builtin {
		t.Fatal("CRLF v4 template was not replaced by the current default")
	}
	if got := ResolveBase("", os.ErrNotExist, builtin, nil, ValidatePolicy); got != builtin {
		t.Fatal("missing template file did not use the current default")
	}
	if got := ResolveBase(" \r\n", nil, builtin, nil, ValidatePolicy); got != builtin {
		t.Fatal("empty template file did not use the current default")
	}

	// A panel file that missed the digest (extra comment, partial edit) is not
	// discarded. Composing it still inserts the three rules.
	rules := ruleList(t, mustCompose(t, string(old), ""))
	assertProcessBlock(t, rules)
	if policyFor(rules, conn{host: "www.qq.com"}) != "DIRECT" || policyFor(rules, conn{host: "www.google.com"}) != "PROXY" {
		t.Fatal("composing the previous default changed mainland or foreign routing")
	}
}

func TestProcessRulesDedupWithoutDroppingCustomRules(t *testing.T) {
	base := `rules:
  - PROCESS-NAME,WeChat.exe,DIRECT
  - PROCESS-NAME, wechat.exe, DIRECT
  - DOMAIN-SUFFIX,keep.example,PROXY
  - IP-CIDR6,::/0,REJECT
  - PROCESS-NAME,360ChromeX.exe,DIRECT
  - PROCESS-NAME,Weixin.exe,DIRECT
  - PROCESS-NAME,WeChat.exe,PROXY
  - DOMAIN-SUFFIX,qq.com,DIRECT
  - MATCH,PROXY
`
	custom := "  - DOMAIN-SUFFIX,only-admin.example,DIRECT\n  - PROCESS-NAME,360ChromeX.exe,DIRECT\n"
	composed := mustCompose(t, base, custom)
	assertNoVergeOverride(t, composed)
	rules := ruleList(t, composed)
	assertProcessBlock(t, rules)
	for _, rule := range []string{
		constant.ClashProcessDirectRule360ChromeX,
		constant.ClashProcessDirectRuleWeChat,
		constant.ClashProcessDirectRuleWeixin,
	} {
		if strings.Count(strings.Join(rules, "\n"), rule) != 1 {
			t.Fatalf("rule %s is not present exactly once:\n%s", rule, composed)
		}
	}
	if !containsRule(rules, "DOMAIN-SUFFIX,keep.example,PROXY") || !containsRule(rules, "DOMAIN-SUFFIX,only-admin.example,DIRECT") || !containsRule(rules, "PROCESS-NAME,WeChat.exe,PROXY") {
		t.Fatalf("custom rules were rewritten:\n%s", strings.Join(rules, "\n"))
	}
	if policyFor(rules, conn{process: "chrome.exe", host: "keep.example"}) != "PROXY" || policyFor(rules, conn{process: "WeChat.exe", host: "keep.example"}) != "PROXY" {
		t.Fatal("domain exception above the IPv6 reject no longer wins")
	}
	if policyFor(rules, conn{process: "WeChat.exe", host: "www.google.com"}) != "DIRECT" {
		t.Fatal("WeChat foreign traffic did not hit the direct process rule")
	}
	// The customized WeChat PROXY rule stays in the list, but it is after the
	// pinned direct rule, so the direct rule wins.
	if indexOf(rules, "PROCESS-NAME,WeChat.exe,PROXY") < indexOf(rules, constant.ClashProcessDirectRuleWeChat) {
		t.Fatal("pinned WeChat direct rule is not ahead of the later custom proxy rule")
	}
	if policyFor(rules, conn{host: "only-admin.example"}) != "DIRECT" {
		t.Fatal("administrator direct exception was dropped")
	}
	if policyFor(rules, conn{host: "www.qq.com"}) != "DIRECT" || policyFor(rules, conn{process: "chrome.exe", host: "www.google.com"}) != "PROXY" {
		t.Fatal("existing domain split regressed while pinning process rules")
	}
}

func TestIPv6OverrideAboveTheRejectStillWins(t *testing.T) {
	base := "rules:\n  - IP-CIDR6,2001:db8::/32,DIRECT\n  - " + constant.ClashIPv6NoEgressRule + "\n  - MATCH,PROXY\n"
	rules := ruleList(t, mustCompose(t, base, ""))
	if indexOf(rules, "IP-CIDR6,2001:db8::/32,DIRECT") > indexOf(rules, constant.ClashIPv6NoEgressRule) {
		t.Fatal("IPv6 exception placed above the reject was moved behind it")
	}
	if got := policyFor(rules, conn{process: "WeChat.exe", ip: "2001:db8::1"}); got != "DIRECT" {
		t.Fatalf("explicit IPv6 exception = %s, want DIRECT", got)
	}
	if got := policyFor(rules, conn{process: "Weixin.exe", ip: "240e:1::1"}); got != "REJECT" {
		t.Fatalf("other IPv6 = %s, want REJECT", got)
	}
	if got := policyFor(rules, conn{process: "360ChromeX.exe", host: "www.google.com"}); got != "DIRECT" {
		t.Fatalf("360ChromeX IPv4 = %s, want DIRECT", got)
	}
}

func TestResolveBaseKeepsCustomTemplateAndDropsBrokenPolicy(t *testing.T) {
	builtin := constant.ClashRules
	custom := "rules:\n  - DOMAIN-SUFFIX,keep.example,PROXY\n  - MATCH,PROXY\n"
	if got := ResolveBase(custom, nil, builtin, func(rules string) (string, error) { return rules, nil }, ValidatePolicy); strings.TrimSpace(got) != strings.TrimSpace(custom) {
		t.Fatalf("custom template was replaced: %s", got)
	}
	expanded := "rules:\n  - DOMAIN-SUFFIX,qq.com,DIRECT\n  - MATCH,PROXY\n"
	got := ResolveBase("rules:\n  - "+constant.ClashDomesticMarker+"\n  - MATCH,PROXY\n", nil, builtin, func(rules string) (string, error) {
		if !strings.Contains(rules, constant.ClashDomesticMarker) {
			t.Fatal("expand saw a template without the marker")
		}
		return expanded, nil
	}, ValidatePolicy)
	if strings.TrimSpace(got) != strings.TrimSpace(expanded) {
		t.Fatalf("expanded custom template not kept: %q", got)
	}
	if got := ResolveBase(custom, nil, builtin, func(string) (string, error) { return "", os.ErrInvalid }, ValidatePolicy); got != builtin {
		t.Fatal("expand failure did not fall back to the built-in template")
	}
	broken := "rules:\n  - MATCH,DIRECT\n"
	if got := ResolveBase(broken, nil, builtin, nil, ValidatePolicy); got != builtin {
		t.Fatal("catch-all direct template was sent to the client")
	}
}

func mustCompose(t *testing.T, base, custom string) string {
	t.Helper()
	got, err := Compose(base, custom, constant.ClashLocalRules)
	if err != nil {
		t.Fatal(err)
	}
	return got
}

func ruleList(t *testing.T, document string) []string {
	t.Helper()
	var parsed struct {
		Rules []string `yaml:"rules"`
	}
	if err := yaml.Unmarshal([]byte(document), &parsed); err != nil {
		t.Fatal(err)
	}
	if len(parsed.Rules) == 0 {
		t.Fatal("subscription has no rules")
	}
	return parsed.Rules
}

func assertProcessBlock(t *testing.T, rules []string) {
	t.Helper()
	want := []string{
		constant.ClashProcessDirectRule360ChromeX,
		constant.ClashProcessDirectRuleWeChat,
		constant.ClashProcessDirectRuleWeixin,
	}
	first := indexOf(rules, want[0])
	reject := indexOf(rules, constant.ClashIPv6NoEgressRule)
	lan := indexOf(rules, "IP-CIDR,192.168.0.0/16,DIRECT,no-resolve")
	localV6 := indexOf(rules, "IP-CIDR6,fe80::/10,DIRECT,no-resolve")
	qq := indexOf(rules, "DOMAIN-SUFFIX,qq.com,DIRECT")
	match := indexOf(rules, "MATCH,PROXY")
	if lan < 0 || localV6 < 0 || reject < 0 || first < 0 || qq < 0 || match < 0 {
		t.Fatalf("missing anchor rule in:\n%s", strings.Join(rules, "\n"))
	}
	if !(lan < reject && localV6 < reject && reject < first && first < qq && qq < match) {
		t.Fatalf("process rules are not between the IPv6 reject and mainland rules: lan=%d localv6=%d reject=%d process=%d qq=%d match=%d", lan, localV6, reject, first, qq, match)
	}
	for i, rule := range want {
		if rules[first+i] != rule {
			t.Fatalf("process rule %d = %s, want %s", i, rules[first+i], rule)
		}
	}
}

func assertNoVergeOverride(t *testing.T, document string) {
	t.Helper()
	for _, key := range []string{"prepend-rules:", "append-rules:", "delete-rules:"} {
		if strings.Contains(document, key) {
			t.Fatalf("subscription contains Clash Verge override key %s", key)
		}
	}
}

func containsRule(rules []string, want string) bool {
	return indexOf(rules, want) >= 0
}

func indexOf(rules []string, want string) int {
	for i, rule := range rules {
		if rule == want {
			return i
		}
	}
	return -1
}

type conn struct {
	process string
	host    string
	ip      string
}

func policyFor(rules []string, in conn) string {
	for _, rule := range rules {
		if !ruleMatches(rule, in) {
			continue
		}
		parts := splitRule(rule)
		if len(parts) == 0 {
			return ""
		}
		if strings.EqualFold(parts[0], "MATCH") || strings.EqualFold(parts[0], "FINAL") {
			return parts[len(parts)-1]
		}
		policy := parts[len(parts)-1]
		if strings.EqualFold(policy, "no-resolve") {
			policy = parts[len(parts)-2]
		}
		return policy
	}
	return ""
}

func ruleMatches(rule string, in conn) bool {
	parts := splitRule(rule)
	if len(parts) < 2 {
		return false
	}
	switch strings.ToUpper(parts[0]) {
	case "MATCH", "FINAL":
		return true
	case "PROCESS-NAME":
		return in.process != "" && strings.EqualFold(parts[1], in.process)
	case "DOMAIN":
		return in.host != "" && strings.EqualFold(in.host, parts[1])
	case "DOMAIN-SUFFIX":
		host := strings.ToLower(in.host)
		suffix := strings.ToLower(parts[1])
		return host != "" && (host == suffix || strings.HasSuffix(host, "."+suffix))
	case "IP-CIDR", "IP-CIDR6":
		if in.ip == "" {
			return false
		}
		_, network, err := net.ParseCIDR(parts[1])
		parsed := net.ParseIP(in.ip)
		return err == nil && parsed != nil && network.Contains(parsed)
	default:
		return false
	}
}

func splitRule(rule string) []string {
	parts := strings.Split(rule, ",")
	for i := range parts {
		parts[i] = strings.TrimSpace(parts[i])
	}
	return parts
}
