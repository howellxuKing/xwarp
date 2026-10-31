package subscriptionrules

import (
	"testing"

	"trojan-panel/model/constant"
)

func TestValidatePolicyAcceptsTheBuiltInTemplate(t *testing.T) {
	if err := ValidatePolicy(constant.ClashRules); err != nil {
		t.Fatalf("built-in template rejected: %v", err)
	}
}

func TestValidatePolicyRejectsTemplatesThatBreakRuleMode(t *testing.T) {
	for _, template := range []string{
		"rules:\n  - DOMAIN-SUFFIX\n  - MATCH,PROXY\n",
		"rules:\n  - RULE-SET,missing,DIRECT\n  - MATCH,PROXY\n",
		"rules:\n  - MATCH,PROXY\n  - DOMAIN,late.example,DIRECT\n",
		// Every unmatched foreign site becomes a direct connection.
		"rules:\n  - GEOIP,cn,DIRECT,no-resolve\n  - MATCH,DIRECT\n",
		"rules:\n  - FINAL,DIRECT\n",
		// The domain is resolved first, so a mainland DNS answer sends it direct.
		"rules:\n  - GEOIP,cn,DIRECT\n  - MATCH,PROXY\n",
		"rules:\n  - GEOIP,CN,DIRECT,src\n  - MATCH,PROXY\n",
	} {
		if err := ValidatePolicy(template); err == nil {
			t.Fatalf("accepted a template that breaks rule mode: %q", template)
		}
	}
}

func TestValidatePolicyAcceptsSafeExceptions(t *testing.T) {
	for _, template := range []string{
		"rules:\n  - GEOIP,cn,DIRECT,no-resolve\n  - MATCH,PROXY\n",
		"rules:\n  - DOMAIN-SUFFIX,example.org,DIRECT\n  - GEOSITE,cn,DIRECT\n  - IP-CIDR,10.0.0.0/8,DIRECT,no-resolve\n  - MATCH,PROXY\n",
		"dns:\n  enable: true\nrules:\n  - GEOIP,lan,DIRECT,no-resolve\n  - MATCH,PROXY\n",
	} {
		if err := ValidatePolicy(template); err != nil {
			t.Fatalf("rejected a safe template %q: %v", template, err)
		}
	}
}
