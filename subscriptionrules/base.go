package subscriptionrules

import (
	"strings"

	"trojan-panel/model/constant"
)

// IsBuiltinTemplate reports whether saved rule text is an unmodified shipped default.
// Those copies are replaced at subscription time, so an upgrade does not depend on
// rewriting the panel file. Comparison uses the canonical digest: CRLF folded to LF
// and surrounding whitespace trimmed.
func IsBuiltinTemplate(content string) bool {
	switch CanonicalDigest(content) {
	case constant.ClashRulesV233SHA256,
		constant.ClashRulesPreviousSHA256,
		constant.ClashRulesV250SHA256,
		constant.ClashRulesV251SHA256,
		constant.ClashRulesV252SHA256,
		constant.ClashRulesV254SHA256,
		constant.ClashRulesV255SHA256,
		constant.ClashRulesV3SHA256,
		constant.ClashRulesV4SHA256:
		return true
	}
	normalized := strings.TrimSpace(strings.ReplaceAll(content, "\r\n", "\n"))
	return normalized == strings.TrimSpace(constant.ClashRules) ||
		normalized == "rules:\n  - GEOIP,CN,DIRECT\n  - MATCH,PROXY"
}

// ResolveBase chooses the template a subscription is built from.
// A missing, empty, or unmodified historical file uses builtin. A customized file
// is kept: expand may rewrite a legacy marker, and accept rejects a template that
// would send foreign sites direct. The saved file itself is not modified.
func ResolveBase(file string, readErr error, builtin string, expand func(string) (string, error), accept func(string) error) string {
	if readErr != nil {
		return builtin
	}
	rules := strings.TrimSpace(file)
	if rules == "" || IsBuiltinTemplate(file) {
		return builtin
	}
	applied := rules
	if expand != nil {
		next, err := expand(rules)
		if err != nil {
			return builtin
		}
		applied = next
	}
	if accept != nil && accept(applied) != nil {
		return builtin
	}
	return applied
}
