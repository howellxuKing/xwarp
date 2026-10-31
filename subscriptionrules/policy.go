package subscriptionrules

import (
	"fmt"
	"strings"

	"gopkg.in/yaml.v3"
)

// ValidatePolicy reports whether an administrator template still honours the routing model:
// everything that is not explicitly sent direct must go through the proxy.
//
// Two shapes break that model and were both seen in templates copied from third-party rule
// projects. A catch-all DIRECT rule turns every unmatched foreign site into a direct connection,
// and a GEOIP,cn rule without no-resolve resolves the destination of a domain connection, so any
// foreign site whose DNS answer happens to land on a mainland IP is sent direct too. Both fail
// only in rule mode, because global mode ignores the rule list entirely.
func ValidatePolicy(template string) error {
	var document yaml.Node
	if err := yaml.Unmarshal([]byte(template), &document); err != nil {
		return fmt.Errorf("invalid rule template: %w", err)
	}
	if len(document.Content) != 1 || document.Content[0].Kind != yaml.MappingNode {
		return fmt.Errorf("rule template must be a mapping")
	}
	fields := document.Content[0].Content
	for i := 0; i+1 < len(fields); i += 2 {
		if fields[i].Value != "rules" {
			continue
		}
		for _, item := range fields[i+1].Content {
			if item.Kind != yaml.ScalarNode {
				continue
			}
			if err := validateRule(item.Value); err != nil {
				return err
			}
		}
	}
	return nil
}

func validateRule(rule string) error {
	parts := strings.Split(rule, ",")
	for index := range parts {
		parts[index] = strings.TrimSpace(parts[index])
	}
	if len(parts) < 2 {
		return nil
	}
	kind := strings.ToUpper(parts[0])
	switch kind {
	case "MATCH", "FINAL":
		if strings.EqualFold(parts[1], "DIRECT") {
			return fmt.Errorf("catch-all rule %q sends unmatched traffic direct; keep MATCH,PROXY", rule)
		}
	case "GEOIP":
		if !strings.EqualFold(parts[1], "cn") {
			return nil
		}
		if len(parts) > 2 && strings.EqualFold(parts[2], "DIRECT") && !hasNoResolve(parts[3:]) {
			return fmt.Errorf("rule %q lets a domain connection be matched by its resolved IP; add no-resolve", rule)
		}
	}
	return nil
}

func hasNoResolve(options []string) bool {
	for _, option := range options {
		if strings.EqualFold(option, "no-resolve") {
			return true
		}
	}
	return false
}
