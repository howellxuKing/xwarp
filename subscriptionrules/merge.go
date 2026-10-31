// Package subscriptionrules merges administrator rules without changing node credentials.
package subscriptionrules

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"

	"gopkg.in/yaml.v3"
)

// Compose protects local destinations, then honours administrator exceptions and the template.
// No overseas rule block is secretly prepended over administrator choices.
func Compose(base, custom, local string) (string, error) {
	var err error
	base, err = NormalizeLegacyGroups(base)
	if err != nil {
		return "", err
	}
	if err := Validate(base); err != nil {
		return "", err
	}
	merged, err := Prepend(base, custom)
	if err != nil {
		return "", err
	}
	merged, err = Prepend(merged, local)
	if err != nil {
		return "", err
	}
	var document yaml.Node
	if err := yaml.Unmarshal([]byte(merged), &document); err != nil {
		return "", err
	}
	fields := document.Content[0].Content
	for i := 0; i < len(fields); i += 2 {
		if fields[i].Value != "rules" {
			continue
		}
		seen := map[string]bool{}
		items := fields[i+1].Content[:0]
		for _, item := range fields[i+1].Content {
			// Historical templates may still reference the removed automatic groups.
			parts := strings.Split(item.Value, ",")
			policy := len(parts) - 1
			if policy > 0 && strings.TrimSpace(parts[policy]) == "no-resolve" {
				policy--
			}
			if policy > 0 && (strings.TrimSpace(parts[policy]) == "AUTO" || strings.TrimSpace(parts[policy]) == "FALLBACK") {
				parts[policy] = "PROXY"
				item.Value = strings.Join(parts, ",")
			}
			if !seen[item.Value] {
				seen[item.Value] = true
				items = append(items, item)
			}
		}
		fields[i+1].Content = items
	}
	// Validate the composed result, including provider references and terminal policy.
	if err := ValidatePolicyNode(&document); err != nil {
		return "", err
	}
	var output bytes.Buffer
	encoder := yaml.NewEncoder(&output)
	encoder.SetIndent(2)
	if err := encoder.Encode(&document); err != nil {
		return "", err
	}
	return output.String(), nil
}

// NormalizeLegacyGroups preserves the intent of older proxy templates after automatic groups
// are removed. It covers both routing targets (including MATCH) and provider download proxies.
func NormalizeLegacyGroups(template string) (string, error) {
	if err := Validate(template); err != nil {
		return "", err
	}
	var document yaml.Node
	if err := yaml.Unmarshal([]byte(template), &document); err != nil {
		return "", err
	}
	changed := false
	fields := document.Content[0].Content
	for i := 0; i < len(fields); i += 2 {
		if fields[i].Value == "rules" {
			for _, item := range fields[i+1].Content {
				parts := strings.Split(item.Value, ",")
				index := len(parts) - 1
				if index > 0 && strings.TrimSpace(parts[index]) == "no-resolve" {
					index--
				}
				if index > 0 && (strings.TrimSpace(parts[index]) == "AUTO" || strings.TrimSpace(parts[index]) == "FALLBACK") {
					parts[index] = "PROXY"
					item.Value = strings.Join(parts, ",")
					changed = true
				}
			}
		}
		if fields[i].Value == "rule-providers" && fields[i+1].Kind == yaml.MappingNode {
			providers := fields[i+1].Content
			for j := 1; j < len(providers); j += 2 {
				if providers[j].Kind != yaml.MappingNode {
					continue
				}
				config := providers[j].Content
				for k := 0; k+1 < len(config); k += 2 {
					if config[k].Value == "proxy" && (config[k+1].Value == "AUTO" || config[k+1].Value == "FALLBACK") {
						config[k+1].Value = "PROXY"
						changed = true
					}
				}
			}
		}
	}
	if !changed {
		return template, nil
	}
	var output bytes.Buffer
	encoder := yaml.NewEncoder(&output)
	encoder.SetIndent(2)
	if err := encoder.Encode(&document); err != nil {
		return "", err
	}
	return output.String(), nil
}

// CanonicalDigest identifies a stored template. Stored copies may use CRLF or carry a trailing
// newline, so the comparison runs on the normalized form: CRLF folded to LF and surrounding
// whitespace trimmed.
func CanonicalDigest(content string) string {
	canonical := strings.TrimSpace(strings.ReplaceAll(content, "\r\n", "\n"))
	sum := sha256.Sum256([]byte(canonical))
	return hex.EncodeToString(sum[:])
}

// Prepend inserts custom rule items into the base rules sequence, preserving other fields.
// An empty custom list leaves the administrator's template byte-for-byte unchanged.
func Prepend(base, custom string) (string, error) {
	if strings.TrimSpace(custom) == "" {
		return base, nil
	}
	if err := Validate(base); err != nil {
		return "", err
	}
	var document, additions yaml.Node
	if err := yaml.Unmarshal([]byte(base), &document); err != nil {
		return "", fmt.Errorf("invalid base rule template: %w", err)
	}
	if err := yaml.Unmarshal([]byte(custom), &additions); err != nil {
		return "", fmt.Errorf("invalid custom rule list: %w", err)
	}
	if len(additions.Content) != 1 || additions.Content[0].Kind != yaml.SequenceNode {
		return "", fmt.Errorf("custom rules must be a sequence")
	}
	for _, item := range additions.Content[0].Content {
		if item.Kind != yaml.ScalarNode || item.Tag != "!!str" {
			return "", fmt.Errorf("custom rules must contain strings")
		}
	}
	fields := document.Content[0].Content
	var rules *yaml.Node
	for i := 0; i < len(fields); i += 2 {
		if fields[i].Value == "rules" {
			rules = fields[i+1]
		}
	}
	rules.Content = append(additions.Content[0].Content, rules.Content...)
	var output bytes.Buffer
	encoder := yaml.NewEncoder(&output)
	encoder.SetIndent(2)
	if err := encoder.Encode(&document); err != nil {
		return "", err
	}
	return output.String(), nil
}

// Validate reports whether a template is a single mapping with one rules sequence.
// It lets the panel reject a broken template at save time instead of at subscription time.
func Validate(base string) error {
	var document yaml.Node
	if err := yaml.Unmarshal([]byte(base), &document); err != nil {
		return fmt.Errorf("invalid base rule template: %w", err)
	}
	if len(document.Content) != 1 || document.Content[0].Kind != yaml.MappingNode {
		return fmt.Errorf("base rule template must be a mapping")
	}
	fields := document.Content[0].Content
	var rules *yaml.Node
	for i := 0; i+1 < len(fields); i += 2 {
		if fields[i].Value == "rules" {
			if rules != nil || fields[i+1].Kind != yaml.SequenceNode {
				return fmt.Errorf("base template must have one rules sequence")
			}
			rules = fields[i+1]
		}
	}
	if rules == nil {
		return fmt.Errorf("base template is missing its rules sequence")
	}
	for _, item := range rules.Content {
		if item.Kind != yaml.ScalarNode || item.Tag != "!!str" {
			return fmt.Errorf("rules must contain strings")
		}
	}
	return nil
}
