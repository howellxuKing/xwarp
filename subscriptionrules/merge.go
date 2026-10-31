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
			if !seen[item.Value] {
				seen[item.Value] = true
				items = append(items, item)
			}
		}
		fields[i+1].Content = items
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
