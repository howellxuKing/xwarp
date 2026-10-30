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

// Compose builds the rule list served to clients: the critical must-proxy exceptions first,
// then the administrator's custom domains, then the template itself.
//
// Order matters, because the first matching rule wins. Prepending the critical block last keeps
// YouTube, Google and GitHub on the proxy even when the template was imported from a third-party
// rule project that sends them direct.
func Compose(base, custom, critical string) (string, error) {
	merged, err := Prepend(base, custom)
	if err != nil {
		return "", err
	}
	return Prepend(merged, critical)
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
	return nil
}
