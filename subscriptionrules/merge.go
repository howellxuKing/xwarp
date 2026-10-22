// Package subscriptionrules merges administrator rules without changing node credentials.
package subscriptionrules

import (
	"bytes"
	"fmt"
	"strings"

	"gopkg.in/yaml.v3"
)

// Prepend inserts custom rule items into the base rules sequence, preserving other fields.
// An empty custom list leaves the administrator's template byte-for-byte unchanged.
func Prepend(base, custom string) (string, error) {
	if strings.TrimSpace(custom) == "" {
		return base, nil
	}
	var document, additions yaml.Node
	if err := yaml.Unmarshal([]byte(base), &document); err != nil {
		return "", fmt.Errorf("invalid base rule template: %w", err)
	}
	if err := yaml.Unmarshal([]byte(custom), &additions); err != nil {
		return "", fmt.Errorf("invalid custom rule list: %w", err)
	}
	if len(document.Content) != 1 || document.Content[0].Kind != yaml.MappingNode {
		return "", fmt.Errorf("base rule template must be a mapping")
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
			if rules != nil || fields[i+1].Kind != yaml.SequenceNode {
				return "", fmt.Errorf("base template must have one rules sequence")
			}
			rules = fields[i+1]
		}
	}
	if rules == nil {
		return "", fmt.Errorf("base template is missing its rules sequence")
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
