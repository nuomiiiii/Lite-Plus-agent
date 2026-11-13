package protection

import (
	"fmt"
	"net/url"
	"strings"
)

func NormalizePath(uri string) (string, error) {
	raw := strings.TrimSpace(uri)
	if raw == "" {
		return "/", nil
	}
	if i := strings.IndexAny(raw, "?#"); i >= 0 {
		raw = raw[:i]
	}
	unescaped, err := url.PathUnescape(raw)
	if err != nil {
		return "", fmt.Errorf("path decode: %w", err)
	}
	if unescaped == "" {
		return "/", nil
	}
	if !strings.HasPrefix(unescaped, "/") {
		unescaped = "/" + unescaped
	}
	return unescaped, nil
}

func PathMatches(path string, rules []string) bool {
	if path == "" || len(rules) == 0 {
		return false
	}
	for _, rule := range rules {
		rule = strings.TrimSpace(rule)
		if rule == "" {
			continue
		}
		if strings.HasSuffix(rule, "/") && rule != "/" {
			if path == strings.TrimSuffix(rule, "/") || strings.HasPrefix(path, rule) {
				return true
			}
			continue
		}
		if path == rule {
			return true
		}
	}
	return false
}
