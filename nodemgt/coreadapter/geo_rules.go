package coreadapter

import (
	"encoding/json"
	"path/filepath"
	"sort"
	"strings"
)

var geoAssetDir string

func SetGeoAssetDir(dir string) {
	geoAssetDir = dir
}

type geoMatch struct {
	Geosite []string
	Suffix  []string
	Exact   []string
	Keyword []string
	Regex   []string
	GeoIP   []string
	Private bool
	CIDRs   []string
}

func CollectGeo(routes []RouteSpec) (geosite, geoip []string) {
	sites := map[string]struct{}{}
	ips := map[string]struct{}{}
	for _, row := range routes {
		if !row.Enabled {
			continue
		}
		m := parseGeoMatch(routeDomainIP(row.RuleJSON))
		for _, code := range m.Geosite {
			sites[code] = struct{}{}
		}
		if m.Private {
			ips["private"] = struct{}{}
		}
		for _, code := range m.GeoIP {
			ips[code] = struct{}{}
		}
	}
	return uniqueCodes(sites), uniqueCodes(ips)
}

func routeDomainIP(ruleJSON string) (domains, ips []string) {
	var s struct {
		Domain string `json:"domain"`
		IP     string `json:"ip"`
	}
	_ = json.Unmarshal([]byte(ruleJSON), &s)
	return splitCSV(s.Domain), splitCSV(s.IP)
}

func parseGeoMatch(domains, ips []string) geoMatch {
	var m geoMatch
	for _, token := range domains {
		kind, code, ok := cutGeoPrefix(token)
		if ok && kind == "geosite" && code != "" {
			m.Geosite = append(m.Geosite, strings.ToLower(code))
			continue
		}
		prefix, rest, ok := cutMatchPrefix(token)
		switch {
		case ok && prefix == "full" && rest != "":
			m.Exact = append(m.Exact, rest)
		case ok && prefix == "keyword" && rest != "":
			m.Keyword = append(m.Keyword, rest)
		case ok && (prefix == "regexp" || prefix == "regex") && rest != "":
			m.Regex = append(m.Regex, rest)
		case ok && prefix == "domain" && rest != "":
			m.Suffix = append(m.Suffix, rest)
		default:
			if token != "" {
				m.Suffix = append(m.Suffix, token)
			}
		}
	}
	for _, token := range ips {
		kind, code, ok := cutGeoPrefix(token)
		if ok && kind == "geoip" && code != "" {
			code = strings.ToLower(code)
			if code == "private" {
				m.Private = true
				continue
			}
			m.GeoIP = append(m.GeoIP, code)
			continue
		}
		m.CIDRs = append(m.CIDRs, token)
	}
	return m
}

func cutGeoPrefix(token string) (kind, code string, ok bool) {
	token = strings.TrimSpace(token)
	lower := strings.ToLower(token)
	for _, prefix := range []string{"geosite:", "geoip:"} {
		if strings.HasPrefix(lower, prefix) {
			return strings.TrimSuffix(prefix, ":"), strings.TrimSpace(token[len(prefix):]), true
		}
	}
	return "", "", false
}

func cutMatchPrefix(token string) (prefix, rest string, ok bool) {
	token = strings.TrimSpace(token)
	i := strings.IndexByte(token, ':')
	if i <= 0 {
		return "", token, false
	}
	prefix = strings.ToLower(token[:i])
	switch prefix {
	case "full", "keyword", "regexp", "regex", "domain":
		return prefix, strings.TrimSpace(token[i+1:]), true
	}
	return "", token, false
}

func uniqueCodes(set map[string]struct{}) []string {
	out := make([]string, 0, len(set))
	for code := range set {
		out = append(out, code)
	}
	sort.Strings(out)
	return out
}

func inboundAliasTags(id string, aliases map[string][]string) []string {
	id = strings.TrimSpace(id)
	if id == "" {
		return nil
	}
	if tags := aliases[id]; len(tags) > 0 {
		return append([]string(nil), tags...)
	}
	return []string{id}
}

func geoRuleSetTag(kind, code string) string {
	return kind + "-" + code
}

func geoRuleSetPath(kind, code string) string {
	name := geoRuleSetTag(kind, code) + ".srs"
	if geoAssetDir == "" {
		return name
	}
	return filepath.Join(geoAssetDir, name)
}

func singBoxRuleSets(routes []RouteSpec) []map[string]any {
	geosite, geoip := CollectGeo(routes)
	var out []map[string]any
	seen := map[string]struct{}{}
	add := func(kind, code string) {
		if strings.EqualFold(code, "private") {
			return
		}
		tag := geoRuleSetTag(kind, code)
		if _, ok := seen[tag]; ok {
			return
		}
		seen[tag] = struct{}{}
		out = append(out, map[string]any{
			"type":   "local",
			"tag":    tag,
			"format": "binary",
			"path":   geoRuleSetPath(kind, code),
		})
	}
	for _, code := range geosite {
		add("geosite", code)
	}
	for _, code := range geoip {
		add("geoip", code)
	}
	return out
}

func mergeSingBoxGeo(item map[string]any, m geoMatch) map[string]any {
	var domainParts []map[string]any
	if tags := geoRuleSetTags("geosite", m.Geosite); len(tags) > 0 {
		domainParts = append(domainParts, map[string]any{"rule_set": tags})
	}
	if len(m.Suffix) > 0 {
		domainParts = append(domainParts, map[string]any{"domain_suffix": m.Suffix})
	}
	if len(m.Exact) > 0 {
		domainParts = append(domainParts, map[string]any{"domain": m.Exact})
	}
	if len(m.Keyword) > 0 {
		domainParts = append(domainParts, map[string]any{"domain_keyword": m.Keyword})
	}
	if len(m.Regex) > 0 {
		domainParts = append(domainParts, map[string]any{"domain_regex": m.Regex})
	}
	var ipParts []map[string]any
	if m.Private {
		ipParts = append(ipParts, map[string]any{"ip_is_private": true})
	}
	if tags := geoRuleSetTags("geoip", m.GeoIP); len(tags) > 0 {
		ipParts = append(ipParts, map[string]any{"rule_set": tags})
	}
	if len(m.CIDRs) > 0 {
		ipParts = append(ipParts, map[string]any{"ip_cidr": m.CIDRs})
	}
	groups := make([]map[string]any, 0, 3)
	if g := flattenOR(domainParts); g != nil {
		groups = append(groups, g)
	}
	if g := flattenOR(ipParts); g != nil {
		groups = append(groups, g)
	}
	outbound, hasOutbound := item["outbound"]
	rest := map[string]any{}
	for k, v := range item {
		if k == "outbound" {
			continue
		}
		rest[k] = v
	}
	if len(rest) > 0 {
		groups = append(groups, rest)
	}
	merged := flattenAND(groups)
	if merged == nil {
		merged = map[string]any{}
	}
	if hasOutbound {
		merged["outbound"] = outbound
	}
	return merged
}

func geoRuleSetTags(kind string, codes []string) []string {
	if len(codes) == 0 {
		return nil
	}
	tags := make([]string, 0, len(codes))
	for _, code := range codes {
		tags = append(tags, geoRuleSetTag(kind, code))
	}
	return tags
}

func flattenOR(parts []map[string]any) map[string]any {
	switch len(parts) {
	case 0:
		return nil
	case 1:
		return parts[0]
	default:
		return map[string]any{"type": "logical", "mode": "or", "rules": parts}
	}
}

func flattenAND(parts []map[string]any) map[string]any {
	switch len(parts) {
	case 0:
		return map[string]any{}
	case 1:
		return parts[0]
	default:
		if merged, ok := mergeFlat(parts); ok {
			return merged
		}
		return map[string]any{"type": "logical", "mode": "and", "rules": parts}
	}
}

func mergeFlat(parts []map[string]any) (map[string]any, bool) {
	out := map[string]any{}
	for _, part := range parts {
		if _, ok := part["type"]; ok {
			return nil, false
		}
		for k, v := range part {
			if _, exists := out[k]; exists {
				return nil, false
			}
			out[k] = v
		}
	}
	return out, true
}
