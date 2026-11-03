package coreadapter

import (
	"encoding/json"
	"strings"
)

const chainProbeURL = "https://www.gstatic.com/generate_204"

func chainGroupProtocol(proto string) bool {
	switch strings.ToLower(strings.TrimSpace(proto)) {
	case "urltest", "failover":
		return true
	default:
		return false
	}
}

type chainGroupSpec struct {
	Members      []string
	BackupDirect bool
	Fallback     bool
	Strategy     string
	Interval     string
}

func parseChainGroup(row OutboundSpec) chainGroupSpec {
	var settings map[string]any
	_ = json.Unmarshal([]byte(row.SettingsJSON), &settings)
	if settings == nil {
		settings = map[string]any{}
	}
	spec := chainGroupSpec{
		Members:      settingIDList(settings["member_ids"]),
		Strategy:     strings.ToLower(strings.TrimSpace(asString(settings["strategy"]))),
		Interval:     strings.TrimSpace(asString(settings["interval"])),
		BackupDirect: asBool(settings["backup_direct"]),
		Fallback:     asBool(settings["fallback_direct"]),
	}
	if spec.Strategy == "" {
		spec.Strategy = strings.ToLower(strings.TrimSpace(row.Protocol))
	}
	if spec.Interval == "" {
		spec.Interval = "1m"
	}
	return spec
}

func resolveMemberTags(ids []string, tags map[string]string) []string {
	out := make([]string, 0, len(ids))
	seen := map[string]struct{}{}
	for _, id := range ids {
		tag := strings.TrimSpace(id)
		if mapped := strings.TrimSpace(tags[id]); mapped != "" {
			tag = mapped
		}
		if tag == "" {
			continue
		}
		if _, ok := seen[tag]; ok {
			continue
		}
		seen[tag] = struct{}{}
		out = append(out, tag)
	}
	return out
}

func settingIDList(raw any) []string {
	switch v := raw.(type) {
	case []any:
		out := make([]string, 0, len(v))
		for _, item := range v {
			id := strings.TrimSpace(asString(item))
			if id != "" && id != "<nil>" {
				out = append(out, id)
			}
		}
		return out
	case []string:
		out := make([]string, 0, len(v))
		for _, id := range v {
			id = strings.TrimSpace(id)
			if id != "" {
				out = append(out, id)
			}
		}
		return out
	default:
		return nil
	}
}

func asString(v any) string {
	switch n := v.(type) {
	case string:
		return n
	default:
		return ""
	}
}

func asBool(v any) bool {
	switch n := v.(type) {
	case bool:
		return n
	case string:
		return strings.EqualFold(n, "true") || n == "1"
	default:
		return false
	}
}

func uniqueStrings(ids []string) []string {
	out := make([]string, 0, len(ids))
	seen := map[string]struct{}{}
	for _, id := range ids {
		id = strings.TrimSpace(id)
		if id == "" {
			continue
		}
		if _, ok := seen[id]; ok {
			continue
		}
		seen[id] = struct{}{}
		out = append(out, id)
	}
	return out
}
