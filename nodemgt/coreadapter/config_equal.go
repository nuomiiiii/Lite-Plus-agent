package coreadapter

import (
	"sort"
	"strconv"
	"strings"
)

func inboundSpecsEqual(a, b []InboundSpec) bool {
	if len(a) != len(b) {
		return false
	}
	left := append([]InboundSpec(nil), a...)
	right := append([]InboundSpec(nil), b...)
	sort.Slice(left, func(i, j int) bool { return inboundSpecKey(left[i]) < inboundSpecKey(left[j]) })
	sort.Slice(right, func(i, j int) bool { return inboundSpecKey(right[i]) < inboundSpecKey(right[j]) })
	for i := range left {
		if inboundSpecKey(left[i]) != inboundSpecKey(right[i]) {
			return false
		}
	}
	return true
}

func inboundSpecKey(in InboundSpec) string {
	return strings.Join([]string{
		in.ID, in.Core, in.Listen, strconv.Itoa(in.Port), in.Protocol,
		in.StreamJSON, in.SettingsJSON, in.CertPEM, in.KeyPEM, in.Flow,
	}, "\x00")
}

func userAuthEqual(a, b []UserSpec) bool {
	if len(a) != len(b) {
		return false
	}
	left := append([]UserSpec(nil), a...)
	right := append([]UserSpec(nil), b...)
	sort.Slice(left, func(i, j int) bool { return left[i].ID < left[j].ID })
	sort.Slice(right, func(i, j int) bool { return right[i].ID < right[j].ID })
	for i := range left {
		if userAuthKey(left[i]) != userAuthKey(right[i]) {
			return false
		}
	}
	return true
}

func userAuthKey(u UserSpec) string {
	ids := append([]string(nil), u.InboundIDs...)
	sort.Strings(ids)
	return strings.Join([]string{
		u.ID, u.UUID, u.Username, u.Password, u.Flow,
		strconv.FormatBool(u.Disabled), strconv.FormatBool(u.Expired),
		strconv.FormatBool(quotaExhausted(u)),
		strings.Join(ids, ","),
	}, "\x00")
}

func quotaExhausted(u UserSpec) bool {
	return u.QuotaBytes > 0 && u.UsedBytes >= u.QuotaBytes
}

func outboundSpecsEqual(a, b []OutboundSpec) bool {
	if len(a) != len(b) {
		return false
	}
	left := append([]OutboundSpec(nil), a...)
	right := append([]OutboundSpec(nil), b...)
	sort.Slice(left, func(i, j int) bool { return left[i].ID < left[j].ID })
	sort.Slice(right, func(i, j int) bool { return right[i].ID < right[j].ID })
	for i := range left {
		if outboundSpecKey(left[i]) != outboundSpecKey(right[i]) {
			return false
		}
	}
	return true
}

func outboundSpecKey(o OutboundSpec) string {
	return strings.Join([]string{o.ID, o.Protocol, o.SettingsJSON, strconv.FormatBool(o.Enabled)}, "\x00")
}

func routeSpecsEqual(a, b []RouteSpec) bool {
	if len(a) != len(b) {
		return false
	}
	left := append([]RouteSpec(nil), a...)
	right := append([]RouteSpec(nil), b...)
	sort.Slice(left, func(i, j int) bool { return left[i].ID < left[j].ID })
	sort.Slice(right, func(i, j int) bool { return right[i].ID < right[j].ID })
	for i := range left {
		if routeSpecKey(left[i]) != routeSpecKey(right[i]) {
			return false
		}
	}
	return true
}

func routeSpecKey(r RouteSpec) string {
	return strings.Join([]string{r.ID, strconv.Itoa(r.Priority), r.RuleJSON, strconv.FormatBool(r.Enabled)}, "\x00")
}

func coreShouldRestart(running bool, in, lastIn []InboundSpec, users, lastUsers []UserSpec, out, lastOut []OutboundSpec, rt, lastRt []RouteSpec) bool {
	same := inboundSpecsEqual(in, lastIn) && userAuthEqual(users, lastUsers) && outboundSpecsEqual(out, lastOut) && routeSpecsEqual(rt, lastRt)
	if same {
		return !running && len(in) > 0
	}
	if !running && len(in) == 0 {
		return false
	}
	return true
}
