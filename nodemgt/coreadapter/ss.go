package coreadapter

import (
	"crypto/sha256"
	"encoding/base64"
	"strings"
)

func ssMethod(in InboundSpec) string {
	method := strings.ToLower(strings.TrimSpace(settingString(in.SettingsJSON, "ss_method")))
	if method == "" {
		return "2022-blake3-aes-128-gcm"
	}
	return method
}

func ss2022Method(method string) bool {
	return strings.HasPrefix(strings.ToLower(strings.TrimSpace(method)), "2022-")
}

func ss2022KeyBytes(method string) int {
	if strings.Contains(strings.ToLower(method), "256") {
		return 32
	}
	return 16
}

func ss2022Key(secret, method string) string {
	secret = strings.TrimSpace(secret)
	n := ss2022KeyBytes(method)
	if raw, err := base64.StdEncoding.DecodeString(secret); err == nil && len(raw) == n {
		return secret
	}
	sum := sha256.Sum256([]byte(secret))
	return base64.StdEncoding.EncodeToString(sum[:n])
}

func ssServerKey(in InboundSpec, method string) string {
	if key := strings.TrimSpace(settingString(in.SettingsJSON, "ss_password")); key != "" {
		return ss2022Key(key, method)
	}
	return ss2022Key("ss-server:"+strings.TrimSpace(in.ID), method)
}

func ssUserPassword(u UserSpec) (string, bool) {
	pass := strings.TrimSpace(u.Password)
	if pass == "" {
		pass = strings.TrimSpace(u.UUID)
	}
	if pass == "" {
		return "", false
	}
	return pass, true
}

func ssXrayClients(in InboundSpec, granted []UserSpec) (method string, settings map[string]any, ok bool) {
	method = ssMethod(in)
	if ss2022Method(method) {
		users := make([]map[string]string, 0, len(granted))
		for _, u := range granted {
			pass, has := ssUserPassword(u)
			if !has {
				continue
			}
			users = append(users, map[string]string{
				"password": ss2022Key(pass, method),
				"email":    u.ID,
			})
		}
		if len(users) == 0 {
			return method, nil, false
		}
		return method, map[string]any{
			"method":   method,
			"password": ssServerKey(in, method),
			"clients":  users,
			"network":  "tcp,udp",
		}, true
	}
	users := make([]map[string]string, 0, len(granted))
	for _, u := range granted {
		pass, has := ssUserPassword(u)
		if !has {
			continue
		}
		users = append(users, map[string]string{"password": pass, "email": u.ID, "method": method})
	}
	if len(users) == 0 {
		return method, nil, false
	}
	return method, map[string]any{"clients": users, "network": "tcp,udp"}, true
}

func ssSingBoxInbound(in InboundSpec, granted []UserSpec) (map[string]any, bool) {
	method := ssMethod(in)
	users := make([]map[string]string, 0, len(granted))
	for _, u := range granted {
		pass, has := ssUserPassword(u)
		if !has {
			continue
		}
		if ss2022Method(method) {
			pass = ss2022Key(pass, method)
		}
		users = append(users, map[string]string{"name": u.ID, "password": pass})
	}
	if len(users) == 0 {
		return nil, false
	}
	item := map[string]any{"method": method, "users": users}
	if ss2022Method(method) {
		item["password"] = ssServerKey(in, method)
	}
	return item, true
}
