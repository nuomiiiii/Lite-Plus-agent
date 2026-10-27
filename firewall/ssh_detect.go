package firewall

import (
	"path/filepath"
	"strings"
)

const plusSSHDropin = "99-lite-plus-port.conf"

func parseSSHConfigPorts(text string) []string {
	var ports []string
	inMatch := false
	for _, raw := range strings.Split(text, "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if i := strings.IndexAny(line, "#"); i >= 0 {
			line = strings.TrimSpace(line[:i])
			if line == "" {
				continue
			}
		}
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		key := strings.ToLower(fields[0])
		if key == "match" {
			inMatch = true
			continue
		}
		if inMatch {
			continue
		}
		if key != "port" || len(fields) < 2 {
			continue
		}
		if port := keepPort(fields[1]); port != "" {
			ports = append(ports, port)
		}
	}
	return ports
}

func parseSSHConfigIncludes(text, dir string) []string {
	var paths []string
	for _, raw := range strings.Split(text, "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if i := strings.IndexAny(line, "#"); i >= 0 {
			line = strings.TrimSpace(line[:i])
		}
		fields := strings.Fields(line)
		if len(fields) < 2 || !strings.EqualFold(fields[0], "include") {
			continue
		}
		pattern := fields[1]
		if !sshIncludeAbs(pattern) {
			pattern = filepath.ToSlash(filepath.Join(dir, pattern))
		}
		paths = append(paths, pattern)
	}
	return paths
}

func sshIncludeAbs(pattern string) bool {
	pattern = strings.ReplaceAll(pattern, "\\", "/")
	return strings.HasPrefix(pattern, "/") || filepath.IsAbs(pattern)
}

func sshConfigIncludesDropins(text string) bool {
	for _, pattern := range parseSSHConfigIncludes(text, "/etc/ssh") {
		if strings.Contains(strings.ToLower(pattern), "sshd_config.d") {
			return true
		}
	}
	return false
}

func parseSSHListenPorts(text string) []string {
	var ports []string
	for _, raw := range strings.Split(text, "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || !sshListenLine(line) {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 4 {
			continue
		}
		addr := fields[3]
		if strings.EqualFold(fields[0], "tcp") || strings.EqualFold(fields[0], "tcp6") {
			if len(fields) < 4 {
				continue
			}
			addr = fields[3]
		}
		if strings.Contains(addr, "Local") {
			continue
		}
		if port := listenAddrPort(addr); port != "" {
			ports = append(ports, port)
		}
	}
	return uniqueSSHPorts(ports)
}

func sshListenLine(line string) bool {
	lower := strings.ToLower(line)
	if !strings.Contains(lower, "sshd") {
		return false
	}
	if strings.Contains(lower, "ssh-agent") || strings.Contains(lower, "sshd-session") {
		return false
	}
	return strings.Contains(lower, "listen") || strings.HasPrefix(lower, "tcp")
}

func listenAddrPort(addr string) string {
	addr = strings.TrimSpace(addr)
	addr = strings.Trim(addr, "[]")
	if i := strings.LastIndex(addr, ":"); i >= 0 && i+1 < len(addr) {
		return keepPort(addr[i+1:])
	}
	return ""
}

func uniqueSSHPorts(in []string) []string {
	seen := map[string]struct{}{}
	out := make([]string, 0, len(in))
	for _, raw := range in {
		port := keepPort(raw)
		if port == "" {
			continue
		}
		if _, ok := seen[port]; ok {
			continue
		}
		seen[port] = struct{}{}
		out = append(out, port)
	}
	return out
}

func preferSSHPort(ports []string) string {
	ports = uniqueSSHPorts(ports)
	if len(ports) == 0 {
		return ""
	}
	for _, port := range ports {
		if port != "22" {
			return port
		}
	}
	return ports[0]
}

func pickDetectedSSHPort(listening, configured []string, sshdPresent bool) string {
	if port := preferSSHPort(listening); port != "" {
		return port
	}
	if port := preferSSHPort(configured); port != "" {
		return port
	}
	if sshdPresent {
		return "22"
	}
	return ""
}

func commentSSHPortLines(text string) string {
	lines := strings.Split(text, "\n")
	inMatch := false
	for i, raw := range lines {
		trim := strings.TrimSpace(raw)
		if trim == "" {
			continue
		}
		if strings.HasPrefix(trim, "#") {
			continue
		}
		fields := strings.Fields(trim)
		if len(fields) == 0 {
			continue
		}
		key := strings.ToLower(fields[0])
		if key == "match" {
			inMatch = true
			continue
		}
		if inMatch {
			continue
		}
		if key != "port" {
			continue
		}
		indent := raw[:len(raw)-len(strings.TrimLeft(raw, " \t"))]
		lines[i] = indent + "# " + trim
	}
	return strings.Join(lines, "\n")
}

func rewriteSSHConfigPort(text, port string) string {
	port = keepPort(port)
	if port == "" {
		return text
	}
	out := strings.TrimRight(commentSSHPortLines(text), "\r\n")
	if out != "" {
		out += "\n"
	}
	return out + "Port " + port + "\n"
}

func plusSSHDropinBody(port string) string {
	return "# Managed by Lite Plus.\nPort " + port + "\n"
}
