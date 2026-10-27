//go:build linux

package firewall

import (
	"fmt"
	"os"
	"path/filepath"
	"time"
)

const (
	linuxSSHConfig   = "/etc/ssh/sshd_config"
	linuxSSHDropinDir = "/etc/ssh/sshd_config.d"
)

type sshFileSnap struct {
	path    string
	data    []byte
	existed bool
}

func detectedSSHPort() string {
	return pickDetectedSSHPort(linuxSSHListenPorts(), linuxSSHConfigPorts(), linuxSSHDPresent())
}

func linuxSSHDPresent() bool {
	if lookPath("sshd") {
		return true
	}
	if _, err := os.Stat("/usr/sbin/sshd"); err == nil {
		return true
	}
	return false
}

func linuxSSHListenPorts() []string {
	if lookPath("ss") {
		if out, err := runCmd(cmdTimeout, "ss", "-ltnp"); err == nil {
			if ports := parseSSHListenPorts(out); len(ports) > 0 {
				return ports
			}
		}
	}
	if lookPath("netstat") {
		if out, err := runCmd(cmdTimeout, "netstat", "-ltnp"); err == nil {
			return parseSSHListenPorts(out)
		}
	}
	return nil
}

func linuxSSHConfigPorts() []string {
	var ports []string
	for _, path := range linuxSSHConfigFiles() {
		raw, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		ports = append(ports, parseSSHConfigPorts(string(raw))...)
	}
	return ports
}

func linuxSSHConfigFiles() []string {
	seen := map[string]struct{}{}
	var files []string
	add := func(path string) {
		path = filepath.Clean(path)
		if _, ok := seen[path]; ok {
			return
		}
		seen[path] = struct{}{}
		files = append(files, path)
	}
	add(linuxSSHConfig)
	raw, err := os.ReadFile(linuxSSHConfig)
	if err == nil {
		for _, pattern := range parseSSHConfigIncludes(string(raw), filepath.Dir(linuxSSHConfig)) {
			matches, _ := filepath.Glob(pattern)
			for _, match := range matches {
				add(match)
			}
		}
	}
	if matches, err := filepath.Glob(filepath.Join(linuxSSHDropinDir, "*.conf")); err == nil {
		for _, match := range matches {
			add(match)
		}
	}
	return files
}

func snapshotSSHConfigs() []sshFileSnap {
	paths := linuxSSHConfigFiles()
	plus := filepath.Join(linuxSSHDropinDir, plusSSHDropin)
	foundPlus := false
	out := make([]sshFileSnap, 0, len(paths)+1)
	for _, path := range paths {
		if filepath.Clean(path) == filepath.Clean(plus) {
			foundPlus = true
		}
		snap := sshFileSnap{path: path}
		raw, err := os.ReadFile(path)
		if err == nil {
			snap.existed = true
			snap.data = raw
		}
		out = append(out, snap)
	}
	if !foundPlus {
		snap := sshFileSnap{path: plus}
		if raw, err := os.ReadFile(plus); err == nil {
			snap.existed = true
			snap.data = raw
		}
		out = append(out, snap)
	}
	return out
}

func restoreSSHConfigs(snaps []sshFileSnap) {
	if len(snaps) == 0 {
		return
	}
	for _, snap := range snaps {
		if !snap.existed {
			_ = os.Remove(snap.path)
			continue
		}
		_ = os.WriteFile(snap.path, snap.data, 0o644)
	}
	_ = reloadSSH()
}

func syncSSHListenPort(raw string) error {
	port := keepPort(raw)
	if port == "" {
		return nil
	}
	if preferSSHPort(linuxSSHListenPorts()) == port {
		return nil
	}
	if detectedSSHPort() == port && preferSSHPort(linuxSSHConfigPorts()) == port {
		return nil
	}
	if !linuxSSHDPresent() {
		return fmt.Errorf("本机没有 sshd，无法改 SSH 监听端口")
	}
	if err := writeLinuxSSHPort(port); err != nil {
		return err
	}
	if err := testSSHConfig(); err != nil {
		return fmt.Errorf("sshd 配置检查失败: %w", err)
	}
	if err := reloadSSH(); err != nil {
		return err
	}
	return nil
}

func writeLinuxSSHPort(port string) error {
	files := linuxSSHConfigFiles()
	mainRaw, err := os.ReadFile(linuxSSHConfig)
	if err != nil {
		return fmt.Errorf("读取 sshd_config: %w", err)
	}
	useDropin := sshConfigIncludesDropins(string(mainRaw))
	if st, err := os.Stat(linuxSSHDropinDir); err != nil || !st.IsDir() {
		useDropin = false
	}
	for _, path := range files {
		raw, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		next := commentSSHPortLines(string(raw))
		if next == string(raw) {
			continue
		}
		if err := os.WriteFile(path, []byte(next), 0o644); err != nil {
			return err
		}
	}
	if useDropin {
		if err := os.MkdirAll(linuxSSHDropinDir, 0o755); err != nil {
			return err
		}
		return os.WriteFile(filepath.Join(linuxSSHDropinDir, plusSSHDropin), []byte(plusSSHDropinBody(port)), 0o644)
	}
	return os.WriteFile(linuxSSHConfig, []byte(rewriteSSHConfigPort(string(mainRaw), port)), 0o644)
}

func testSSHConfig() error {
	if lookPath("sshd") {
		_, err := runCmd(cmdTimeout, "sshd", "-t")
		return err
	}
	_, err := runCmd(cmdTimeout, "/usr/sbin/sshd", "-t")
	return err
}

func reloadSSH() error {
	if lookPath("systemctl") {
		if _, err := runCmd(15*time.Second, "systemctl", "reload", "ssh"); err == nil {
			return nil
		}
		if _, err := runCmd(15*time.Second, "systemctl", "reload", "sshd"); err == nil {
			return nil
		}
	}
	if lookPath("pkill") {
		if _, err := runCmd(cmdTimeout, "pkill", "-HUP", "-x", "sshd"); err == nil {
			return nil
		}
	}
	return fmt.Errorf("无法重载 sshd")
}
