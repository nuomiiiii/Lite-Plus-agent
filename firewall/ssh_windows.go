//go:build windows

package firewall

import (
	"fmt"
	"os"
	"path/filepath"
	"time"
)

type sshFileSnap struct {
	path    string
	data    []byte
	existed bool
}

func windowsSSHConfigPath() string {
	base := os.Getenv("ProgramData")
	if base == "" {
		base = `C:\ProgramData`
	}
	return filepath.Join(base, "ssh", "sshd_config")
}

func detectedSSHPort() string {
	return pickDetectedSSHPort(nil, windowsSSHConfigPorts(), windowsSSHDPresent())
}

func windowsSSHDPresent() bool {
	if lookPath("sshd") {
		return true
	}
	if _, err := os.Stat(windowsSSHConfigPath()); err == nil {
		return true
	}
	if _, err := runCmd(cmdTimeout, "sc", "query", "sshd"); err == nil {
		return true
	}
	return false
}

func windowsSSHConfigPorts() []string {
	raw, err := os.ReadFile(windowsSSHConfigPath())
	if err != nil {
		return nil
	}
	return parseSSHConfigPorts(string(raw))
}

func snapshotSSHConfigs() []sshFileSnap {
	path := windowsSSHConfigPath()
	snap := sshFileSnap{path: path}
	if raw, err := os.ReadFile(path); err == nil {
		snap.existed = true
		snap.data = raw
	}
	return []sshFileSnap{snap}
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
	if detectedSSHPort() == port {
		return nil
	}
	if !windowsSSHDPresent() {
		return fmt.Errorf("本机没有 OpenSSH，无法改 SSH 监听端口")
	}
	path := windowsSSHConfigPath()
	current, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("读取 sshd_config: %w", err)
	}
	if err := os.WriteFile(path, []byte(rewriteSSHConfigPort(string(current), port)), 0o644); err != nil {
		return err
	}
	if err := reloadSSH(); err != nil {
		return err
	}
	return nil
}

func reloadSSH() error {
	if _, err := runCmd(15*time.Second, "powershell", "-NoProfile", "-Command", "Restart-Service -Name sshd -Force"); err == nil {
		return nil
	}
	if _, err := runCmd(15*time.Second, "net", "stop", "sshd"); err == nil {
		if _, startErr := runCmd(15*time.Second, "net", "start", "sshd"); startErr == nil {
			return nil
		}
	}
	return fmt.Errorf("无法重载 OpenSSH")
}
