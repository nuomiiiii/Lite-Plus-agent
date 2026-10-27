//go:build !linux && !windows

package firewall

type sshFileSnap struct {
	path    string
	data    []byte
	existed bool
}

func detectedSSHPort() string { return "" }

func snapshotSSHConfigs() []sshFileSnap { return nil }

func restoreSSHConfigs([]sshFileSnap) {}

func syncSSHListenPort(raw string) error {
	if keepPort(raw) == "" {
		return nil
	}
	return nil
}
