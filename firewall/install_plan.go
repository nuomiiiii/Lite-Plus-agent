package firewall

type nftInstallStep struct {
	Name string
	Args []string
	Env  []string
}

func nftablesInstallPlan(has func(string) bool) []nftInstallStep {
	debianEnv := []string{
		"DEBIAN_FRONTEND=noninteractive",
		"APT_LISTCHANGES_FRONTEND=none",
		"NEEDRESTART_MODE=a",
		"NEEDRESTART_SUSPEND=1",
		"UCF_FORCE_CONFFOLD=1",
		"DEBIAN_PRIORITY=critical",
	}
	switch {
	case has("apt-get"):
		return []nftInstallStep{
			{Name: "apt-get", Args: []string{"update", "-y"}, Env: debianEnv},
			{Name: "apt-get", Args: []string{"install", "-y", "-o", "Dpkg::Options::=--force-confdef", "-o", "Dpkg::Options::=--force-confold", "nftables"}, Env: debianEnv},
		}
	case has("dnf"):
		return []nftInstallStep{{Name: "dnf", Args: []string{"install", "-y", "nftables"}}}
	case has("yum"):
		return []nftInstallStep{{Name: "yum", Args: []string{"install", "-y", "nftables"}}}
	case has("zypper"):
		return []nftInstallStep{{Name: "zypper", Args: []string{"--non-interactive", "install", "--auto-agree-with-licenses", "nftables"}}}
	case has("apk"):
		return []nftInstallStep{
			{Name: "apk", Args: []string{"update"}},
			{Name: "apk", Args: []string{"add", "nftables"}},
		}
	case has("opkg"):
		return []nftInstallStep{
			{Name: "opkg", Args: []string{"update"}},
			{Name: "opkg", Args: []string{"install", "nftables"}},
		}
	case has("pacman"):
		return []nftInstallStep{{Name: "pacman", Args: []string{"-Sy", "--noconfirm", "nftables"}}}
	default:
		return nil
	}
}
