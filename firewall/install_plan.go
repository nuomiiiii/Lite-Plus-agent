package firewall

type nftInstallStep struct {
	Name string
	Args []string
	Env  []string
}

func nftablesInstallPlan(has func(string) bool) []nftInstallStep {
	debianEnv := []string{"DEBIAN_FRONTEND=noninteractive", "APT_LISTCHANGES_FRONTEND=none"}
	switch {
	case has("apt-get"):
		return []nftInstallStep{
			{Name: "apt-get", Args: []string{"update", "-y"}, Env: debianEnv},
			{Name: "apt-get", Args: []string{"install", "-y", "nftables"}, Env: debianEnv},
		}
	case has("dnf"):
		return []nftInstallStep{{Name: "dnf", Args: []string{"install", "-y", "nftables"}}}
	case has("yum"):
		return []nftInstallStep{{Name: "yum", Args: []string{"install", "-y", "nftables"}}}
	case has("zypper"):
		return []nftInstallStep{{Name: "zypper", Args: []string{"--non-interactive", "install", "nftables"}}}
	case has("apk"):
		return []nftInstallStep{{Name: "apk", Args: []string{"add", "nftables"}}}
	case has("pacman"):
		return []nftInstallStep{{Name: "pacman", Args: []string{"-Sy", "--noconfirm", "nftables"}}}
	default:
		return nil
	}
}
