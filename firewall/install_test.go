package firewall

import (
	"os"
	"strings"
	"testing"
)

func TestNftablesInstallDoesNotEnableDistroService(t *testing.T) {
	src, err := os.ReadFile("install_linux.go")
	if err != nil {
		t.Fatal(err)
	}
	text := string(src)
	if !strings.Contains(text, `"systemctl", "disable", "--now", "nftables"`) {
		t.Fatal("installing nftables must disable distro nftables.service so its policy drop cannot shadow Plus allows")
	}
	if !strings.Contains(text, "suppressServiceStart(") || !strings.Contains(text, "policy-rc.d") {
		t.Fatal("Debian apt install must block nftables.service from starting mid-install")
	}
	if strings.Contains(text, `"enable"`) {
		t.Fatal("installing nftables must not enable nftables.service")
	}
}

func TestNftablesInstallPlanPicksPackageManager(t *testing.T) {
	got := nftablesInstallPlan(func(name string) bool { return name == "apt-get" })
	if len(got) != 2 || got[1].Name != "apt-get" || got[1].Args[len(got[1].Args)-1] != "nftables" {
		t.Fatalf("apt plan: %+v", got)
	}
	env := strings.Join(got[0].Env, " ")
	if !strings.Contains(env, "DEBIAN_FRONTEND=noninteractive") || !strings.Contains(env, "NEEDRESTART_SUSPEND=1") {
		t.Fatalf("apt env must skip needrestart prompts: %+v", got[0].Env)
	}
	got = nftablesInstallPlan(func(name string) bool { return name == "dnf" })
	if len(got) != 1 || got[0].Name != "dnf" {
		t.Fatalf("dnf plan: %+v", got)
	}
	got = nftablesInstallPlan(func(name string) bool { return name == "apk" })
	if len(got) != 2 || got[0].Args[0] != "update" || got[1].Args[len(got[1].Args)-1] != "nftables" {
		t.Fatalf("apk plan: %+v", got)
	}
	got = nftablesInstallPlan(func(name string) bool { return name == "opkg" })
	if len(got) != 2 || got[1].Name != "opkg" {
		t.Fatalf("opkg plan: %+v", got)
	}
	if plan := nftablesInstallPlan(func(string) bool { return false }); plan != nil {
		t.Fatalf("empty plan: %+v", plan)
	}
}

func TestFirewallCommandsSearchSbin(t *testing.T) {
	src, err := os.ReadFile("exec.go")
	if err != nil {
		t.Fatal(err)
	}
	text := string(src)
	if !strings.Contains(text, "/usr/sbin") || !strings.Contains(text, "func resolveCmd(") {
		t.Fatal("nft after apt install lives in /usr/sbin; firewall commands must search sbin even if PATH is short")
	}
}
