//go:build linux

package firewall

import (
	"fmt"
	"time"

	v2 "github.com/nuomiiiii/lite-agent/protocol/v2"
)

const nftInstallTimeout = 4 * time.Minute

func canInstallNftables() bool {
	if !privileged() {
		return false
	}
	if ufwActive() || firewalldActive() {
		return false
	}
	return !lookPath("nft") && !lookPath("iptables")
}

func installNftables() v2.FirewallResultParams {
	result := currentBackend().snapshot()
	result.Kind = v2.FirewallKindInstall
	if !privileged() {
		result.Status = v2.FirewallStatusUnsupported
		result.Error = "Agent 需要 root 或 CAP_NET_ADMIN 才能安装 nftables"
		return result
	}
	if lookPath("nft") {
		result.Status = v2.FirewallStatusOK
		result.CanInstallNftables = false
		return withLiveBackend(result)
	}
	steps := nftablesInstallPlan(lookPath)
	if len(steps) == 0 {
		result.Status = v2.FirewallStatusError
		result.Error = "未找到 apt / dnf / yum / zypper / apk / pacman，请先手动安装 nftables"
		return result
	}
	for _, step := range steps {
		if _, err := runCmdEnv(nftInstallTimeout, step.Env, step.Name, step.Args...); err != nil {
			result.Status = v2.FirewallStatusError
			result.Error = fmt.Sprintf("安装 nftables 失败: %v", err)
			return result
		}
	}
	if lookPath("systemctl") {
		_, _ = runCmd(cmdTimeout, "systemctl", "disable", "--now", "nftables")
	}
	if !lookPath("nft") {
		result.Status = v2.FirewallStatusError
		result.Error = "已尝试安装 nftables，但仍找不到 nft 命令"
		return result
	}
	result.Status = v2.FirewallStatusOK
	result.Error = ""
	return withLiveBackend(result)
}

func withLiveBackend(result v2.FirewallResultParams) v2.FirewallResultParams {
	live := currentBackend().snapshot()
	live.Kind = result.Kind
	live.RequestID = result.RequestID
	live.CanInstallNftables = canInstallNftables()
	if live.Status == "" {
		live.Status = v2.FirewallStatusOK
	}
	return live
}
