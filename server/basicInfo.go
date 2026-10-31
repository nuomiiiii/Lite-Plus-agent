package server

import (
	"bytes"
	"context"
	"log"
	"net/http"
	"runtime"
	"strings"
	"time"

	monitoring "github.com/nuomiiiii/lite-agent/monitoring/unit"
	v2 "github.com/nuomiiiii/lite-agent/protocol/v2"
	"github.com/nuomiiiii/lite-agent/update"

	pkg_flags "github.com/nuomiiiii/lite-agent/cmd/flags"
)

const addressWatchEvery = 30 * time.Second

var flags = pkg_flags.GlobalConfig

var runtimeConfigStateUploadRequests = make(chan struct{}, 1)

func DoUploadBasicInfoWorks() {
	go watchHostAddresses()
	ticker := time.NewTicker(time.Duration(flags.InfoReportInterval) * time.Minute)
	defer ticker.Stop()
	for range ticker.C {
		err := uploadBasicInfo()
		if err != nil {
			log.Println("Error uploading basic info:", err)
		}
	}
}

func watchHostAddresses() {
	ticker := time.NewTicker(addressWatchEvery)
	defer ticker.Stop()
	var last4, last6 string
	for {
		next4, next6, _ := monitoring.GetIPAddress()
		if addressesChanged(last4, last6, next4, next6) {
			if err := uploadBasicInfo(); err != nil {
				log.Println("Error uploading address change:", err)
			} else {
				last4, last6 = next4, next6
			}
		}
		<-ticker.C
	}
}

func addressesChanged(prev4, prev6, next4, next6 string) bool {
	return strings.TrimSpace(prev4) != strings.TrimSpace(next4) || strings.TrimSpace(prev6) != strings.TrimSpace(next6)
}

func UpdateBasicInfo() {
	err := uploadBasicInfo()
	if err != nil {
		log.Println("Error uploading basic info:", err)
	} else {
		log.Println("Basic info uploaded successfully")
	}
}

func DoRuntimeConfigStateUploadWorks() {
	for range runtimeConfigStateUploadRequests {
		if err := uploadBasicInfo(); err != nil {
			log.Println("Error uploading runtime config state:", err)
			time.AfterFunc(5*time.Second, requestRuntimeConfigStateUpload)
		}
	}
}

func requestRuntimeConfigStateUpload() {
	select {
	case runtimeConfigStateUploadRequests <- struct{}{}:
	default:
	}
}

func uploadBasicInfo() error {
	return tryUploadData(buildBasicInfoMap())
}

func buildBasicInfoMap() map[string]interface{} {
	cpu := monitoring.CpuStaticInfo()

	osname := monitoring.CachedOSName()
	kernelVersion := monitoring.CachedKernelVersion()
	ipv4, ipv6, _ := monitoring.GetIPAddress()

	return map[string]interface{}{
		"cpu_name":               cpu.CPUName,
		"cpu_cores":              cpu.CPUCores,
		"cpu_physical_cores":     cpu.CPUPhysicalCores,
		"arch":                   cpu.CPUArchitecture,
		"os":                     osname,
		"kernel_version":         kernelVersion,
		"ipv4":                   ipv4,
		"ipv6":                   ipv6,
		"mem_total":              monitoring.Ram().Total,
		"swap_total":             monitoring.Swap().Total,
		"disk_total":             monitoring.Disk().Total,
		"gpu_name":               monitoring.CachedGpuName(),
		"virtualization":         monitoring.CachedVirtualized(),
		"version":                update.CurrentVersion,
		"remote_protocol":        2,
		"remote_control_enabled": pkg_flags.RemoteControlEnabled(),
		// mcp_full is advertised on pull, not basic info: 2.3.2 Lite updates
		// every map key as a column and would reject the whole report.
	}
}

func tryUploadData(data map[string]interface{}) error {
	return tryUploadDataV2(data)
}

func tryUploadDataV2(data map[string]interface{}) error {
	sentConfigResult := snapshotPendingConfigResult()
	payload := v2.BuildBasicInfoPayload(data, currentRuntimeConfigParams(), sentConfigResult, runtime.GOOS)
	status, respBody, err := postV2JSONRPC(context.Background(), payload, 30*time.Second)
	if err != nil {
		return err
	}
	message := string(respBody)
	if status != http.StatusOK {
		return &httpStatusError{StatusCode: status, Status: http.StatusText(status), Body: message}
	}
	if len(bytes.TrimSpace(respBody)) > 0 {
		if err := processBasicInfoResponse(respBody); err != nil {
			return err
		}
	}
	clearPendingConfigResult(sentConfigResult)
	return nil
}
