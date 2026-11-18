package server

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"sync"
	"time"

	pkg_flags "github.com/nuomiiiii/lite-agent/cmd/flags"
	v2 "github.com/nuomiiiii/lite-agent/protocol/v2"
	"github.com/nuomiiiii/lite-agent/tasklog"
	"github.com/nuomiiiii/lite-agent/ws"
	ping "github.com/prometheus-community/pro-bing"
)

var execLog *tasklog.Log

var (
	recoverWorkerCount       = 4
	finishPersistMaxAttempts = 5
	recoverMaxBackoff        = 5 * time.Minute
)

type taskResultUploader func(taskID, result string, exitCode int, finishedAt time.Time, status string) bool

var (
	uploadTaskResultFn = defaultUploadTaskResult
	finishRetryDelay   func(attempt int) time.Duration
	recoveryMu         sync.Mutex
	recoveryStarted    bool
	recoverMinSleep    = time.Second
)

func SetTaskLog(store *tasklog.Log) {
	execLog = store
}

func StartTaskRecovery(ctx context.Context) {
	recoveryMu.Lock()
	defer recoveryMu.Unlock()
	if recoveryStarted || execLog == nil {
		return
	}
	recoveryStarted = true
	go recoverLoop(ctx, execLog)
}

func resetTaskRecoveryForTest() {
	recoveryMu.Lock()
	recoveryStarted = false
	recoveryMu.Unlock()
}

func recoverLoop(ctx context.Context, store *tasklog.Log) {
	if store == nil {
		return
	}
	backoff := recoverBackoff(0)
	for {
		if ctx.Err() != nil {
			return
		}
		if strings.TrimSpace(flags.Token) == "" {
			if !sleepCtx(ctx, backoff) {
				return
			}
			backoff = nextRecoverBackoff(backoff)
			continue
		}
		recoverPendingReportsWith(ctx, store, uploadTaskResult)
		if len(store.PendingReports()) == 0 {
			backoff = recoverBackoff(0)
		} else {
			backoff = nextRecoverBackoff(backoff)
		}
		if !sleepCtx(ctx, backoff) {
			return
		}
	}
}

func recoverBackoff(attempt int) time.Duration {
	delay := time.Duration(flags.ReconnectInterval) * time.Second
	if delay <= 0 {
		delay = recoverMinSleep
	}
	for i := 0; i < attempt; i++ {
		delay *= 2
		if delay > recoverMaxBackoff {
			return recoverMaxBackoff
		}
	}
	return delay
}

func nextRecoverBackoff(current time.Duration) time.Duration {
	if current <= 0 {
		return recoverBackoff(0)
	}
	next := current * 2
	if next > recoverMaxBackoff {
		return recoverMaxBackoff
	}
	return next
}

func sleepCtx(ctx context.Context, delay time.Duration) bool {
	if delay <= 0 {
		delay = time.Second
	}
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}

func recoverInterruptedTasksWith(store *tasklog.Log, upload taskResultUploader) {
	recoverPendingReportsWith(context.Background(), store, upload)
}

func recoverPendingReportsWith(ctx context.Context, store *tasklog.Log, upload taskResultUploader) {
	if store == nil || upload == nil {
		return
	}
	entries := store.PendingReports()
	if len(entries) == 0 {
		return
	}
	workers := recoverWorkerCount
	if workers < 2 {
		workers = 2
	}
	if workers > 4 {
		workers = 4
	}
	jobs := make(chan tasklog.Entry)
	var wg sync.WaitGroup
	wg.Add(workers)
	for i := 0; i < workers; i++ {
		go func() {
			defer wg.Done()
			for entry := range jobs {
				if ctx.Err() != nil {
					return
				}
				finishedAt := entry.FinishedAt
				if finishedAt.IsZero() {
					finishedAt = time.Now().UTC()
				}
				summary := entry.Summary
				status := v2.TaskResultStatusInterrupted
				if entry.State == tasklog.StateFinished {
					status = v2.TaskResultStatusFinished
				} else if summary == "" {
					summary = "execution status unknown"
				}
				if !upload(entry.TaskID, summary, entry.ExitCode, finishedAt, status) {
					continue
				}
				if err := store.Ack(entry.TaskID); err != nil {
					log.Printf("task log ack %s: %v", entry.TaskID, err)
				}
			}
		}()
	}
	for _, entry := range entries {
		select {
		case <-ctx.Done():
			close(jobs)
			wg.Wait()
			return
		case jobs <- entry:
		}
	}
	close(jobs)
	wg.Wait()
}

func acceptTask(taskID string) (run bool, ack bool) {
	if taskID == "" {
		return false, false
	}
	if execLog == nil {
		return true, true
	}
	entry, err := execLog.Begin(taskID)
	if err == nil {
		return true, true
	}
	if errors.Is(err, tasklog.ErrAlreadyFinished) {
		if !entry.Acked {
			finishedAt := entry.FinishedAt
			if finishedAt.IsZero() {
				finishedAt = time.Now().UTC()
			}
			if uploadTaskResult(taskID, entry.Summary, entry.ExitCode, finishedAt, v2.TaskResultStatusFinished) {
				if ackErr := execLog.Ack(taskID); ackErr != nil {
					log.Printf("task log ack %s: %v", taskID, ackErr)
				}
			}
		}
		return false, true
	}
	if errors.Is(err, tasklog.ErrAlreadyStarted) {
		return false, true
	}
	if errors.Is(err, tasklog.ErrInterrupted) {
		if !entry.Acked {
			summary := entry.Summary
			if summary == "" {
				summary = "execution status unknown"
			}
			finishedAt := entry.FinishedAt
			if finishedAt.IsZero() {
				finishedAt = time.Now().UTC()
			}
			if uploadTaskResult(taskID, summary, entry.ExitCode, finishedAt, v2.TaskResultStatusInterrupted) {
				if ackErr := execLog.Ack(taskID); ackErr != nil {
					log.Printf("task log ack %s: %v", taskID, ackErr)
				}
			}
		}
		return false, true
	}
	if errors.Is(err, tasklog.ErrLogFull) {
		log.Printf("task log begin %s: task log is full", taskID)
		return false, false
	}
	log.Printf("task log begin %s: %v", taskID, err)
	return false, false
}

func NewTask(task_id, command string) {
	run, _ := acceptTask(task_id)
	if !run {
		return
	}
	executeAcceptedTask(task_id, command)
}

func executeAcceptedTask(task_id, command string) {
	if strings.TrimSpace(command) == "" {
		finishTask(task_id, "No command provided", 0)
		return
	}
	if !pkg_flags.RemoteControlEnabled() {
		finishTask(task_id, "Remote control is disabled.", -1)
		return
	}
	if len(command) > 64<<10 {
		finishTask(task_id, "Command is too long", -1)
		return
	}
	log.Printf("Executing task %s", task_id)
	result, exitCode := runTaskCommand(command)
	finishTask(task_id, result, exitCode)
}

func finishTask(taskID, result string, exitCode int) {
	finishedAt := time.Now().UTC()
	persisted := false
	if execLog != nil {
		entry, err := persistTaskFinish(taskID, result, exitCode)
		if err != nil {
			log.Printf("task log finish %s: 本地完成状态持久化失败", taskID)
		} else {
			persisted = true
			if !entry.FinishedAt.IsZero() {
				finishedAt = entry.FinishedAt
			}
		}
	}
	if uploadTaskResult(taskID, result, exitCode, finishedAt, v2.TaskResultStatusFinished) && persisted {
		if err := execLog.Ack(taskID); err != nil {
			log.Printf("task log ack %s: %v", taskID, err)
		}
	}
}

func persistTaskFinish(taskID, result string, exitCode int) (tasklog.Entry, error) {
	var last error
	for attempt := 0; attempt < finishPersistMaxAttempts; attempt++ {
		entry, err := execLog.Finish(taskID, result, exitCode)
		if err == nil {
			return entry, nil
		}
		last = err
		log.Printf("task log finish %s attempt %d: %v", taskID, attempt+1, err)
		if delay := finishRetrySleep(attempt); delay > 0 {
			time.Sleep(delay)
		}
	}
	return tasklog.Entry{}, last
}

func finishRetrySleep(attempt int) time.Duration {
	if finishRetryDelay != nil {
		return finishRetryDelay(attempt)
	}
	delay := time.Duration(flags.ReconnectInterval) * time.Second
	if delay <= 0 {
		delay = time.Second
	}
	for i := 0; i < attempt; i++ {
		delay *= 2
		if delay > 30*time.Second {
			return 30 * time.Second
		}
	}
	return delay
}

func runTaskCommand(command string) (string, int) {
	cmd, cleanup, err := buildTaskCommand(command)
	if err != nil {
		return err.Error(), -1
	}
	defer cleanup()

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err = cmd.Run()

	result := decodeCommandOutput(stdout.Bytes())
	if stderr.Len() > 0 {
		result = appendErrorResult(result, decodeCommandOutput(stderr.Bytes()))
	}
	result = strings.ReplaceAll(result, "\r\n", "\n")
	const maxResultBytes = 1 << 20
	if len(result) > maxResultBytes {
		result = result[:maxResultBytes]
		for len(result) > 0 && result[len(result)-1]&0xc0 == 0x80 {
			result = result[:len(result)-1]
		}
		result += "\n[truncated]"
	}
	exitCode := 0
	if err != nil {
		if exitError, ok := err.(*exec.ExitError); ok {
			exitCode = exitError.ExitCode()
		} else {
			result = appendErrorResult(result, err.Error())
			exitCode = -1
		}
	}

	return result, exitCode
}

func buildTaskCommand(command string) (*exec.Cmd, func(), error) {
	var cmd *exec.Cmd
	if runtime.GOOS == "windows" {
		scriptFile, err := os.CreateTemp("", "lite-agent-task-*.ps1")
		if err != nil {
			return nil, func() {}, err
		}
		cleanup := func() {
			_ = os.Remove(scriptFile.Name())
		}
		if _, err := scriptFile.Write([]byte{0xEF, 0xBB, 0xBF}); err != nil {
			_ = scriptFile.Close()
			cleanup()
			return nil, func() {}, err
		}
		script := strings.Join([]string{
			"$nativeEncoding = [System.Text.Encoding]::Default",
			"[Console]::OutputEncoding = $nativeEncoding",
			"$OutputEncoding = [System.Text.Encoding]::UTF8",
			command,
		}, "\n")
		if _, err := scriptFile.WriteString(script); err != nil {
			_ = scriptFile.Close()
			cleanup()
			return nil, func() {}, err
		}
		if err := scriptFile.Close(); err != nil {
			cleanup()
			return nil, func() {}, err
		}
		cmd = exec.Command("powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", scriptFile.Name())
		return cmd, cleanup, nil
	} else {
		cmd = exec.Command("sh", "-s")
		cmd.Stdin = strings.NewReader(command)
	}
	return cmd, func() {}, nil
}

func appendErrorResult(result, err string) string {
	if result == "" {
		return err
	}
	return result + "\n" + err
}

func uploadTaskResult(taskID, result string, exitCode int, finishedAt time.Time, status string) bool {
	return uploadTaskResultFn(taskID, result, exitCode, finishedAt, status)
}

func defaultUploadTaskResult(taskID, result string, exitCode int, finishedAt time.Time, status string) bool {
	if strings.TrimSpace(flags.Token) == "" {
		return false
	}
	payload := v2.BuildTaskResultPayload(taskID, result, exitCode, finishedAt, status)
	var err error
	for attempt := 0; attempt <= flags.MaxRetries; attempt++ {
		err = postV2RPC(payload)
		if err == nil {
			return true
		}
		if attempt == flags.MaxRetries {
			break
		}
		delay := time.Duration(flags.ReconnectInterval) * time.Second
		if delay <= 0 {
			delay = time.Second
		}
		time.Sleep(delay)
	}
	log.Printf("Failed to upload task result: %v", err)
	return false
}

// resolveIP 解析域名到 IP 地址，排除 DNS 查询时间
func resolveIP(target string) (string, error) {
	// 如果已经是 IP 地址，直接返回
	if ip := net.ParseIP(target); ip != nil {
		return target, nil
	}
	// 解析域名到 IP
	addrs, err := net.LookupHost(target)
	if err != nil || len(addrs) == 0 {
		return "", errors.New("failed to resolve target")
	}
	return addrs[0], nil // 返回第一个解析的 IP
}

func latencyMilliseconds(d time.Duration) float64 {
	return float64(d) / float64(time.Millisecond)
}

func icmpPing(target string, timeout time.Duration) (float64, error) {
	host, _, err := net.SplitHostPort(target)
	if err != nil {
		host = target
	}
	// For ICMP, we only need the host/IP, port is irrelevant.
	// If the host is an IPv6 literal, it might be wrapped in brackets.
	host = strings.Trim(host, "[]")

	// 先解析 IP 地址
	ip, err := resolveIP(host)
	if err != nil {
		return -1, err
	}

	pinger, err := ping.NewPinger(ip)
	if err != nil {
		return -1, err
	}
	pinger.Count = 1
	pinger.Timeout = timeout
	pinger.SetPrivileged(true)
	err = pinger.Run()
	if err != nil {
		return -1, err
	}
	stats := pinger.Statistics()
	if stats.PacketsRecv == 0 {
		return -1, errors.New("no packets received")
	}
	return latencyMilliseconds(stats.AvgRtt), nil
}

func tcpPing(target string, timeout time.Duration) (float64, error) {
	host, port, err := net.SplitHostPort(target)
	if err != nil {
		// No port, assume port 80
		host = target
		port = "80"
	}

	// If the host is an IPv6 literal, it might be wrapped in brackets.
	host = strings.Trim(host, "[]")

	ip, err := resolveIP(host)
	if err != nil {
		return -1, err
	}

	targetAddr := net.JoinHostPort(ip, port)
	start := time.Now()
	conn, err := net.DialTimeout("tcp", targetAddr, timeout)
	if err != nil {
		return -1, err
	}
	defer conn.Close()
	return latencyMilliseconds(time.Since(start)), nil
}

// httpPingUserAgent 用常见浏览器标识，避免站点把 Go 默认 UA 直接拦成 403。
const httpPingUserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"

func httpPing(target string, timeout time.Duration) (float64, error) {
	// Handle raw IPv6 address for URL
	if strings.Contains(target, ":") && !strings.Contains(target, "[") {
		// check if it's a valid IP to avoid wrapping hostnames
		if ip := net.ParseIP(target); ip != nil && ip.To4() == nil {
			target = "[" + target + "]"
		}
	}

	if !strings.HasPrefix(target, "http://") && !strings.HasPrefix(target, "https://") {
		target = "http://" + target
	}

	req, err := http.NewRequest(http.MethodGet, target, nil)
	if err != nil {
		return -1, err
	}
	req.Header.Set("User-Agent", httpPingUserAgent)
	req.Header.Set("Accept", "*/*")

	transport := &http.Transport{
		DisableKeepAlives: true,
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			// 在 Dial 之前解析 IP，排除 DNS 时间
			host, port, err := net.SplitHostPort(addr)
			if err != nil {
				return nil, err
			}
			ip, err := resolveIP(host)
			if err != nil {
				return nil, err
			}
			return net.DialTimeout(network, net.JoinHostPort(ip, port), timeout)
		},
	}
	defer transport.CloseIdleConnections()

	client := &http.Client{
		Timeout:   timeout,
		Transport: transport,
	}
	start := time.Now()
	resp, err := client.Do(req)
	latency := latencyMilliseconds(time.Since(start))
	if err != nil {
		return -1, err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 200 && resp.StatusCode < 400 {
		return latency, nil
	}
	return latency, errors.New("http status not ok")
}

func NewPingTask(conn *ws.SafeConn, taskID uint, pingType, pingTarget string) {
	if taskID == 0 {
		log.Printf("Invalid task ID: %d", taskID)
		return
	}
	var err error = nil
	var latency float64
	pingResult := -1.0
	timeout := 3 * time.Second             // 默认超时时间
	const highLatencyThreshold = 1000.0    // ms 阈值
	const retryDropThresholdTcping = 800.0 // ms 重试中延迟降低超过此值则基本认为发生重传
	// 800ms = SYN/SYN-ACK 首次超时重传 1000ms - 防误判容许 200ms 延迟抖动

	measure := func() (float64, error) {
		switch pingType {
		case "icmp":
			return icmpPing(pingTarget, timeout)
		case "tcp":
			return tcpPing(pingTarget, timeout)
		case "http":
			return httpPing(pingTarget, timeout)
		default:
			return -1, errors.New("unsupported ping type")
		}
	}
	PingHighLatencyRetries := 3
	// 首次测量
	if latency, err = measure(); err == nil {
		firstLatency := latency
		if latency > highLatencyThreshold && PingHighLatencyRetries > 0 {
			attempts := PingHighLatencyRetries
			for i := 0; i < attempts; i++ {
				if second, err2 := measure(); err2 == nil {
					if second <= highLatencyThreshold {
						if pingType == "tcp" && firstLatency-second > retryDropThresholdTcping {
							err = errors.New("suspicious retransmission detected in tcp handshake")
							break
						}
						latency = second
						break
					}
					if i == attempts-1 { // 最后一次仍高
						err = errors.New("latency remains high after retries")
					}
				} else {
					err = err2
					break
				}
			}
		}
	}

	if err != nil {
		log.Printf("Ping task %d failed: %v", taskID, err)
		pingResult = -1 // 如果有错误，设置结果为 -1
	} else {
		pingResult = latency
	}
	finishedAt := time.Now()
	wsPayload := v2.BuildPingResultPayload(taskID, pingType, pingResult, finishedAt)
	reportV2Result(conn, wsPayload, "Failed to upload ping result")

}

func reportV2Result(conn *ws.SafeConn, payload interface{}, failLog string) {
	if conn != nil && conn.WriteJSON(payload) == nil {
		return
	}
	if err := postV2RPC(payload); err != nil {
		log.Printf("%s: %v", failLog, err)
	}
}

func postV2RPC(payload interface{}) error {
	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	status, respBody, err := postV2JSONRPC(context.Background(), body, 30*time.Second)
	if err != nil {
		return err
	}
	if status != http.StatusOK {
		return &httpStatusError{StatusCode: status, Status: http.StatusText(status), Body: string(respBody)}
	}
	return nil
}
