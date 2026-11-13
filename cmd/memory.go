package cmd

import (
	"log"
	"math"
	"os"
	"runtime"
	"runtime/debug"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/shirou/gopsutil/v4/mem"
)

const (
	minMemory1CPU               = 64 << 20
	minMemoryMultiCPU           = 96 << 20
	hostReserveSmall            = 64 << 20
	hostReserveDefault          = 128 << 20
	defaultMemoryReleaseMinutes = 10
	unlimitedCgroup             = int64(math.MaxInt64 / 2)
	// 512MiB and below still get an auto GOMEMLIMIT so a monitoring-only
	// agent cannot eat the box. Anything larger skips the cap at startup;
	// 640/768/891 "small 1G" hosts do not need it and will GC-thrash if capped.
	autoMemoryLimitMax = 512 << 20
)

var (
	memoryBudget  = detectMemoryBudget
	effectiveCPUs = detectEffectiveCPUs

	memoryMu          sync.Mutex
	envMemoryLimit    bool
	autoMemoryLimited bool
	autoMemoryLimit   int64
	proxyMemoryLimit  int64
	proxyMemoryLifted bool
)

func configureRuntimeMemory() {
	cpus := effectiveCPUs()
	if os.Getenv("GOMAXPROCS") == "" && cpus > 0 {
		cur := runtime.GOMAXPROCS(0)
		if cpus < cur {
			runtime.GOMAXPROCS(cpus)
		}
	}
	memoryMu.Lock()
	envMemoryLimit = os.Getenv("GOMEMLIMIT") != ""
	autoMemoryLimited = false
	autoMemoryLimit = 0
	proxyMemoryLimit = 0
	proxyMemoryLifted = false
	if !envMemoryLimit {
		total, limited := memoryBudget()
		kind := "host"
		if limited {
			kind = "cgroup"
		}
		if shouldSetAutoMemoryLimit(total) {
			limit := pickAgentMemoryLimit(total, cpus, limited)
			debug.SetMemoryLimit(limit)
			autoMemoryLimited = true
			autoMemoryLimit = limit
			proxyMemoryLimit = pickProxyMemoryLimit(total, cpus, limited)
			log.Printf("runtime memory limit %dMiB (%s %dMiB, %d cpu)", limit>>20, kind, total>>20, cpus)
		} else {
			log.Printf("runtime memory limit skipped (%s %dMiB, %d cpu; GOGC and periodic release only)", kind, total>>20, cpus)
		}
	}
	memoryMu.Unlock()
	if os.Getenv("GOGC") == "" {
		debug.SetGCPercent(50)
	}
	startMemoryRelease(memoryReleaseInterval())
}

// setProxyMemoryMode lifts the auto GOMEMLIMIT while node inbounds are live.
// A 128MiB cap on a 512MiB box is right for monitoring-only; linked xray
// sessions need more than that and will GC-thrash if the cap stays.
func setProxyMemoryMode(live bool) {
	memoryMu.Lock()
	defer memoryMu.Unlock()
	if envMemoryLimit || !autoMemoryLimited {
		return
	}
	if live {
		if proxyMemoryLifted {
			return
		}
		limit := proxyMemoryLimit
		if limit <= 0 {
			limit = autoMemoryLimit
		}
		debug.SetMemoryLimit(limit)
		proxyMemoryLifted = true
		log.Printf("runtime memory limit %dMiB (live node inbounds)", limit>>20)
		return
	}
	if !proxyMemoryLifted {
		return
	}
	debug.SetMemoryLimit(autoMemoryLimit)
	proxyMemoryLifted = false
	log.Printf("runtime memory limit restored %dMiB (no live node inbounds)", autoMemoryLimit>>20)
}

func shouldSetAutoMemoryLimit(total int64) bool {
	return total > 0 && total <= autoMemoryLimitMax
}

func pickProxyMemoryLimit(total int64, cpus int, limited bool) int64 {
	monitor := pickAgentMemoryLimit(total, cpus, limited)
	if total <= 0 {
		return monitor
	}
	reserve := int64(hostReserveDefault)
	if total <= 256<<20 {
		reserve = hostReserveSmall
	}
	lifted := total - reserve
	if lifted < monitor {
		lifted = monitor
	}
	capAt := total * 9 / 10
	if capAt > 0 && lifted > capAt {
		lifted = capAt
	}
	return lifted
}

func pickAgentMemoryLimit(total int64, cpus int, limited bool) int64 {
	class := cpuClass(cpus)
	minLimit := int64(minMemoryMultiCPU)
	if class == 1 {
		minLimit = minMemory1CPU
	}
	if total <= 0 {
		return minLimit
	}
	maxLimit := hostMaxLimit(total, class)
	budget := total
	percent := int64(60)
	switch class {
	case 1:
		percent = 40
	case 2:
		percent = 50
	}
	if limited {
		if class == 1 {
			percent = 70
		} else {
			percent = 80
		}
	} else {
		reserve := int64(hostReserveDefault)
		if total <= 256<<20 {
			reserve = hostReserveSmall
		}
		if total > reserve {
			budget = total - reserve
		} else {
			budget = total / 2
		}
	}
	limit := budget * percent / 100
	if limit < minLimit {
		limit = minLimit
	}
	if limit > maxLimit {
		limit = maxLimit
	}
	capAt := total * 9 / 10
	if capAt > 0 && limit > capAt {
		limit = capAt
	}
	return limit
}

func cpuClass(cpus int) int {
	if cpus <= 1 {
		return 1
	}
	if cpus <= 3 {
		return 2
	}
	return 4
}

func hostMaxLimit(total int64, class int) int64 {
	var max1, max2, max4 int64
	switch {
	case total <= 256<<20:
		max1, max2, max4 = 64, 96, 96
	case total <= 512<<20:
		max1, max2, max4 = 128, 160, 192
	case total <= 1024<<20:
		max1, max2, max4 = 192, 256, 320
	case total <= 2048<<20:
		max1, max2, max4 = 256, 384, 512
	case total <= 3072<<20:
		max1, max2, max4 = 320, 448, 640
	default:
		max1, max2, max4 = 384, 512, 768
	}
	switch class {
	case 1:
		return max1 << 20
	case 2:
		return max2 << 20
	default:
		return max4 << 20
	}
}

func memoryReleaseInterval() time.Duration {
	raw := strings.TrimSpace(os.Getenv("AGENT_MEMORY_RELEASE_INTERVAL"))
	if raw == "" {
		return defaultMemoryReleaseMinutes * time.Minute
	}
	n, err := strconv.Atoi(raw)
	if err != nil || n < 0 {
		return defaultMemoryReleaseMinutes * time.Minute
	}
	if n == 0 {
		return 0
	}
	return time.Duration(n) * time.Minute
}

func startMemoryRelease(interval time.Duration) {
	if interval <= 0 {
		return
	}
	log.Printf("runtime memory release every %s", interval)
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for range ticker.C {
			debug.FreeOSMemory()
		}
	}()
}

func detectMemoryBudget() (total int64, limited bool) {
	if n, ok := readCgroupMemory(); ok {
		return n, true
	}
	v, err := mem.VirtualMemory()
	if err != nil || v == nil || v.Total == 0 {
		return 0, false
	}
	return int64(v.Total), false
}

func detectEffectiveCPUs() int {
	n := runtime.NumCPU()
	if n < 1 {
		n = 1
	}
	if c, ok := readCgroupCPUCount(); ok && c < n {
		n = c
	}
	if n < 1 {
		return 1
	}
	return n
}

func readCgroupMemory() (int64, bool) {
	for _, path := range []string{
		"/sys/fs/cgroup/memory.max",
		"/sys/fs/cgroup/memory/memory.limit_in_bytes",
	} {
		raw, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		if n, ok := parseCgroupBytes(string(raw)); ok {
			return n, true
		}
	}
	return 0, false
}

func parseCgroupBytes(raw string) (int64, bool) {
	s := strings.TrimSpace(raw)
	if s == "" || strings.EqualFold(s, "max") {
		return 0, false
	}
	n, err := strconv.ParseInt(s, 10, 64)
	if err != nil || n <= 0 || n >= unlimitedCgroup {
		return 0, false
	}
	return n, true
}

func readCgroupCPUCount() (int, bool) {
	best := 0
	ok := false
	if raw, err := os.ReadFile("/sys/fs/cgroup/cpu.max"); err == nil {
		if n, parsed := parseCPUMax(string(raw)); parsed {
			best = n
			ok = true
		}
	}
	if raw, err := os.ReadFile("/sys/fs/cgroup/cpuset.cpus.effective"); err == nil {
		if n, parsed := parseCPUSet(string(raw)); parsed && (!ok || n < best) {
			best = n
			ok = true
		}
	} else if raw, err := os.ReadFile("/sys/fs/cgroup/cpuset.cpus"); err == nil {
		if n, parsed := parseCPUSet(string(raw)); parsed && (!ok || n < best) {
			best = n
			ok = true
		}
	}
	if !ok || best < 1 {
		return 0, false
	}
	return best, true
}

func parseCPUMax(raw string) (int, bool) {
	fields := strings.Fields(raw)
	if len(fields) == 0 || strings.EqualFold(fields[0], "max") {
		return 0, false
	}
	quota, err := strconv.ParseInt(fields[0], 10, 64)
	if err != nil || quota <= 0 {
		return 0, false
	}
	period := int64(100000)
	if len(fields) > 1 {
		p, err := strconv.ParseInt(fields[1], 10, 64)
		if err == nil && p > 0 {
			period = p
		}
	}
	n := int((quota + period - 1) / period)
	if n < 1 {
		n = 1
	}
	return n, true
}

func parseCPUSet(raw string) (int, bool) {
	s := strings.TrimSpace(raw)
	if s == "" {
		return 0, false
	}
	n := 0
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if lo, hi, ok := strings.Cut(part, "-"); ok {
			a, err1 := strconv.Atoi(strings.TrimSpace(lo))
			b, err2 := strconv.Atoi(strings.TrimSpace(hi))
			if err1 != nil || err2 != nil || b < a {
				return 0, false
			}
			n += b - a + 1
			continue
		}
		if _, err := strconv.Atoi(part); err != nil {
			return 0, false
		}
		n++
	}
	if n < 1 {
		return 0, false
	}
	return n, true
}
