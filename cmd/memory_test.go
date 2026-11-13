package cmd

import (
	"math"
	"os"
	"runtime"
	"runtime/debug"
	"testing"
	"time"
)

func TestPickAgentMemoryLimit(t *testing.T) {
	const mib = int64(1 << 20)
	cases := []struct {
		name    string
		total   int64
		cpus    int
		limited bool
		wantMiB int64
	}{
		{"unknown 1cpu", 0, 1, false, 64},
		{"unknown 2cpu", 0, 2, false, 96},
		{"unknown 4cpu", 0, 4, false, 96},
		{"256 host 1cpu", 256 * mib, 1, false, 64},
		{"256 host 2cpu", 256 * mib, 2, false, 96},
		{"256 host 4cpu", 256 * mib, 4, false, 96},
		{"512 host 1cpu", 512 * mib, 1, false, 128},
		{"512 host 2cpu", 512 * mib, 2, false, 160},
		{"512 host 4cpu", 512 * mib, 4, false, 192},
		{"960 host 1cpu", 960 * mib, 1, false, 192},
		{"1g host 1cpu", 1024 * mib, 1, false, 192},
		{"1g host 2cpu", 1024 * mib, 2, false, 256},
		{"1g host 3cpu", 1024 * mib, 3, false, 256},
		{"1g host 4cpu", 1024 * mib, 4, false, 320},
		{"1g host 5cpu", 1024 * mib, 5, false, 320},
		{"2g host 1cpu", 2048 * mib, 1, false, 256},
		{"2g host 2cpu", 2048 * mib, 2, false, 384},
		{"2g host 4cpu", 2048 * mib, 4, false, 512},
		{"3g host 1cpu", 3072 * mib, 1, false, 320},
		{"3g host 2cpu", 3072 * mib, 2, false, 448},
		{"3g host 4cpu", 3072 * mib, 4, false, 640},
		{"4g host 1cpu", 4096 * mib, 1, false, 384},
		{"4g host 2cpu", 4096 * mib, 2, false, 512},
		{"4g host 4cpu", 4096 * mib, 4, false, 768},
		{"256 cgroup 1cpu", 256 * mib, 1, true, 64},
		{"256 cgroup 2cpu", 256 * mib, 2, true, 96},
		{"512 cgroup 1cpu", 512 * mib, 1, true, 128},
		{"1g cgroup 2cpu", 1024 * mib, 2, true, 256},
		{"1g cgroup 4cpu", 1024 * mib, 4, true, 320},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := pickAgentMemoryLimit(tc.total, tc.cpus, tc.limited)
			gotMiB := got >> 20
			if gotMiB != tc.wantMiB {
				t.Fatalf("limit %dMiB, want %dMiB", gotMiB, tc.wantMiB)
			}
		})
	}
}

func TestParseCPUMax(t *testing.T) {
	if n, ok := parseCPUMax("max 100000"); ok {
		t.Fatalf("unlimited parsed as %d", n)
	}
	n, ok := parseCPUMax("100000 100000")
	if !ok || n != 1 {
		t.Fatalf("1 cpu quota = %d %v", n, ok)
	}
	n, ok = parseCPUMax("200000 100000")
	if !ok || n != 2 {
		t.Fatalf("2 cpu quota = %d %v", n, ok)
	}
	n, ok = parseCPUMax("150000 100000")
	if !ok || n != 2 {
		t.Fatalf("1.5 cpu ceil = %d %v", n, ok)
	}
}

func TestParseCPUSet(t *testing.T) {
	n, ok := parseCPUSet("0")
	if !ok || n != 1 {
		t.Fatalf("single = %d %v", n, ok)
	}
	n, ok = parseCPUSet("0-1")
	if !ok || n != 2 {
		t.Fatalf("range = %d %v", n, ok)
	}
	n, ok = parseCPUSet("0-1,3")
	if !ok || n != 3 {
		t.Fatalf("list = %d %v", n, ok)
	}
}

func TestParseCgroupBytes(t *testing.T) {
	if _, ok := parseCgroupBytes("max"); ok {
		t.Fatal("max should be unlimited")
	}
	n, ok := parseCgroupBytes("268435456")
	if !ok || n != 256<<20 {
		t.Fatalf("256MiB = %d %v", n, ok)
	}
	if _, ok := parseCgroupBytes("9223372036854771712"); ok {
		t.Fatal("v1 unlimited sentinel")
	}
}

func TestPickProxyMemoryLimitStaysBelowHost(t *testing.T) {
	const mib = int64(1 << 20)
	got := pickProxyMemoryLimit(512*mib, 1, false)
	monitor := pickAgentMemoryLimit(512*mib, 1, false)
	if got <= monitor || got >= 512*mib {
		t.Fatalf("proxy %d monitor %d", got, monitor)
	}
}

func TestShouldSetAutoMemoryLimit(t *testing.T) {
	const mib = int64(1 << 20)
	cases := []struct {
		total int64
		want  bool
	}{
		{0, false},
		{256 * mib, true},
		{512 * mib, true},
		{513 * mib, false},
		{640 * mib, false},
		{767 * mib, false},
		{768 * mib, false},
		{891 * mib, false},
		{899 * mib, false},
		{900 * mib, false},
		{960 * mib, false},
		{1024 * mib, false},
		{2048 * mib, false},
		{3072 * mib, false},
		{4096 * mib, false},
	}
	for _, tc := range cases {
		got := shouldSetAutoMemoryLimit(tc.total)
		if got != tc.want {
			t.Fatalf("total %dMiB: auto limit %v, want %v", tc.total>>20, got, tc.want)
		}
	}
}

func TestCpuClass(t *testing.T) {
	if cpuClass(1) != 1 || cpuClass(0) != 1 {
		t.Fatal("1 cpu class")
	}
	if cpuClass(2) != 2 || cpuClass(3) != 2 {
		t.Fatal("2/3 cpu class")
	}
	if cpuClass(4) != 4 || cpuClass(8) != 4 {
		t.Fatal("4+ cpu class")
	}
}

func TestMemoryReleaseInterval(t *testing.T) {
	t.Setenv("AGENT_MEMORY_RELEASE_INTERVAL", "")
	_ = os.Unsetenv("AGENT_MEMORY_RELEASE_INTERVAL")
	if memoryReleaseInterval() != 10*time.Minute {
		t.Fatalf("default = %s", memoryReleaseInterval())
	}
	t.Setenv("AGENT_MEMORY_RELEASE_INTERVAL", "0")
	if memoryReleaseInterval() != 0 {
		t.Fatal("0 should disable")
	}
	t.Setenv("AGENT_MEMORY_RELEASE_INTERVAL", "15")
	if memoryReleaseInterval() != 15*time.Minute {
		t.Fatalf("15m = %s", memoryReleaseInterval())
	}
}

func TestConfigureRuntimeMemoryDefault(t *testing.T) {
	t.Setenv("AGENT_MEMORY_RELEASE_INTERVAL", "0")
	if err := os.Unsetenv("GOMEMLIMIT"); err != nil {
		t.Fatal(err)
	}
	if err := os.Unsetenv("GOGC"); err != nil {
		t.Fatal(err)
	}
	if err := os.Unsetenv("GOMAXPROCS"); err != nil {
		t.Fatal(err)
	}
	prevBudget, prevCPUs := memoryBudget, effectiveCPUs
	memoryBudget = func() (int64, bool) { return 512 << 20, false }
	effectiveCPUs = func() int { return 1 }
	t.Cleanup(func() {
		memoryBudget = prevBudget
		effectiveCPUs = prevCPUs
		_ = os.Unsetenv("GOMEMLIMIT")
		_ = os.Unsetenv("GOGC")
		_ = os.Unsetenv("GOMAXPROCS")
	})

	prevLimit := debug.SetMemoryLimit(math.MaxInt64)
	prevGC := debug.SetGCPercent(100)
	prevMax := runtime.GOMAXPROCS(0)
	t.Cleanup(func() {
		debug.SetMemoryLimit(prevLimit)
		debug.SetGCPercent(prevGC)
		runtime.GOMAXPROCS(prevMax)
	})

	configureRuntimeMemory()

	want := pickAgentMemoryLimit(512<<20, 1, false)
	gotLimit := debug.SetMemoryLimit(want)
	if gotLimit != want {
		t.Fatalf("memory limit = %d, want %d", gotLimit, want)
	}
	gotGC := debug.SetGCPercent(50)
	if gotGC != 50 {
		t.Fatalf("GOGC = %d, want 50", gotGC)
	}
}

func TestConfigureRuntimeMemorySkipsAbove512(t *testing.T) {
	t.Setenv("AGENT_MEMORY_RELEASE_INTERVAL", "0")
	if err := os.Unsetenv("GOMEMLIMIT"); err != nil {
		t.Fatal(err)
	}
	if err := os.Unsetenv("GOGC"); err != nil {
		t.Fatal(err)
	}
	if err := os.Unsetenv("GOMAXPROCS"); err != nil {
		t.Fatal(err)
	}
	prevBudget, prevCPUs := memoryBudget, effectiveCPUs
	memoryBudget = func() (int64, bool) { return 640 << 20, false }
	effectiveCPUs = func() int { return 1 }
	t.Cleanup(func() {
		memoryBudget = prevBudget
		effectiveCPUs = prevCPUs
		_ = os.Unsetenv("GOMEMLIMIT")
		_ = os.Unsetenv("GOGC")
		_ = os.Unsetenv("GOMAXPROCS")
	})

	prevLimit := debug.SetMemoryLimit(math.MaxInt64)
	prevGC := debug.SetGCPercent(100)
	prevMax := runtime.GOMAXPROCS(0)
	t.Cleanup(func() {
		debug.SetMemoryLimit(prevLimit)
		debug.SetGCPercent(prevGC)
		runtime.GOMAXPROCS(prevMax)
	})

	configureRuntimeMemory()

	gotLimit := debug.SetMemoryLimit(math.MaxInt64)
	if gotLimit != math.MaxInt64 {
		t.Fatalf(">512MiB host should skip auto GOMEMLIMIT, got %d", gotLimit)
	}
	gotGC := debug.SetGCPercent(50)
	if gotGC != 50 {
		t.Fatalf("GOGC = %d, want 50", gotGC)
	}
}

func TestConfigureRuntimeMemorySkipsLargeHost(t *testing.T) {
	t.Setenv("AGENT_MEMORY_RELEASE_INTERVAL", "0")
	if err := os.Unsetenv("GOMEMLIMIT"); err != nil {
		t.Fatal(err)
	}
	if err := os.Unsetenv("GOGC"); err != nil {
		t.Fatal(err)
	}
	if err := os.Unsetenv("GOMAXPROCS"); err != nil {
		t.Fatal(err)
	}
	prevBudget, prevCPUs := memoryBudget, effectiveCPUs
	memoryBudget = func() (int64, bool) { return 960 << 20, false }
	effectiveCPUs = func() int { return 1 }
	t.Cleanup(func() {
		memoryBudget = prevBudget
		effectiveCPUs = prevCPUs
		_ = os.Unsetenv("GOMEMLIMIT")
		_ = os.Unsetenv("GOGC")
		_ = os.Unsetenv("GOMAXPROCS")
	})

	prevLimit := debug.SetMemoryLimit(math.MaxInt64)
	prevGC := debug.SetGCPercent(100)
	prevMax := runtime.GOMAXPROCS(0)
	t.Cleanup(func() {
		debug.SetMemoryLimit(prevLimit)
		debug.SetGCPercent(prevGC)
		runtime.GOMAXPROCS(prevMax)
	})

	configureRuntimeMemory()

	gotLimit := debug.SetMemoryLimit(math.MaxInt64)
	if gotLimit != math.MaxInt64 {
		t.Fatalf("1G host should skip auto GOMEMLIMIT, got %d", gotLimit)
	}
	gotGC := debug.SetGCPercent(50)
	if gotGC != 50 {
		t.Fatalf("GOGC = %d, want 50", gotGC)
	}
}

func TestConfigureRuntimeMemoryRespectsEnv(t *testing.T) {
	t.Setenv("AGENT_MEMORY_RELEASE_INTERVAL", "0")
	t.Setenv("GOMEMLIMIT", "256MiB")
	t.Setenv("GOGC", "200")
	t.Setenv("GOMAXPROCS", "4")

	const keepLimit int64 = 123 << 20
	prevLimit := debug.SetMemoryLimit(keepLimit)
	prevGC := debug.SetGCPercent(100)
	prevMax := runtime.GOMAXPROCS(0)
	t.Cleanup(func() {
		debug.SetMemoryLimit(prevLimit)
		debug.SetGCPercent(prevGC)
		runtime.GOMAXPROCS(prevMax)
	})

	configureRuntimeMemory()

	gotLimit := debug.SetMemoryLimit(keepLimit)
	if gotLimit != keepLimit {
		t.Fatalf("GOMEMLIMIT env should skip override, got %d", gotLimit)
	}
	gotGC := debug.SetGCPercent(100)
	if gotGC != 100 {
		t.Fatalf("GOGC env should skip override, got %d", gotGC)
	}
	if runtime.GOMAXPROCS(0) != prevMax {
		t.Fatalf("GOMAXPROCS env should skip override, got %d want %d", runtime.GOMAXPROCS(0), prevMax)
	}
}

func TestSetProxyMemoryModeLifts512Cap(t *testing.T) {
	t.Setenv("AGENT_MEMORY_RELEASE_INTERVAL", "0")
	if err := os.Unsetenv("GOMEMLIMIT"); err != nil {
		t.Fatal(err)
	}
	if err := os.Unsetenv("GOGC"); err != nil {
		t.Fatal(err)
	}
	if err := os.Unsetenv("GOMAXPROCS"); err != nil {
		t.Fatal(err)
	}
	prevBudget, prevCPUs := memoryBudget, effectiveCPUs
	memoryBudget = func() (int64, bool) { return 512 << 20, false }
	effectiveCPUs = func() int { return 1 }
	t.Cleanup(func() {
		memoryBudget = prevBudget
		effectiveCPUs = prevCPUs
		_ = os.Unsetenv("GOMEMLIMIT")
		_ = os.Unsetenv("GOGC")
		_ = os.Unsetenv("GOMAXPROCS")
	})

	prevLimit := debug.SetMemoryLimit(math.MaxInt64)
	prevGC := debug.SetGCPercent(100)
	t.Cleanup(func() {
		debug.SetMemoryLimit(prevLimit)
		debug.SetGCPercent(prevGC)
	})

	configureRuntimeMemory()
	want := pickAgentMemoryLimit(512<<20, 1, false)
	if got := debug.SetMemoryLimit(want); got != want {
		t.Fatalf("512 monitoring cap = %d, want %d", got, want)
	}

	lifted := pickProxyMemoryLimit(512<<20, 1, false)
	if lifted <= want || lifted >= 512<<20 {
		t.Fatalf("proxy cap %d must sit between monitor %d and host 512MiB", lifted, want)
	}
	setProxyMemoryMode(true)
	if got := debug.SetMemoryLimit(lifted); got != lifted {
		t.Fatalf("live inbounds should lift 512 cap to %d, got %d", lifted, got)
	}
	setProxyMemoryMode(true)
	if got := debug.SetMemoryLimit(lifted); got != lifted {
		t.Fatalf("lifting twice should keep proxy cap %d, got %d", lifted, got)
	}

	setProxyMemoryMode(false)
	if got := debug.SetMemoryLimit(want); got != want {
		t.Fatalf("no inbounds should restore 512 cap %d, got %d", want, got)
	}
}

func TestSetProxyMemoryModeRespectsEnv(t *testing.T) {
	t.Setenv("AGENT_MEMORY_RELEASE_INTERVAL", "0")
	t.Setenv("GOMEMLIMIT", "256MiB")
	const keepLimit int64 = 123 << 20
	prevLimit := debug.SetMemoryLimit(keepLimit)
	t.Cleanup(func() {
		debug.SetMemoryLimit(prevLimit)
	})

	configureRuntimeMemory()
	setProxyMemoryMode(true)
	if got := debug.SetMemoryLimit(keepLimit); got != keepLimit {
		t.Fatalf("GOMEMLIMIT env should keep %d, got %d", keepLimit, got)
	}
}

func TestSetProxyMemoryModeNoopWhenHostSkips(t *testing.T) {
	t.Setenv("AGENT_MEMORY_RELEASE_INTERVAL", "0")
	if err := os.Unsetenv("GOMEMLIMIT"); err != nil {
		t.Fatal(err)
	}
	prevBudget, prevCPUs := memoryBudget, effectiveCPUs
	memoryBudget = func() (int64, bool) { return 960 << 20, false }
	effectiveCPUs = func() int { return 1 }
	t.Cleanup(func() {
		memoryBudget = prevBudget
		effectiveCPUs = prevCPUs
	})

	prevLimit := debug.SetMemoryLimit(math.MaxInt64)
	t.Cleanup(func() {
		debug.SetMemoryLimit(prevLimit)
	})

	configureRuntimeMemory()
	setProxyMemoryMode(true)
	if got := debug.SetMemoryLimit(math.MaxInt64); got != math.MaxInt64 {
		t.Fatalf("skipped host should stay unlimited, got %d", got)
	}
}
