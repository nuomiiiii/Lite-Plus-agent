package runtime

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	v2 "github.com/nuomiiiii/lite-agent/protocol/v2"
)

func writeRuntimePair(t *testing.T, dir, name string) (certPath, keyPath string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 62))
	if err != nil {
		t.Fatal(err)
	}
	tpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: name, Organization: []string{"Lite Test CA"}},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		DNSNames:     []string{name},
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	certPath = filepath.Join(dir, name+".crt")
	keyPath = filepath.Join(dir, name+".key")
	if err := os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		t.Fatal(err)
	}
	return certPath, keyPath
}

func TestApplyConfigBindsFileCertAndReportsRenewal(t *testing.T) {
	dir := t.TempDir()
	certPath, keyPath := writeRuntimePair(t, dir, "panel.example")
	var mu sync.Mutex
	var reports []map[string]any
	rt, err := Start(filepath.Join(dir, "agent.json"), func(method string, params any) {
		if method != v2.MethodNodemgtControlResult {
			return
		}
		raw, _ := json.Marshal(params)
		var row map[string]any
		_ = json.Unmarshal(raw, &row)
		mu.Lock()
		reports = append(reports, row)
		mu.Unlock()
	})
	if err != nil {
		t.Fatal(err)
	}
	rt.HandleControl(map[string]any{
		"operation_id": "apply-file",
		"kind":         "applyConfig",
		"payload": map[string]any{
			"certs": []any{map[string]any{
				"id":        "c1",
				"domain":    "panel.example",
				"status":    "pending",
				"source":    "file",
				"cert_path": certPath,
				"key_path":  keyPath,
			}},
		},
	}, "")
	infos := rt.certs.InspectFiles()
	if len(infos) != 1 || infos[0].Err != nil || infos[0].Fingerprint == "" {
		t.Fatalf("bound file cert %+v", infos)
	}
	firstFP := infos[0].Fingerprint
	found := false
	mu.Lock()
	for _, row := range reports {
		if row["cert_id"] == "c1" && row["fingerprint"] == firstFP && row["status"] == "applied" {
			found = true
		}
	}
	mu.Unlock()
	if !found {
		t.Fatalf("missing file cert report %#v", reports)
	}
	writeRuntimePair(t, dir, "panel.example")
	rt.reloadRenewedFileCerts()
	infos = rt.certs.InspectFiles()
	if len(infos) != 1 || infos[0].Fingerprint == "" || infos[0].Fingerprint == firstFP {
		t.Fatalf("renewed fingerprint %+v first=%s", infos, firstFP)
	}
	renewed := false
	mu.Lock()
	for _, row := range reports {
		if row["cert_id"] == "c1" && row["fingerprint"] == infos[0].Fingerprint {
			renewed = true
		}
	}
	mu.Unlock()
	if !renewed {
		t.Fatalf("missing renewal report %#v", reports)
	}
}

func TestRestoreRemembersFileCertAndDedupsMissingErrors(t *testing.T) {
	dir := t.TempDir()
	certPath, keyPath := writeRuntimePair(t, dir, "boot.example")
	snap := map[string]any{
		"certs": []any{map[string]any{
			"id":        "c-boot",
			"domain":    "boot.example",
			"status":    "active",
			"source":    "file",
			"cert_path": certPath,
			"key_path":  keyPath,
		}},
	}
	snapRaw, _ := json.Marshal(snap)
	if err := os.MkdirAll(filepath.Join(dir, "nodemgt"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "nodemgt", "last-snapshot.json"), snapRaw, 0o600); err != nil {
		t.Fatal(err)
	}

	var mu sync.Mutex
	var reports []map[string]any
	rt, err := Start(filepath.Join(dir, "agent.json"), func(method string, params any) {
		if method != v2.MethodNodemgtControlResult {
			return
		}
		raw, _ := json.Marshal(params)
		var row map[string]any
		_ = json.Unmarshal(raw, &row)
		mu.Lock()
		reports = append(reports, row)
		mu.Unlock()
	})
	if err != nil {
		t.Fatal(err)
	}
	defer stopGeoRuntime(rt)

	// Unchanged file cert after restore() must NOT trigger spurious reload/report!
	rt.reloadRenewedFileCerts()
	mu.Lock()
	nAfterBoot := len(reports)
	mu.Unlock()
	if nAfterBoot != 0 {
		t.Fatalf("expected 0 reports on unchanged cert after restore, got %#v", reports)
	}

	// Missing cert file must report failure ONCE and not spam on subsequent ticks!
	if err := os.Remove(certPath); err != nil {
		t.Fatal(err)
	}
	rt.reloadRenewedFileCerts()
	rt.reloadRenewedFileCerts()
	rt.reloadRenewedFileCerts()
	mu.Lock()
	nErr := len(reports)
	mu.Unlock()
	if nErr != 1 || reports[0]["status"] != "failed" {
		t.Fatalf("expected exactly 1 deduplicated failure report, got %d: %#v", nErr, reports)
	}

	// Restoring valid cert file must report applied once and then go quiet again!
	writeRuntimePair(t, dir, "boot.example")
	rt.reloadRenewedFileCerts()
	rt.reloadRenewedFileCerts()
	mu.Lock()
	defer mu.Unlock()
	if len(reports) != 2 || reports[1]["status"] != "applied" {
		t.Fatalf("expected recovery applied report once, got %#v", reports)
	}
}
