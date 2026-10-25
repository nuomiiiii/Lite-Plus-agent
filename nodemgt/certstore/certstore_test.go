package certstore

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestGenerateCSRUsesRSA2048(t *testing.T) {
	store, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	keyPEM, csrPEM, err := store.GenerateCSR("panel.example")
	if err != nil {
		t.Fatal(err)
	}
	keyBlock, _ := pem.Decode([]byte(keyPEM))
	if keyBlock == nil || keyBlock.Type != "RSA PRIVATE KEY" {
		t.Fatalf("key type %q", keyBlock)
	}
	key, err := x509.ParsePKCS1PrivateKey(keyBlock.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if key.N.BitLen() != 2048 {
		t.Fatalf("key bits %d", key.N.BitLen())
	}
	csrBlock, _ := pem.Decode([]byte(csrPEM))
	if csrBlock == nil {
		t.Fatal("csr pem")
	}
	csr, err := x509.ParseCertificateRequest(csrBlock.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	pub, ok := csr.PublicKey.(*rsa.PublicKey)
	if !ok || pub.N.BitLen() != 2048 {
		t.Fatalf("csr pub %T bits", csr.PublicKey)
	}
}

func TestGenerateCSRIncludesWildcardSAN(t *testing.T) {
	store, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	_, csrPEM, err := store.GenerateCSR("abc.com", "abc.com", "*.abc.com")
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode([]byte(csrPEM))
	if block == nil {
		t.Fatal("csr pem")
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if csr.Subject.CommonName != "abc.com" {
		t.Fatalf("cn %s", csr.Subject.CommonName)
	}
	got := map[string]bool{}
	for _, name := range csr.DNSNames {
		got[name] = true
	}
	if !got["abc.com"] || !got["*.abc.com"] {
		t.Fatalf("san %v", csr.DNSNames)
	}
}

func TestSaveChainKeyAcceptsPushedKey(t *testing.T) {
	dir := t.TempDir()
	store, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	certPath, keyPath, _ := writePair(t, dir, "abc.com", time.Now().Add(24*time.Hour))
	chain, err := os.ReadFile(certPath)
	if err != nil {
		t.Fatal(err)
	}
	key, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.SaveChainKey("abc.com", string(chain), string(key)); err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.TLSConfig("abc.com"); err != nil {
		t.Fatal(err)
	}
}

func writePair(t *testing.T, dir, name string, notAfter time.Time) (certPath, keyPath, fp string) {
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
		Issuer:       pkix.Name{CommonName: name, Organization: []string{"Lite Test CA"}},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     notAfter,
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
	fp, _, _, err = parseLeaf(
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}),
	)
	if err != nil {
		t.Fatal(err)
	}
	return certPath, keyPath, fp
}

func TestBindFileReadsExternalPathsAndDetectsRenewal(t *testing.T) {
	dir := t.TempDir()
	store, err := Open(filepath.Join(dir, "certs"))
	if err != nil {
		t.Fatal(err)
	}
	certPath, keyPath, fp1 := writePair(t, dir, "panel.example", time.Now().Add(24*time.Hour))
	store.BindFile("c1", "panel.example", certPath, keyPath)
	cfg, gotFP, err := store.TLSConfig("panel.example")
	if err != nil {
		t.Fatal(err)
	}
	if cfg == nil || gotFP != fp1 {
		t.Fatalf("fingerprint %q want %q", gotFP, fp1)
	}
	infos := store.InspectFiles()
	if len(infos) != 1 || infos[0].Err != nil || !infos[0].Changed || infos[0].Fingerprint != fp1 {
		t.Fatalf("first inspect %+v", infos)
	}
	if infos[0].Issuer != "Lite Test CA" {
		t.Fatalf("issuer %q", infos[0].Issuer)
	}
	store.RememberFingerprint("panel.example", fp1)
	infos = store.InspectFiles()
	if len(infos) != 1 || infos[0].Changed {
		t.Fatalf("unchanged inspect %+v", infos)
	}
	_, _, fp2 := writePair(t, dir, "panel.example", time.Now().Add(48*time.Hour))
	if fp2 == fp1 {
		t.Fatal("renewed cert kept the same fingerprint")
	}
	infos = store.InspectFiles()
	if len(infos) != 1 || !infos[0].Changed || infos[0].Fingerprint != fp2 {
		t.Fatalf("renewed inspect %+v", infos)
	}
	_, gotFP, err = store.TLSConfig("panel.example")
	if err != nil {
		t.Fatal(err)
	}
	if gotFP != fp2 {
		t.Fatalf("tls fingerprint %q want %q", gotFP, fp2)
	}
}
