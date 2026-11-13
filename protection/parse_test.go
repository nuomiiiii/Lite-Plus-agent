package protection

import (
	"strings"
	"testing"
	"time"

	v2 "github.com/nuomiiiii/lite-agent/protocol/v2"
)

func TestParseCaddyJSON(t *testing.T) {
	line := `{"ts":1699999999.5,"request":{"remote_ip":"203.0.113.9","client_ip":"198.51.100.7","method":"GET","uri":"/admin/login?x=1","proto":"HTTP/2.0","host":"example.com"},"status":404}`
	rec, err := ParseLine(v2.ProtectionLogCaddyJSON, line)
	if err != nil {
		t.Fatal(err)
	}
	if rec.IP != "198.51.100.7" || rec.PeerAddr != "203.0.113.9" || rec.Path != "/admin/login" || rec.Status != 404 || rec.Transport != "tcp" || rec.Host != "example.com" {
		t.Fatalf("%+v", rec)
	}
	if rec.Time.Unix() != 1699999999 {
		t.Fatalf("ts %s", rec.Time)
	}
}

func TestParseCaddyJSONStringTS(t *testing.T) {
	line := `{"ts":"1699999999.25","request":{"remote_ip":"2001:db8::1","method":"POST","uri":"/","proto":"HTTP/3.0","host":"a.test"},"status":"200"}`
	rec, err := ParseLine(v2.ProtectionLogCaddyJSON, line)
	if err != nil {
		t.Fatal(err)
	}
	if rec.IP != "2001:db8::1" || rec.Transport != "udp" || rec.Status != 200 {
		t.Fatalf("%+v", rec)
	}
}

func TestParseNginxJSON(t *testing.T) {
	line := `{"ts":"1699999999","remote_addr":"192.0.2.8","server_port":"443","host":"web.test","method":"GET","uri":"/wp-login.php","protocol":"HTTP/1.1","status":"403","peer_addr":"198.51.100.1"}`
	rec, err := ParseLine(v2.ProtectionLogNginxJSON, line)
	if err != nil {
		t.Fatal(err)
	}
	if rec.IP != "192.0.2.8" || rec.ServerPort != 443 || rec.PeerAddr != "198.51.100.1" || rec.Path != "/wp-login.php" {
		t.Fatalf("%+v", rec)
	}
}

func TestParseNginxJSONServerAddr(t *testing.T) {
	line := `{"ts":"1699999999","remote_addr":"192.0.2.8","server_addr":"192.0.2.10","server_port":"443","host":"web.test","method":"GET","uri":"/","protocol":"HTTP/1.1","status":"200"}`
	rec, err := ParseLine(v2.ProtectionLogNginxJSON, line)
	if err != nil {
		t.Fatal(err)
	}
	if rec.DestAddr != "192.0.2.10" || rec.IP != "192.0.2.8" {
		t.Fatalf("%+v", rec)
	}
}

func TestParseNginxCombined(t *testing.T) {
	line := `203.0.113.10 - - [07/Nov/2026:01:02:03 +0000] "GET /secret HTTP/1.1" 404 12 "-" "curl"`
	rec, err := ParseLine(v2.ProtectionLogNginxCombined, line)
	if err != nil {
		t.Fatal(err)
	}
	if rec.IP != "203.0.113.10" || rec.Path != "/secret" || rec.Status != 404 || rec.Method != "GET" {
		t.Fatalf("%+v", rec)
	}
	if rec.Time.UTC() != time.Date(2026, 11, 7, 1, 2, 3, 0, time.UTC) {
		t.Fatalf("time %s", rec.Time)
	}
}

func TestParseNginxCombinedIPv6QuotedRequest(t *testing.T) {
	line := `2001:db8::ab - - [07/Nov/2026:01:02:03 +0000] "GET /a\"b HTTP/1.1" 200 1 "-" "-"`
	rec, err := ParseLine(v2.ProtectionLogNginxCombined, line)
	if err != nil {
		t.Fatal(err)
	}
	if rec.IP != "2001:db8::ab" || rec.Path != `/a"b` {
		t.Fatalf("%+v", rec)
	}
}

func TestParseSSHDFailedPassword(t *testing.T) {
	line := `2026-11-12T12:00:00+00:00 vps sshd[123]: Failed password for root from 203.0.113.9 port 54321 ssh2`
	rec, err := ParseLine(v2.ProtectionLogSSHD, line)
	if err != nil {
		t.Fatal(err)
	}
	if rec.IP != "203.0.113.9" || rec.Method != "password" || rec.Path != "root" || rec.Transport != "tcp" {
		t.Fatalf("%+v", rec)
	}
	if rec.Time.UTC() != time.Date(2026, 11, 12, 12, 0, 0, 0, time.UTC) {
		t.Fatalf("time %s", rec.Time.UTC())
	}
}

func TestParseSSHDInvalidUserAndIPv6(t *testing.T) {
	line := `2026-11-12T12:00:00+00:00 vps sshd-session[9]: Failed password for invalid user admin from 2001:db8::ab port 22 ssh2`
	rec, err := ParseLine(v2.ProtectionLogSSHD, line)
	if err != nil {
		t.Fatal(err)
	}
	if rec.IP != "2001:db8::ab" || rec.Path != "admin" {
		t.Fatalf("%+v", rec)
	}
}

func TestParseSSHDSyslogAndSkipsNoise(t *testing.T) {
	now := time.Now()
	line := now.Format("Jan 2 15:04:05") + ` host sshd[8]: Failed keyboard-interactive/pam for root from 198.51.100.7 port 1 ssh2`
	rec, err := parseSSHD(line, now)
	if err != nil {
		t.Fatal(err)
	}
	if rec.IP != "198.51.100.7" || rec.Method != "keyboard-interactive" {
		t.Fatalf("%+v", rec)
	}
	if _, err := ParseLine(v2.ProtectionLogSSHD, now.Format("Jan 2 15:04:05")+` host sshd[8]: Accepted password for root from 198.51.100.7 port 1 ssh2`); !IsSkip(err) {
		t.Fatalf("accepted password must skip: %v", err)
	}
	if _, err := ParseLine(v2.ProtectionLogSSHD, now.Format("Jan 2 15:04:05")+` host cron[1]: Failed password for root from 198.51.100.7 port 1 ssh2`); !IsSkip(err) {
		t.Fatalf("non-sshd ident must skip: %v", err)
	}
	if rec, err := parseSSHD(now.Format("Jan 2 15:04:05")+` host sshd[8]: Maximum authentication attempts exceeded for root from 192.0.2.8 port 9 ssh2 [preauth]`, now); err != nil || rec.Method != "max-attempts" || rec.IP != "192.0.2.8" {
		t.Fatalf("max attempts %+v %v", rec, err)
	}
}

func TestParseRejectsUnknownFormatAndLongLine(t *testing.T) {
	if _, err := ParseLine("regex", "x"); err == nil {
		t.Fatal("unknown format")
	}
	if _, err := ParseLine(v2.ProtectionLogCaddyJSON, strings.Repeat("x", maxLineBytes+1)); err == nil {
		t.Fatal("long line")
	}
}

func TestNormalizePathStripsQueryOnce(t *testing.T) {
	path, err := NormalizePath("/a%2Fb?x=1")
	if err != nil || path != "/a/b" {
		t.Fatalf("%q %v", path, err)
	}
	if PathMatches("/admin/x", []string{"/admin/"}) != true {
		t.Fatal("prefix")
	}
	if PathMatches("/Admin", []string{"/admin"}) {
		t.Fatal("must keep case")
	}
}
