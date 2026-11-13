package server

import (
	"os"
	"strings"
	"testing"
)

func TestProtectionCommandsStayOrderedExceptUpgrade(t *testing.T) {
	raw, err := os.ReadFile("protection.go")
	if err != nil {
		t.Fatal(err)
	}
	text := string(raw)
	if !strings.Contains(text, "enqueueProtectionCommand") {
		t.Fatal("apply/ban/unban/snapshot must share one command queue")
	}
	if strings.Count(text, "go func()") != 1 {
		t.Fatal("only package install/upgrade may leave the receive loop")
	}
	if !strings.Contains(text, "AckProtectionReports(sent)") {
		t.Fatal("flush must ack only the reports that were sent")
	}
	if strings.Contains(text, "KeepProtectionReports") {
		t.Fatal("replacing the whole report queue drops items enqueued during send")
	}
	if !strings.Contains(text, "default:") || !strings.Contains(text, "protection command queue full") {
		t.Fatal("full command queue must reject without blocking the websocket loop")
	}
	if !strings.Contains(text, "reportProtectionParamError") {
		t.Fatal("invalid protection params must still return a result")
	}
}
