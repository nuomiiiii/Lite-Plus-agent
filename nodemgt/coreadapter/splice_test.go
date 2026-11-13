package coreadapter

import (
	"io"
	"net"
	"testing"
	"time"
)

func TestServeSpliceReapsClientFIN(t *testing.T) {
	old := spliceHalfCloseWait
	spliceHalfCloseWait = 50 * time.Millisecond
	defer func() { spliceHalfCloseWait = old }()

	backend, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer backend.Close()
	go func() {
		conn, err := backend.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		_, _ = io.Copy(io.Discard, conn)
	}()

	frontLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	front := &spliceFront{ln: frontLn}
	go serveSplice(front, frontSpec{Dest: backend.Addr().String()})
	defer front.close()

	client, err := net.DialTimeout("tcp", frontLn.Addr().String(), 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	if _, err := client.Write([]byte("hi")); err != nil {
		t.Fatal(err)
	}
	if err := client.(*net.TCPConn).CloseWrite(); err != nil {
		t.Fatal(err)
	}
	_ = client.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, err := client.Read(make([]byte, 8))
	if n != 0 || err != io.EOF {
		t.Fatalf("want EOF after client FIN, n=%d err=%v", n, err)
	}
}

func TestServeSpliceDrainsDownlinkAfterClientFIN(t *testing.T) {
	old := spliceHalfCloseWait
	spliceHalfCloseWait = 300 * time.Millisecond
	defer func() { spliceHalfCloseWait = old }()

	backend, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer backend.Close()
	go func() {
		conn, err := backend.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		_, _ = io.Copy(io.Discard, conn)
		_, _ = conn.Write([]byte("late-data"))
		_, _ = io.Copy(io.Discard, conn)
	}()

	frontLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	front := &spliceFront{ln: frontLn}
	go serveSplice(front, frontSpec{Dest: backend.Addr().String()})
	defer front.close()

	client, err := net.DialTimeout("tcp", frontLn.Addr().String(), 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	if _, err := client.Write([]byte("hi")); err != nil {
		t.Fatal(err)
	}
	if err := client.(*net.TCPConn).CloseWrite(); err != nil {
		t.Fatal(err)
	}
	_ = client.SetReadDeadline(time.Now().Add(2 * time.Second))
	got, err := io.ReadAll(client)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "late-data" {
		t.Fatalf("downlink after FIN: %q", got)
	}
}

func TestServeSpliceKeepsActiveDownlink(t *testing.T) {
	old := spliceHalfCloseWait
	spliceHalfCloseWait = 80 * time.Millisecond
	defer func() { spliceHalfCloseWait = old }()

	backend, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer backend.Close()
	go func() {
		conn, err := backend.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		_, _ = io.Copy(io.Discard, conn)
		for i := 0; i < 4; i++ {
			if _, err := conn.Write([]byte("x")); err != nil {
				return
			}
			time.Sleep(40 * time.Millisecond)
		}
	}()

	frontLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	front := &spliceFront{ln: frontLn}
	go serveSplice(front, frontSpec{Dest: backend.Addr().String()})
	defer front.close()

	client, err := net.DialTimeout("tcp", frontLn.Addr().String(), 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	if _, err := client.Write([]byte("hi")); err != nil {
		t.Fatal(err)
	}
	if err := client.(*net.TCPConn).CloseWrite(); err != nil {
		t.Fatal(err)
	}
	_ = client.SetReadDeadline(time.Now().Add(2 * time.Second))
	got, err := io.ReadAll(client)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "xxxx" {
		t.Fatalf("active downlink after FIN: %q", got)
	}
}
