package commands

import (
	"bytes"
	"strings"
	"testing"

	"rsc.io/qr"
)

func TestWriteQRUsesExplicitColorsAndQuietZone(t *testing.T) {
	ticket := "DATUMTUN1" + strings.Repeat("A7", 112)
	var out bytes.Buffer
	if err := writeQR(&out, ticket); err != nil {
		t.Fatal(err)
	}
	code, _ := qr.Encode(ticket, qr.L)
	rows := strings.Split(strings.TrimSuffix(out.String(), "\n"), "\n")
	if want := (code.Size + 2*quietZone + 1) / 2; len(rows) != want {
		t.Fatalf("rows = %d, want %d", len(rows), want)
	}
	// The first row is entirely quiet zone: light over light.
	if !strings.HasPrefix(rows[0], "\033[97m\033[107m▀") || strings.Contains(rows[0], "\033[30m") {
		t.Fatalf("first row is not light quiet zone: %q", rows[0][:40])
	}
	// A ticket-sized code stays small enough to scan from a terminal.
	if code.Size > 57 {
		t.Fatalf("QR code is %d modules wide; ticket too large", code.Size)
	}
}
