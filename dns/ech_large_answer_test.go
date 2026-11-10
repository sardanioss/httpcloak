package dns

import (
	"bytes"
	"context"
	"testing"
)

// An HTTPS answer over 512 bytes, as Cloudflare's for cloudflare-ech.com now
// is, still yields its ECH config. The query sent no EDNS0, so the client read
// into a 512-byte buffer, failed to unpack ("overflow unpacking uint16") and
// the host was taken to have no ECH.
func TestECHConfigFromAnAnswerOver512Bytes(t *testing.T) {
	want := bytes.Repeat([]byte{0xec}, 600)
	SetECHDNSServers([]string{slowECHServer(t, 0, want)})
	t.Cleanup(func() { SetECHDNSServers(nil) })

	const host = "ech-large-answer.example"
	InvalidateECHConfig(host)
	t.Cleanup(func() { InvalidateECHConfig(host) })

	got, err := FetchECHConfigs(context.Background(), host)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("got a %d-byte ECH config, want the %d-byte one served", len(got), len(want))
	}
}
