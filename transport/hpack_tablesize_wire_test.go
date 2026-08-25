package transport

import (
	"context"
	"encoding/hex"
	"fmt"
	"testing"
	"time"

	"github.com/sardanioss/httpcloak/fingerprint"
	"github.com/sardanioss/httpcloak/internal/h2build"
)

// presetOrSkip fetches a preset, reporting rather than skipping silently if a
// name in a table has been retired.
func presetOrSkip(t *testing.T, name string) *fingerprint.Preset {
	t.Helper()
	p := fingerprint.Get(name)
	if p == nil {
		t.Logf("preset %s is not registered; row not exercised", name)
	}
	return p
}

// Wire locks on the dynamic table size update we send back when a server
// advertises SETTINGS_HEADER_TABLE_SIZE.
//
// This is the one part of the HPACK encoder where the SERVER picks the input,
// so every divergence here is something a server can probe for rather than
// something the client happens to reveal. quiche echoes the peer's value;
// three separate defects meant we did not.
//
// The unit table lives in the fork, at http2/hpack/tablesize_test.go. These
// exist because the fork's config layer used to overwrite the encoder limit
// from the advertised setting AFTER the consumer built its transport, so a
// consumer-only change looked applied, passed the encoder tests, and left the
// wire unchanged.

// tableSizeUpdates returns the hex of every TABLE_SIZE_UPDATE instruction
// across the captured header blocks. 0x20 with a 5-bit prefix.
func tableSizeUpdates(t *testing.T, blocks [][]byte) []string {
	t.Helper()
	var out []string
	for _, b := range blocks {
		for _, in := range parseHPACK(t, b) {
			if in.Kind == "TABLE_SIZE_UPDATE" {
				out = append(out, fmt.Sprintf("%d", in.Size))
			}
		}
	}
	return out
}

func driveTableSize(t *testing.T, cfg h2Config, n int) *h2Server {
	t.Helper()
	s := startH2Server(t, cfg)

	tr := NewTransport("chrome-latest")
	tr.SetProtocol(ProtocolHTTP2)
	tr.SetInsecureSkipVerify(true)
	defer tr.Close()

	for i := 0; i < n; i++ {
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		_, err := tr.Do(ctx, &Request{Method: "GET", URL: s.url(fmt.Sprintf("/req%d", i))})
		cancel()
		if err != nil {
			t.Fatalf("request %d: %v", i, err)
		}
	}
	if got := len(s.headerBlocks()); got != n {
		t.Fatalf("captured %d header blocks, want %d", got, n)
	}
	return s
}

// A server advertising the RFC default has told us nothing new, so a browser
// says nothing back. Every Go HTTP/2 server advertises exactly this, so this
// was firing constantly.
func TestNoTableSizeUpdateForTheDefault(t *testing.T) {
	s := driveTableSize(t, h2Config{
		Settings: []h2Setting{{ID: 0x1, Val: 4096}},
	}, 2)
	if got := tableSizeUpdates(t, s.headerBlocks()); len(got) != 0 {
		t.Fatalf("sent table size updates %v for a peer advertising the default 4096, want none", got)
	}
}

// A value above our own advertised size is echoed, not clamped to ours. Our
// SETTINGS_HEADER_TABLE_SIZE describes our DECODER; the encoder limit governs
// the other direction and has no business rewriting what the peer asked for.
func TestTableSizeUpdateEchoesThePeer(t *testing.T) {
	for _, advertised := range []uint32{65537, 1048576} {
		t.Run(fmt.Sprint(advertised), func(t *testing.T) {
			s := driveTableSize(t, h2Config{
				Settings: []h2Setting{{ID: 0x1, Val: advertised}},
			}, 2)
			got := tableSizeUpdates(t, s.headerBlocks())
			want := []string{fmt.Sprint(advertised)}
			if len(got) != 1 || got[0] != want[0] {
				t.Fatalf("peer advertised %d, we sent updates %v, want %v",
					advertised, got, want)
			}
		})
	}
}

// Two SETTINGS frames carrying increasing values, both above the bound and
// both arriving with no header block encoded in between, are ONE update
// carrying the final size. The minimum is lowered against the bound, not
// against the running minimum; guarding on the running minimum makes the first
// value look like a decrease and puts it on the wire ahead of the second.
//
// Both frames landing before a block is encoded is the whole design here.
// Emitting a block resets the minimum, so a version that lets a block flush
// between the two SETTINGS produces identical bytes either way and asserts
// nothing at all. They go out back to back after response 1, with a pause
// before request 2, so the client has settled both before it encodes anything.
func TestTableSizeUpdateCountsOnceForIncreasingSizes(t *testing.T) {
	s := startH2Server(t, h2Config{
		MidSettings: map[int][][]h2Setting{
			1: {
				{{ID: 0x1, Val: 8192}},
				{{ID: 0x1, Val: 16384}},
			},
		},
	})

	tr := NewTransport("chrome-latest")
	tr.SetProtocol(ProtocolHTTP2)
	tr.SetInsecureSkipVerify(true)
	defer tr.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if _, err := tr.Do(ctx, &Request{Method: "GET", URL: s.url("/one")}); err != nil {
		t.Fatalf("request 1: %v", err)
	}
	time.Sleep(300 * time.Millisecond) // let both SETTINGS land
	if _, err := tr.Do(ctx, &Request{Method: "GET", URL: s.url("/two")}); err != nil {
		t.Fatalf("request 2: %v", err)
	}

	blocks := s.headerBlocks()
	if len(blocks) != 2 {
		t.Fatalf("captured %d header blocks, want 2", len(blocks))
	}
	if got := tableSizeUpdates(t, blocks[:1]); len(got) != 0 {
		t.Fatalf("block 1 carried table size updates %v; the preface advertised "+
			"no table size, so there was nothing to answer", got)
	}
	got := tableSizeUpdates(t, blocks[1:])
	if len(got) != 1 || got[0] != "16384" {
		t.Fatalf("block 2 carried table size updates %v, want exactly [16384]; "+
			"8192 was never below the bound when it arrived, so it is not a "+
			"minimum and must not be signalled", got)
	}
}

// The encoder limit is a fixed memory policy, not the profile's advertised
// size. Pinning it to the advertised size is what produced the clamped echo,
// and it is not observable from the wire when the peer stays below it, so it
// gets a direct assertion.
func TestEncoderTableLimitIsNotTheAdvertisedSize(t *testing.T) {
	for _, name := range []string{"chrome-latest", "firefox-latest", "safari-latest"} {
		p := presetOrSkip(t, name)
		if p == nil {
			continue
		}
		h2 := h2build.Transport(h2build.Options{Preset: p})
		if h2.MaxEncoderHeaderTableSize == p.HTTP2Settings.HeaderTableSize {
			t.Errorf("%s: encoder limit equals the advertised decoder size (%d); "+
				"they are different directions of the connection and must not "+
				"be the same knob", name, h2.MaxEncoderHeaderTableSize)
		}
		if h2.MaxDecoderHeaderTableSize != p.HTTP2Settings.HeaderTableSize {
			t.Errorf("%s: decoder capacity = %d, want the advertised %d",
				name, h2.MaxDecoderHeaderTableSize, p.HTTP2Settings.HeaderTableSize)
		}
	}
}

// The instruction stream around a table size update, byte for byte, so nobody
// re-derives the prefix while tuning the values above.
func TestTableSizeUpdateBytes(t *testing.T) {
	s := driveTableSize(t, h2Config{
		Settings: []h2Setting{{ID: 0x1, Val: 65536}},
	}, 2)
	blocks := s.headerBlocks()
	var found bool
	for _, b := range blocks {
		if len(b) >= 4 && hex.EncodeToString(b[:4]) == "3fe1ff03" {
			found = true
			break
		}
	}
	if !found {
		var got []string
		for _, b := range blocks {
			n := min(6, len(b))
			got = append(got, hex.EncodeToString(b[:n]))
		}
		t.Fatalf("no header block opened with 3fe1ff03 (table size update, 65536); "+
			"block prefixes were %v", got)
	}
}
