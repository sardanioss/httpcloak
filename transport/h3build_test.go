package transport

import (
	"testing"
	"time"

	"github.com/sardanioss/httpcloak/fingerprint"
	"github.com/sardanioss/httpcloak/internal/h3build"
)

// Locks on the QUIC config every HTTP/3 connection is built from.
//
// Three entrypoints used to build this literal separately, and they had
// drifted. The pool path applied neither QUICInitialStreamReceiveWindow nor
// QUICInitialConnectionReceiveWindow, so a profile that sets them got quic-go's
// defaults there and its own values through the transport. Those two are
// initial_max_stream_data_bidi_remote and initial_max_data on the wire:
// transport parameters the server reads straight off the handshake, with no
// request needed and no capture tooling.

// Path MTU discovery stays off.
//
// Chromium leaves it off unless the embedder asks, and nothing on the ordinary
// navigation path does. Left on, quic-go starts probing within the first
// handful of packets, where Chromium's own search would not begin until the
// peer's 100th, and it will probe past 1400, which is Chromium's hard ceiling.
// Measured against a real origin: probes at sent-packet indices 9, 13, 17 and
// 21 with lengths 1351, 1401, 1426 and 1439, while every other datagram in the
// session was at most 1250. Datagram lengths are free to read server-side.
func TestQUICConfigDisablesPathMTUDiscovery(t *testing.T) {
	for _, name := range []string{"chrome-latest", "firefox-latest", "safari-latest"} {
		p := presetOrSkip(t, name)
		if p == nil {
			continue
		}
		cfg := h3build.QUICConfig(h3build.QUICOptions{Preset: p})
		if !cfg.DisablePathMTUDiscovery {
			t.Errorf("%s: path MTU discovery is on", name)
		}
	}
}

// A profile's QUIC flow control reaches the config. This is the knob the pool
// path used to drop.
func TestQUICConfigCarriesPresetFlowControl(t *testing.T) {
	const (
		wantStream = uint64(2097152)
		wantConn   = uint64(16777216)
	)
	registerPreset(t, "h3-windows", `,"http3":{"quic_initial_stream_receive_window":2097152,"quic_initial_connection_receive_window":16777216}`)

	p := fingerprint.Get("h3-windows")
	if p == nil {
		t.Fatal("preset h3-windows did not register")
	}
	if got := p.H3QUICInitialStreamReceiveWindow(); got != wantStream {
		t.Fatalf("preset stream window = %d, want %d; the JSON key did not land", got, wantStream)
	}

	cfg := h3build.QUICConfig(h3build.QUICOptions{Preset: p})
	if cfg.InitialStreamReceiveWindow != wantStream {
		t.Errorf("InitialStreamReceiveWindow = %d, want %d; this goes on the wire "+
			"as initial_max_stream_data_bidi_remote",
			cfg.InitialStreamReceiveWindow, wantStream)
	}
	if cfg.InitialConnectionReceiveWindow != wantConn {
		t.Errorf("InitialConnectionReceiveWindow = %d, want %d; this goes on the "+
			"wire as initial_max_data",
			cfg.InitialConnectionReceiveWindow, wantConn)
	}
}

// A profile that sets nothing keeps quic-go's defaults, which is what the
// Chrome family wants because it matches them already. Setting an explicit
// zero would advertise a zero window and stall the connection.
func TestQUICConfigLeavesUnsetFlowControlAlone(t *testing.T) {
	p := presetOrSkip(t, "chrome-latest")
	if p == nil {
		return
	}
	cfg := h3build.QUICConfig(h3build.QUICOptions{Preset: p})
	if cfg.InitialStreamReceiveWindow != 0 || cfg.InitialConnectionReceiveWindow != 0 {
		t.Errorf("a profile that sets no windows produced stream=%d conn=%d; "+
			"want both left at zero so quic-go supplies its defaults",
			cfg.InitialStreamReceiveWindow, cfg.InitialConnectionReceiveWindow)
	}
}

// The tunnelled variant takes the tunnel's numbers, not the profile's, because
// an observer sees the outer connection. It also keeps its own packet size.
func TestQUICConfigTunnelledIgnoresPresetFlowControl(t *testing.T) {
	registerPreset(t, "h3-windows-tunnel", `,"http3":{"quic_initial_stream_receive_window":2097152}`)
	p := fingerprint.Get("h3-windows-tunnel")

	cfg := h3build.QUICConfig(h3build.QUICOptions{
		Preset:            p,
		InitialPacketSize: 1200,
		Tunnelled:         true,
	})
	if cfg.InitialStreamReceiveWindow == 2097152 {
		t.Error("the tunnelled config took the profile's stream window; inside a " +
			"tunnel the flow control is the tunnel's business")
	}
	if cfg.InitialPacketSize != 1200 {
		t.Errorf("InitialPacketSize = %d, want the 1200 the tunnel requires",
			cfg.InitialPacketSize)
	}
	if !cfg.DisablePathMTUDiscovery {
		t.Error("the tunnelled config left path MTU discovery on")
	}
}

// The idle timeout defaults and the keep-alive stays at half of it.
func TestQUICConfigIdleTimeout(t *testing.T) {
	p := presetOrSkip(t, "chrome-latest")
	if p == nil {
		return
	}
	cfg := h3build.QUICConfig(h3build.QUICOptions{Preset: p})
	if cfg.MaxIdleTimeout != h3build.DefaultIdleTimeout {
		t.Errorf("MaxIdleTimeout = %v, want %v", cfg.MaxIdleTimeout, h3build.DefaultIdleTimeout)
	}
	if cfg.KeepAlivePeriod != h3build.DefaultIdleTimeout/2 {
		t.Errorf("KeepAlivePeriod = %v, want half the idle timeout", cfg.KeepAlivePeriod)
	}

	cfg = h3build.QUICConfig(h3build.QUICOptions{Preset: p, IdleTimeout: 20 * time.Second})
	if cfg.MaxIdleTimeout != 20*time.Second || cfg.KeepAlivePeriod != 10*time.Second {
		t.Errorf("with a 20s idle timeout: MaxIdleTimeout=%v KeepAlivePeriod=%v",
			cfg.MaxIdleTimeout, cfg.KeepAlivePeriod)
	}
}

// The SETTINGS map is the same from either entrypoint. It used to be built
// twice from two copies of the same four constants.
func TestH3SettingsMatchThePreset(t *testing.T) {
	p := presetOrSkip(t, "chrome-latest")
	if p == nil {
		return
	}
	const greaseID, greaseValue = uint64(0x1f*1234567890 + 0x21), uint64(42)
	s := h3build.Settings(p, greaseID, greaseValue)

	if got := s[h3build.SettingQPACKMaxTableCapacity]; got != p.H3QPACKMaxTableCapacity() {
		t.Errorf("QPACK max table capacity = %d, want %d", got, p.H3QPACKMaxTableCapacity())
	}
	if got := s[h3build.SettingQPACKBlockedStreams]; got != p.H3QPACKBlockedStreams() {
		t.Errorf("QPACK blocked streams = %d, want %d", got, p.H3QPACKBlockedStreams())
	}
	if got := s[greaseID]; got != greaseValue {
		t.Errorf("GREASE setting = %d, want %d", got, greaseValue)
	}
	if p.H3EnableDatagrams() && s[h3build.SettingH3Datagram] != 1 {
		t.Error("the profile enables H3 datagrams and the setting is absent")
	}
	if !p.H3EnableDatagrams() {
		if _, ok := s[h3build.SettingH3Datagram]; ok {
			t.Error("the profile does not enable H3 datagrams and the setting is present")
		}
	}
}
