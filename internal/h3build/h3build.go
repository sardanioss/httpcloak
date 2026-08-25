// Package h3build constructs the QUIC config and the HTTP/3 SETTINGS map for a
// fingerprint preset.
//
// It exists for the same reason internal/h2build does: three entrypoints built
// the quic.Config literal separately and had drifted. The pool path applied
// neither QUICInitialStreamReceiveWindow nor QUICInitialConnectionReceiveWindow,
// so a preset that sets them, which is every iOS Chrome and Safari-family one,
// emitted quic-go's defaults there and the preset's values through the
// transport path. Those are initial_max_stream_data_bidi_remote and
// initial_max_data on the wire: transport parameters the server reads directly
// off the handshake.
package h3build

import (
	"time"

	"github.com/sardanioss/httpcloak/fingerprint"
	"github.com/sardanioss/quic-go"
	utls "github.com/sardanioss/utls"
)

// H3 SETTINGS identifiers.
const (
	SettingQPACKMaxTableCapacity = 0x1
	SettingMaxFieldSectionSize   = 0x6
	SettingQPACKBlockedStreams   = 0x7
	SettingH3Datagram            = 0x33
)

// DefaultIdleTimeout is what a connection uses when nothing overrides it.
const DefaultIdleTimeout = 30 * time.Second

// QUICOptions are the things a call site knows that the preset does not.
type QUICOptions struct {
	// Preset is the profile being impersonated. Required.
	Preset *fingerprint.Preset

	// IdleTimeout is the QUIC max_idle_timeout. Zero means DefaultIdleTimeout.
	IdleTimeout time.Duration

	// TransportParameterShuffleSeed pins the transport-parameter order, and
	// production leaves it at zero so the order is reshuffled per connection.
	//
	// It is NOT the session's ClientHello shuffle seed, and the two must not be
	// conflated. Chrome permutes its TLS extensions once per profile, so one
	// session holding one extension order is right; it reshuffles transport
	// parameters on every serialization, so a session holding one parameter
	// order means every connection that session opens carries a byte-identical
	// ID sequence. That is detectable with no probability argument at all:
	// strip the GREASE id, length and payload from two connections and compare.
	TransportParameterShuffleSeed int64

	ClientHelloID *utls.ClientHelloID
	CachedSpec    *utls.ClientHelloSpec
	ECHConfigList []byte

	// AdditionalTransportParameters is resolved by the caller, because it can
	// need a context and a live RTT measurement.
	AdditionalTransportParameters map[uint64][]byte

	// InitialPacketSize overrides the preset's value. MASQUE needs 1200.
	InitialPacketSize uint16

	// Tunnelled marks a connection running inside a MASQUE tunnel. The flow
	// control and packet sizing then come from the tunnel's constraints rather
	// than from the profile, because the outer connection is what the server
	// sees and this inner one is not being fingerprinted.
	Tunnelled bool
}

// QUICConfig builds the QUIC config for one preset.
func QUICConfig(o QUICOptions) *quic.Config {
	p := o.Preset

	idle := o.IdleTimeout
	if idle <= 0 {
		idle = DefaultIdleTimeout
	}

	initialPacketSize := p.H3QUICInitialPacketSize()
	if o.InitialPacketSize > 0 {
		initialPacketSize = o.InitialPacketSize
	}

	cfg := &quic.Config{
		MaxIdleTimeout: idle,

		// The keep-alive PING. Half the idle timeout is what keeps a
		// connection alive while a request is outstanding, which is what a
		// browser does too; what a browser does NOT do is keep pinging once
		// the last stream has closed. That gating lives in the QUIC layer,
		// because only it knows the stream count.
		KeepAlivePeriod: idle / 2,

		MaxIncomingStreams:    p.H3QUICMaxIncomingStreams(),
		MaxIncomingUniStreams: p.H3QUICMaxIncomingUniStreams(),
		Allow0RTT:             p.H3QUICAllow0RTT(),

		// Always on at the QUIC level; the H3 SETTINGS decide what each
		// profile advertises.
		EnableDatagrams: true,

		InitialPacketSize: initialPacketSize,

		// Path MTU discovery is off. Chromium leaves it off unless the
		// embedder asks for it, and nothing on the ordinary navigation path
		// does. Left on, quic-go probes within the first handful of packets,
		// where Chromium's own search would not start until the peer's 100th,
		// and it will probe past 1400, which is Chromium's hard ceiling. Both
		// are visible as datagram lengths with no capture tooling at all.
		DisablePathMTUDiscovery: true,

		DisableClientHelloScrambling:  p.H3QUICDisableHelloScramble(),
		ChromeStyleInitialPackets:     p.H3QUICChromeStyleInitial(),
		ClientHelloID:                 o.ClientHelloID,
		CachedClientHelloSpec:         o.CachedSpec,
		TransportParameterOrder:       TransportParamOrder(p.H3QUICTransportParamOrder()),
		TransportParameterShuffleSeed: o.TransportParameterShuffleSeed,
		AdditionalTransportParameters: o.AdditionalTransportParameters,
		MaxDatagramFrameSize:          p.H3QUICMaxDatagramFrameSize(),
	}

	if len(o.ECHConfigList) > 0 {
		cfg.ECHConfigList = o.ECHConfigList
	}

	if o.Tunnelled {
		// The tunnel's numbers, not the profile's. Nothing here is a
		// fingerprint: the observer sees the outer connection.
		cfg.InitialStreamReceiveWindow = 512 * 1024
		cfg.MaxStreamReceiveWindow = 6 * 1024 * 1024
		cfg.InitialConnectionReceiveWindow = 15 * 1024 * 1024 / 2
		cfg.MaxConnectionReceiveWindow = 15 * 1024 * 1024
		return cfg
	}

	// Per-profile flow control. Zero means "leave quic-go's default", which is
	// what the Chrome-family profiles want because they match it already. The
	// Safari and iOS Chrome profiles set their own, and those values go on the
	// wire as initial_max_stream_data_bidi_remote and initial_max_data.
	if v := p.H3QUICInitialStreamReceiveWindow(); v != 0 {
		cfg.InitialStreamReceiveWindow = v
	}
	if v := p.H3QUICInitialConnectionReceiveWindow(); v != 0 {
		cfg.InitialConnectionReceiveWindow = v
	}
	return cfg
}

// TransportParamOrder converts a preset's string to the quic-go mode.
func TransportParamOrder(mode string) quic.TransportParameterOrderMode {
	if mode == "random" {
		return quic.TransportParameterOrderDefault
	}
	return quic.TransportParameterOrderChrome
}

// Settings builds the HTTP/3 SETTINGS map, including the GREASE entry.
//
// greaseID and greaseValue are supplied by the caller so the randomness stays
// in one place and a test can pin it.
func Settings(p *fingerprint.Preset, greaseID, greaseValue uint64) map[uint64]uint64 {
	settings := map[uint64]uint64{
		SettingQPACKMaxTableCapacity: p.H3QPACKMaxTableCapacity(),
		SettingQPACKBlockedStreams:   p.H3QPACKBlockedStreams(),
		greaseID:                     greaseValue,
	}
	if maxField := p.H3MaxFieldSectionSize(); maxField > 0 {
		settings[SettingMaxFieldSectionSize] = maxField
	}
	if p.H3EnableDatagrams() {
		settings[SettingH3Datagram] = 1
	}
	return settings
}
