// Package h2build constructs the HTTP/2 transport for a fingerprint preset.
//
// It exists because two entrypoints of this library used to build that struct
// literal independently, and they had drifted. The pool path set no
// HeaderPriorityFunc, so per-request priority tables never applied to a
// Session; it also set neither ReadIdleTimeout nor DisableCookieSplit. Two
// callers of one library disagreeing about the same preset is exactly the kind
// of thing a profile is supposed to prevent.
package h2build

import (
	"strconv"
	"strings"

	http "github.com/sardanioss/http"
	"github.com/sardanioss/httpcloak/fingerprint"
	"github.com/sardanioss/net/http2"
	"github.com/sardanioss/net/http2/hpack"
)

// encoderTableSizeLimit is the largest dynamic table we are willing to
// maintain for ENCODING. It is a memory policy, not a fingerprint of anything.
//
// It used to be the profile's own SETTINGS_HEADER_TABLE_SIZE, which is a
// category error: that value is what we tell the peer our DECODER can hold,
// and the encoder limit governs the other direction of the connection. The
// consequence was visible on the wire. A peer advertising more than our own
// number got a table size update carrying our number back, which is a
// discrepancy the peer chooses and can therefore probe for; quiche sets its
// bound to the maximum representable value and lets the peer's value through
// untouched.
//
// 16 MiB rather than unbounded because the cost is real and one-directional.
// The entry table shrinks by reslicing and never returns capacity, and the two
// lookup maps never shrink their bucket arrays after a delete, so a connection
// holds its high-water mark for its whole life. At this ceiling that is
// roughly half a million entries and about 36 MB as the pathological worst
// case. The growth vector is cheaper than "deliberately hostile" too: neither
// cookie jar caps cookies per domain, so a server that keeps issuing Set-Cookie
// grows the indexed crumb count directly.
const encoderTableSizeLimit = 16 << 20

// Options are the few things a call site knows that the preset does not.
type Options struct {
	// Preset is the profile being impersonated. Required.
	Preset *fingerprint.Preset

	// TLSOnly suppresses the preset's User-Agent, for callers that want to
	// supply every header themselves. (The automatic Accept-Encoding it used
	// to disable is now off for every transport.)
	TLSOnly bool

	// PseudoHeaderOrder overrides the preset's pseudo-header order. Used by
	// the Akamai custom-fingerprint path, where the order comes from a
	// user-supplied string rather than from the profile.
	PseudoHeaderOrder []string
}

// Transport builds the HTTP/2 transport for one preset.
func Transport(o Options) *http2.Transport {
	p := o.Preset
	s := p.HTTP2Settings

	userAgent := p.UserAgent
	if o.TLSOnly {
		userAgent = ""
	}

	pseudoOrder := o.PseudoHeaderOrder
	if len(pseudoOrder) == 0 {
		pseudoOrder = PseudoHeaderOrder(p)
	}

	// DisableCompression: never add "accept-encoding: gzip" on the caller's
	// behalf. Every preset carries its own Accept-Encoding, so this only ever
	// fired for a request without one: ExactHeaders, a custom order that leaves
	// it out, or TLS-only passthrough. Each of those promises the headers go
	// out as given, and a browser never adds one either. Bodies are decoded
	// from Content-Encoding by the transport, not here.
	return &http2.Transport{
		AllowHTTP:                  false,
		DisableCompression:         true,
		StrictMaxConcurrentStreams: false,

		// Response header maps keep the wire's lowercase names. This library
		// lowercases every response header for its own map anyway, so the
		// canonical spelling was built per field only to be converted back
		// out of. Everything that still reads the fork's map before the
		// conversion goes through responseContentEncoding or addresses the
		// exact key, never http.Header's canonicalising accessors.
		WireCaseResponseHeaders:   true,
		MaxHeaderListSize:         s.MaxHeaderListSize,
		MaxReadFrameSize:          s.MaxFrameSize,
		MaxDecoderHeaderTableSize: s.HeaderTableSize,
		MaxEncoderHeaderTableSize: encoderTableSizeLimit,

		// The periodic health-check ping, off for every shipped preset. It is
		// a PING with no frame behind it on a fixed timer, and Chromium's
		// pings are all attached to a frame it is about to send, so there is
		// no interval that makes the shape right. See H2IdlePing.
		ReadIdleTimeout: p.H2IdlePing(),
		PingTimeout:     p.H2PrefacePingHang(),

		// The preface ping, which a browser does send: one PING alongside a
		// request on a connection whose peer has been quiet.
		PrefacePingIdle: p.H2PrefacePingIdle(),
		PrefacePingHang: p.H2PrefacePingHang(),

		ConnectionFlow:     s.ConnectionWindowUpdate,
		Settings:           Settings(s),
		SettingsOrder:      SettingsOrder(p),
		DisableCookieSplit: p.H2DisableCookieSplit(),
		PseudoHeaderOrder:  pseudoOrder,

		// Chrome 120+ uses RFC 9218 extensible priorities (the priority
		// header) rather than RFC 7540 PRIORITY frames. StreamWeight 0 means
		// no PRIORITY data on the wire.
		HeaderPriority: func() *http2.PriorityParam {
			if s.StreamWeight == 0 {
				return nil
			}
			return &http2.PriorityParam{
				Weight:    uint8(s.StreamWeight - 1), // wire format is weight-1
				Exclusive: s.StreamExclusive,
				StreamDep: 0,
			}
		}(),

		// Per-request priority. Chrome derives a stream's weight and its
		// priority header from one request priority (spdy_session.cc and
		// spdy_http_utils.cc both start from HIGHEST - priority), so a request
		// that carries its own priority header gets the weight that goes with
		// it. The dest is only a stand-in for when it does not: a favicon is
		// dest image like an <img>, but goes at u=1 where the <img> goes at u=2.
		// nil, for an unknown dest and no header, falls back to HeaderPriority.
		//
		// That is Chromium's model only. Firefox's weight is not a function of
		// the urgency (u=2 and u=4 both go at 22), so a "table" preset takes
		// its weight from the table whatever header the request carries.
		//
		// Both names are looked up without regard to case, because exact
		// headers keep them lowercase and Header.Get would miss them.
		HeaderPriorityFunc: func() func(*http.Request) *http2.PriorityParam {
			if !p.H2HasPriorityTable() {
				return nil
			}
			chromium := p.H2PriorityModel() == fingerprint.PriorityModelChromium
			return func(req *http.Request) *http2.PriorityParam {
				weight, exclusive, _, ok := p.H2PriorityFor(headerValue(req.Header, "Sec-Fetch-Dest"))
				if v := headerValue(req.Header, "Priority"); chromium && v != "" {
					if !ok {
						exclusive = s.StreamExclusive
					}
					weight, ok = fingerprint.PriorityFromUrgency(urgencyOf(v)), true
				}
				if !ok {
					return nil
				}
				return &http2.PriorityParam{
					Weight:    uint8(weight - 1), // weight is 1..256, never 0
					Exclusive: exclusive,
					StreamDep: 0,
				}
			}
		}(),

		// Chromium chains each new stream onto the newest open stream at the
		// same or a higher priority; Firefox and the rest name stream 0.
		ChainStreamDependencies: p.H2PriorityModel() == fingerprint.PriorityModelChromium,

		HeaderOrder:          p.H2HeaderOrder(),
		UserAgent:            userAgent,
		StreamPriorityMode:   StreamPriorityMode(p.H2StreamPriorityMode()),
		HPACKIndexingPolicy:  HPACKIndexingPolicy(p.H2HPACKIndexingPolicy()),
		DataFrameMaxSize:     p.H2DataFrameMaxSize(),
		HPACKRepresentations: HPACKRepresentations(p.H2HPACKRepresentation()),
		HPACKNeverIndex:      p.H2HPACKNeverIndex(),
	}
}

// PseudoHeaderOrder is the preset's pseudo-header order, or the heuristic.
func PseudoHeaderOrder(p *fingerprint.Preset) []string {
	if order := p.H2PseudoHeaderOrder(); order != nil {
		return order
	}
	if p.HTTP2Settings.NoRFC7540Priorities {
		return []string{":method", ":scheme", ":path", ":authority"} // Safari
	}
	return []string{":method", ":authority", ":scheme", ":path"} // Chrome
}

// Settings builds the SETTINGS map. Every conditional entry here has a
// matching entry in SettingsOrder; changing one without the other puts a
// setting on the wire in an order nothing produces.
func Settings(s fingerprint.HTTP2Settings) map[http2.SettingID]uint32 {
	out := map[http2.SettingID]uint32{
		http2.SettingHeaderTableSize:   s.HeaderTableSize,
		http2.SettingEnablePush:        boolToUint32(s.EnablePush),
		http2.SettingInitialWindowSize: s.InitialWindowSize,
		http2.SettingMaxHeaderListSize: s.MaxHeaderListSize,
	}
	if s.MaxConcurrentStreams > 0 {
		out[http2.SettingMaxConcurrentStreams] = s.MaxConcurrentStreams
	}
	if s.MaxFrameSize > 0 {
		out[http2.SettingMaxFrameSize] = s.MaxFrameSize
	}
	if s.NoRFC7540Priorities {
		out[http2.SettingNoRFC7540Priorities] = 1
	}
	return out
}

// SettingsOrder is the preset's explicit order, or one derived to stay
// consistent with Settings.
func SettingsOrder(p *fingerprint.Preset) []http2.SettingID {
	if order := p.H2SettingsOrder(); order != nil {
		out := make([]http2.SettingID, len(order))
		for i, id := range order {
			out[i] = http2.SettingID(id)
		}
		return out
	}

	s := p.HTTP2Settings
	var out []http2.SettingID
	if s.NoRFC7540Priorities {
		out = []http2.SettingID{ // Safari and iOS base order: 2, 4
			http2.SettingEnablePush,
			http2.SettingInitialWindowSize,
		}
	} else {
		out = []http2.SettingID{ // Chrome base order: 1, 2, 4, 6
			http2.SettingHeaderTableSize,
			http2.SettingEnablePush,
			http2.SettingInitialWindowSize,
			http2.SettingMaxHeaderListSize,
		}
	}
	if s.MaxConcurrentStreams > 0 {
		out = append(out, http2.SettingMaxConcurrentStreams)
	}
	if s.MaxFrameSize > 0 {
		out = append(out, http2.SettingMaxFrameSize)
	}
	if s.NoRFC7540Priorities {
		out = append(out, http2.SettingNoRFC7540Priorities)
	}
	return out
}

// StreamPriorityMode converts the preset's string to the fork's constant.
func StreamPriorityMode(mode string) http2.StreamPriorityMode {
	if mode == "default" {
		return http2.StreamPriorityDefault
	}
	return http2.StreamPriorityChrome
}

// HPACKIndexingPolicy converts the preset's string to the encoder's constant.
func HPACKIndexingPolicy(policy string) hpack.IndexingPolicy {
	switch policy {
	case "never":
		return hpack.IndexingNever
	case "always":
		return hpack.IndexingAlways
	case "default":
		return hpack.IndexingDefault
	default:
		return hpack.IndexingChrome
	}
}

// HPACKRepresentations converts a preset's per-name representation overrides
// into the encoder's typed form. Names are validated at preset load time, so
// an unparseable value here can only mean a preset built by some other route;
// it is dropped rather than silently treated as a different representation.
func HPACKRepresentations(m map[string]string) map[string]hpack.Representation {
	if len(m) == 0 {
		return nil
	}
	out := make(map[string]hpack.Representation, len(m))
	for name, rep := range m {
		if r, ok := hpack.ParseRepresentation(rep); ok && r != hpack.RepresentationDefault {
			out[name] = r
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func boolToUint32(b bool) uint32 {
	if b {
		return 1
	}
	return 0
}

// headerValue is the first value of a header, whatever case its name was
// stored in.
func headerValue(h http.Header, name string) string {
	if v := h.Get(name); v != "" {
		return v
	}
	for k, vs := range h {
		if len(vs) > 0 && strings.EqualFold(k, name) {
			return vs[0]
		}
	}
	return ""
}

// urgencyOf reads the urgency from an RFC 9218 priority field value. A
// repeated key takes its last value, as in any structured field dictionary,
// and a value with no u=, or one that is not an integer from 0 to 7, has the
// default urgency, 3, as section 4.1 says.
func urgencyOf(v string) uint8 {
	last := ""
	for _, member := range strings.Split(v, ",") {
		member, _, _ = strings.Cut(member, ";") // drop parameters
		if key, val, _ := strings.Cut(strings.TrimSpace(member), "="); key == "u" {
			last = strings.TrimSpace(val)
		}
	}
	if u, err := strconv.Atoi(last); err == nil && u >= 0 && u <= 7 {
		return uint8(u)
	}
	return 3
}
