package pool

import (
	"github.com/sardanioss/httpcloak/fingerprint"
	utls "github.com/sardanioss/utls"
)

// Both helpers go through SpecForWithAnchors rather than SpecFor. SpecFor
// passes no trust anchors, so every pooled connection was building a spec
// without the trust_anchors extension while the transport path built one with
// it: one profile, two different ClientHellos, decided by whether the caller
// happened to use a pool. That is the same drift that moved the quic.Config
// and the HTTP/3 SETTINGS into internal/h3build.
func tcpClientHelloSpec(preset *fingerprint.Preset, id utls.ClientHelloID, seed int64) (*utls.ClientHelloSpec, error) {
	return fingerprint.SpecForWithAnchors(id, seed, preset.SignatureAlgorithms, preset.TrustAnchors)
}

// quicClientHelloSpec passes the pool's seed through, and SpecForQUICWithAnchors
// ignores it: on QUIC the extension order is redrawn per connection. The pool
// holding one seed for its lifetime is exactly what used to pin that order.
func quicClientHelloSpec(preset *fingerprint.Preset, id utls.ClientHelloID, seed int64) (*utls.ClientHelloSpec, error) {
	return fingerprint.SpecForQUICWithAnchors(id, seed, preset.QUICSignatureAlgorithms, preset.TrustAnchors, preset.QUICTrustAnchorShuffle)
}

// referenceQUICSpecs builds the fresh and the resuming QUIC hello once, through
// the shared resolver, so a dial can tell whether either is buildable. A nil
// resuming spec means the preset cannot resume, and the pool then keeps no
// session cache for it. The order they carry is not reused: each connection
// draws its own.
func referenceQUICSpecs(preset *fingerprint.Preset, seed int64) (fresh, resume *utls.ClientHelloSpec) {
	if preset == nil {
		return nil, nil
	}
	if spec, _, err := fingerprint.ResolveQUICClientHelloSpec(preset, false, seed); err == nil {
		fresh = spec
	}
	if fingerprint.HasQUICPSKVariant(preset) {
		if spec, _, err := fingerprint.ResolveQUICClientHelloSpec(preset, true, seed); err == nil {
			resume = spec
		}
	}
	return fresh, resume
}
