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

func quicClientHelloSpec(preset *fingerprint.Preset, id utls.ClientHelloID, seed int64) (*utls.ClientHelloSpec, error) {
	return fingerprint.SpecForWithAnchors(id, seed, preset.QUICSignatureAlgorithms, preset.TrustAnchors)
}
