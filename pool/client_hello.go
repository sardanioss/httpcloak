package pool

import (
	"github.com/sardanioss/httpcloak/fingerprint"
	utls "github.com/sardanioss/utls"
)

func tcpClientHelloSpec(preset *fingerprint.Preset, id utls.ClientHelloID, seed int64) (*utls.ClientHelloSpec, error) {
	return fingerprint.SpecFor(id, seed, preset.SignatureAlgorithms)
}

func quicClientHelloSpec(preset *fingerprint.Preset, id utls.ClientHelloID, seed int64) (*utls.ClientHelloSpec, error) {
	return fingerprint.SpecFor(id, seed, preset.QUICSignatureAlgorithms)
}
