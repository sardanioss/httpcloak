package transport

import (
	"encoding/base64"
	"testing"

	"github.com/sardanioss/httpcloak/dns"
	"github.com/sardanioss/httpcloak/fingerprint"
	utls "github.com/sardanioss/utls"
)

// rawHello builds a captured-shape hello from a parrot. transportParams is the
// quic_transport_parameters body, for a QUIC parrot.
func rawHello(t *testing.T, id utls.ClientHelloID, transportParams []byte) []byte {
	t.Helper()
	spec, err := utls.UTLSIdToSpecWithSeed(id, 1)
	if err != nil {
		t.Fatalf("build %s spec: %v", id.Str(), err)
	}
	for _, ext := range spec.Extensions {
		if qtp, ok := ext.(*utls.QUICTransportParametersExtension); ok {
			qtp.RawData = transportParams
		}
	}
	conn := utls.UClient(nil, &utls.Config{ServerName: "example.com", OmitEmptyPsk: true}, utls.HelloCustom)
	if err := conn.ApplyPreset(&spec); err != nil {
		t.Fatalf("apply %s spec: %v", id.Str(), err)
	}
	if err := conn.BuildHandshakeState(); err != nil {
		t.Fatalf("build handshake state: %v", err)
	}
	hello := conn.HandshakeState.Hello.Raw
	return append([]byte{0x16, 0x03, 0x01, byte(len(hello) >> 8), byte(len(hello))}, hello...)
}

// The session cache is what lets HTTP/3 resume at all, and it is attached only
// when the preset has a resumption hello to send. A captured QUIC PSK hello
// has to count, or a raw QUIC preset never resumes however it was written.
func TestRawQUICPSKCaptureEnablesTheSessionCache(t *testing.T) {
	quic := base64.StdEncoding.EncodeToString(rawHello(t, utls.HelloChrome_146_QUIC, nil))

	for _, tc := range []struct {
		name, tls string
		want      bool
	}{
		{"with PSK capture", `"raw_quic_client_hello":"` + quic + `","raw_quic_psk_client_hello":"` + quic + `"`, true},
		{"without PSK capture", `"raw_quic_client_hello":"` + quic + `"`, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p, err := fingerprint.LoadAndBuildPresetFromJSON([]byte(`{"preset":{"name":"h3-raw-quic",` +
				`"based_on":"chrome-latest","tls":{` + tc.tls + `}}}`))
			if err != nil {
				t.Fatalf("load: %v", err)
			}
			tr, err := NewHTTP3Transport(p, dns.NewCache())
			if err != nil {
				t.Fatalf("NewHTTP3Transport: %v", err)
			}
			defer tr.Close()

			if got := tr.tlsConfig.ClientSessionCache != nil; got != tc.want {
				t.Errorf("session cache attached = %v, want %v", got, tc.want)
			}
			if spec := tr.getSpecForHost("example.com"); !fingerprint.SpecHasQUICTransportParameters(spec) {
				t.Error("the dial spec is not the QUIC capture")
			}
		})
	}
}
