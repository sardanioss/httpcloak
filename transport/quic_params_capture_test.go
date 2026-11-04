package transport

import (
	"encoding/base64"
	"encoding/binary"
	"testing"

	"github.com/sardanioss/httpcloak/fingerprint"
	utls "github.com/sardanioss/utls"
)

// max_idle_timeout 30000 and initial_max_data 15728640, and neither of Chrome's
// browser-specific parameters.
var standardOnlyTransportParams = []byte{
	0x01, 0x04, 0x80, 0x00, 0x75, 0x30,
	0x04, 0x04, 0x80, 0xf0, 0x00, 0x00,
}

// The standard parameters plus the two Chrome sends: version_information
// (QUICv1 chosen, a GREASE label and QUICv1 available) and
// google_connection_options "ORIGNOIP".
var chromeTransportParams = append(append([]byte{}, standardOnlyTransportParams...),
	0x11, 0x0c, 0x00, 0x00, 0x00, 0x01, 0xaa, 0xba, 0x2a, 0x0a, 0x00, 0x00, 0x00, 0x01,
	0x71, 0x28, 0x08, 'O', 'R', 'I', 'G', 'N', 'O', 'I', 'P',
)

func loadCapturePreset(t *testing.T, basedOn, tlsBlock, extra string) *fingerprint.Preset {
	t.Helper()
	p, err := fingerprint.LoadAndBuildPresetFromJSON([]byte(`{"preset":{"name":"quic-capture-params",` +
		`"based_on":"` + basedOn + `","tls":{` + tlsBlock + `}` + extra + `}}`))
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	return p
}

// A preset carrying a TCP and a QUIC capture has neither identity left, since
// each capture clears the one it replaces. Asking the identity whether to send
// Chrome's parameters therefore answered no for a real Chrome QUIC capture that
// carries both. The capture is the record of what the client sends, so it
// decides, and it decides the same way whichever preset it was layered on.
func TestCapturedChromeQUICHelloSendsItsChromeParams(t *testing.T) {
	tcp := base64.StdEncoding.EncodeToString(rawHello(t, utls.HelloChrome_146_Windows, nil))
	quic := base64.StdEncoding.EncodeToString(rawHello(t, utls.HelloChrome_146_QUIC, chromeTransportParams))
	both := `"raw_client_hello":"` + tcp + `","raw_quic_client_hello":"` + quic + `"`

	for _, tc := range []struct {
		name, basedOn, tls, extra, wantOptions string
	}{
		{"both captures", "chrome-latest", both, "", "ORIGNOIP"},
		{"on a safari base", "safari-18", `"raw_quic_client_hello":"` + quic + `"`, "", "ORIGNOIP"},
		{"preset options win", "chrome-latest", both, `,"http3":{"quic_connection_options":["ORIG"]}`, "ORIG"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := loadCapturePreset(t, tc.basedOn, tc.tls, tc.extra)
			params := AdditionalTransportParamsForPreset(p, nil, "", 0)

			versionInfo, ok := params[tpVersionInformation]
			if !ok {
				t.Error("version_information (0x11) absent, but the capture carries it")
			}
			if len(versionInfo) != 12 || binary.BigEndian.Uint32(versionInfo) != 1 {
				t.Errorf("version_information = % x, want QUICv1 chosen with QUICv1 and one GREASE available", versionInfo)
			}
			if got := string(params[tpGoogleConnectionOptions]); got != tc.wantOptions {
				t.Errorf("google_connection_options = %q, want %q", got, tc.wantOptions)
			}
		})
	}
}

// The negative half: a capture without the parameters sends neither, even on
// a Chrome base whose identity alone would have sent both.
func TestCapturedQUICHelloWithoutChromeParamsSendsNeither(t *testing.T) {
	quic := base64.StdEncoding.EncodeToString(rawHello(t, utls.HelloChrome_146_QUIC, standardOnlyTransportParams))
	p := loadCapturePreset(t, "chrome-latest", `"raw_quic_client_hello":"`+quic+`"`, "")

	params := AdditionalTransportParamsForPreset(p, nil, "", 0)
	if params == nil {
		t.Fatal("got a nil map, which quic-go reads as the process-global parameter set")
	}
	if len(params) != 0 {
		t.Errorf("sent %d Chrome parameters the capture does not carry: %v", len(params), params)
	}
}

// A capture whose parameter list cannot be read is refused at load, since
// HTTP/3 reads that list to decide what to send.
func TestUnreadableCapturedTransportParametersAreRefused(t *testing.T) {
	truncated := []byte{0x01, 0x04, 0x80, 0x00}
	quic := base64.StdEncoding.EncodeToString(rawHello(t, utls.HelloChrome_146_QUIC, truncated))

	_, err := fingerprint.LoadAndBuildPresetFromJSON([]byte(`{"preset":{"name":"quic-truncated-params",` +
		`"based_on":"chrome-latest","tls":{"raw_quic_client_hello":"` + quic + `"}}}`))
	if err == nil {
		t.Fatal("loaded a QUIC capture whose transport parameters are truncated")
	}
}
