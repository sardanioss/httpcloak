package client

import (
	"crypto/x509"
	"testing"

	"github.com/sardanioss/httpcloak/transport"
)

// Regression lock: rotating a proxy must not drop the caller's certificate
// verification from the HTTP/3 transports.
//
// SetProxy and SetUDPProxy close and recreate the HTTP/3 transports, and used to
// re-apply only InsecureSkipVerify. The verification hooks live on the transport
// objects, not on the Client, so they were silently lost: a client that pinned a
// certificate and then rotated its proxy - the ordinary usage pattern for this
// library - went back to accepting anything the system roots accept, on the
// protocol tried first, with no error.
//
// Verified end to end at the time of the fix: with a rejecting callback, an
// HTTP/3 request aborted before the change and still aborts after SetProxy and
// SetUDPProxy; before the fix both of those succeeded.
func TestH3VerifyHooksSurviveProxyRebuild(t *testing.T) {
	c := NewClient("chrome-latest",
		WithVerifyPeerCertificate(func(_ [][]byte, _ [][]*x509.Certificate) error { return nil }),
	)
	defer c.Close()

	installed := func(stage string) {
		t.Helper()
		if c.quicManager == nil && c.masqueTransport == nil && c.socks5H3Transport == nil {
			t.Fatalf("%s: no HTTP/3 transport exists to check", stage)
		}
		if c.quicManager != nil && c.quicManager.TLSVerify() == nil {
			t.Errorf("%s: quicManager lost its verification hooks, so HTTP/3 silently stopped verifying", stage)
		}
		if c.masqueTransport != nil && c.masqueTransport.TLSVerify() == nil {
			t.Errorf("%s: masqueTransport lost its verification hooks", stage)
		}
		if c.socks5H3Transport != nil && c.socks5H3Transport.TLSVerify() == nil {
			t.Errorf("%s: socks5H3Transport lost its verification hooks", stage)
		}
	}

	installed("baseline")
	c.SetProxy("")
	installed("after SetProxy")
	c.SetUDPProxy("")
	installed("after SetUDPProxy")
}

// The helper must report nothing when the caller supplied nothing, so an
// ordinary client is not handed an empty non-nil config.
func TestTLSVerifyFromConfigNilWhenUnset(t *testing.T) {
	c := NewClient("chrome-latest")
	defer c.Close()
	if v := c.tlsVerifyFromConfig(); v != nil {
		t.Errorf("expected nil when no verification was configured, got %+v", v)
	}
	var _ *transport.TLSVerify = c.tlsVerifyFromConfig()
}
