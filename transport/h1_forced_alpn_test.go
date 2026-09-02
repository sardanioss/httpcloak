package transport

import (
	"net"
	"testing"

	"github.com/sardanioss/httpcloak/fingerprint"
	utls "github.com/sardanioss/utls"
)

// Forced HTTP/1.1 has to reach the wire, and it has to be self-consistent.
//
// The ClientHelloID branch used to pass the ID straight to UClient, call
// BuildHandshakeState and then edit uconn.Extensions. Those edits only landed
// when something later forced a re-marshal, which a pre_shared_key extension
// does and padding does not. So the ALPN rewrite survived on Chrome and was
// silently dropped on every WebKit preset, the client advertised
// [h2, http/1.1] while its config said [http/1.1], the server picked h2, and
// uTLS rejected its own peer's choice:
//
//	tls: server selected unadvertised ALPN protocol
//
// A total handshake failure, not a fingerprint tell. Measured against a live
// origin on safari-18, safari-latest and chrome-151-ios.

// helloOf builds the ClientHello a forced-H1 connection would send.
func helloOf(t *testing.T, presetName string) *utls.UConn {
	t.Helper()
	p := fingerprint.GetStrict(presetName)
	if p == nil {
		t.Skipf("%s is unavailable", presetName)
	}
	spec, source, err := fingerprint.ResolveClientHelloSpec(p, "", nil, false, 0)
	if err != nil {
		t.Fatalf("%s: resolve: %v", presetName, err)
	}
	tr := &HTTP1Transport{preset: p}
	cfg := &utls.Config{
		ServerName:         "example.com",
		InsecureSkipVerify: true,
		NextProtos:         []string{"http/1.1"},
		OmitEmptyPsk:       true,
	}
	conn, err := tr.applyH1Spec(&net.TCPConn{}, cfg, spec, source)
	if err != nil {
		t.Fatalf("%s: applyH1Spec: %v", presetName, err)
	}
	if err := conn.BuildHandshakeState(); err != nil {
		t.Fatalf("%s: BuildHandshakeState: %v", presetName, err)
	}
	return conn
}

// alpnOnTheWire pulls the ALPN protocol list out of the MARSHALLED
// ClientHello.
//
// Reading HandshakeState.Hello.AlpnProtocols proves nothing: that field is
// populated from tlsConfig.NextProtos, so it says http/1.1 whether or not the
// extension bytes ever changed. The bytes are what the server reads and what
// the failure was about.
func alpnOnTheWire(t *testing.T, raw []byte) []string {
	t.Helper()
	if len(raw) < 38 {
		t.Fatalf("marshalled hello is %d bytes", len(raw))
	}
	b := raw[4:] // skip handshake type and length
	b = b[2+32:]
	b = b[1+int(b[0]):]
	n := int(b[0])<<8 | int(b[1])
	b = b[2+n:]
	b = b[1+int(b[0]):]
	if len(b) < 2 {
		t.Fatal("no extension block in the marshalled hello")
	}
	b = b[2:]
	for len(b) >= 4 {
		id := int(b[0])<<8 | int(b[1])
		l := int(b[2])<<8 | int(b[3])
		body := b[4 : 4+l]
		b = b[4+l:]
		if id != 16 {
			continue
		}
		body = body[2:] // list length
		var out []string
		for len(body) > 0 {
			pl := int(body[0])
			out = append(out, string(body[1:1+pl]))
			body = body[1+pl:]
		}
		return out
	}
	return nil
}

// The ALPN rewrite reaches the marshalled hello for every preset family, not
// only the ones whose spec happens to carry a pre_shared_key extension.
func TestForcedH1ALPNReachesTheHello(t *testing.T) {
	for _, name := range []string{
		"chrome-152-windows", "chrome-151-windows", // re-marshalled before, so these always worked
		"chrome-151-ios", "safari-18", // WebKit: these are the ones that failed
		"firefox-148",
	} {
		t.Run(name, func(t *testing.T) {
			conn := helloOf(t, name)
			got := alpnOnTheWire(t, conn.HandshakeState.Hello.Raw)
			if len(got) != 1 || got[0] != "http/1.1" {
				t.Fatalf("the marshalled hello advertises %v, want [http/1.1]; a "+
					"server will negotiate h2 and uTLS will then reject its own "+
					"peer's choice", got)
			}
		})
	}
}

// ALPS never names a protocol that ALPN is not offering.
//
// The forced-H1 hello advertised application_settings for h2 while ALPN
// offered only http/1.1, which no browser produces. Chromium registers ALPS by
// walking the ALPN list, net/socket/ssl_client_socket_impl.cc:
//
//	for (NextProto proto : ssl_config_.alpn_protos) {
//	  auto iter = ssl_config_.application_settings.find(proto);
//	  if (iter != ssl_config_.application_settings.end()) {
//	    ... SSL_add_application_settings(...)
//
// so a socket offering only http/1.1 registers none and the extension is
// omitted entirely.
func TestForcedH1DropsALPSForUnofferedProtocols(t *testing.T) {
	for _, name := range []string{"chrome-152-windows", "chrome-151-windows", "chrome-151-ios", "safari-18"} {
		t.Run(name, func(t *testing.T) {
			conn := helloOf(t, name)
			for _, ext := range conn.Extensions {
				var protos []string
				switch alps := ext.(type) {
				case *utls.ApplicationSettingsExtension:
					protos = alps.SupportedProtocols
				case *utls.ApplicationSettingsExtensionNew:
					protos = alps.SupportedProtocols
				default:
					continue
				}
				for _, p := range protos {
					if p != "http/1.1" {
						t.Errorf("ALPS offers settings for %q while ALPN offers only "+
							"http/1.1; Chromium registers ALPS by walking the ALPN "+
							"list, so this pair cannot occur", p)
					}
				}
			}
		})
	}
}

// The Chrome 152 overrides survive the forced-H1 path too, since they are
// applied to the spec rather than to a materialised hello.
func TestForcedH1KeepsThePresetOverrides(t *testing.T) {
	p := fingerprint.GetStrict("chrome-152-windows")
	if p == nil {
		t.Skip("chrome-152-windows is unavailable")
	}
	conn := helloOf(t, "chrome-152-windows")

	var anchors int
	var got []uint16
	for _, ext := range conn.Extensions {
		switch e := ext.(type) {
		case *utls.TrustAnchorsExtension:
			anchors = len(e.TrustAnchors)
		case *utls.SignatureAlgorithmsExtension:
			for _, sa := range e.SupportedSignatureAlgorithms {
				got = append(got, uint16(sa))
			}
		}
	}
	if anchors != len(p.TrustAnchors) {
		t.Errorf("forced H1 carries %d trust anchors, want %d", anchors, len(p.TrustAnchors))
	}

	// Compare against the preset element by element rather than asserting a
	// particular shape. Chrome 152 has two genuine sigalg cohorts (see the
	// kTlsGreaseSigalgs note on Chrome152Windows), we default to the one
	// without GREASE, and either is a legitimate configuration. What forced H1
	// must never do is drop or reorder whatever the preset asked for, and this
	// holds for both cohorts.
	if len(got) != len(p.SignatureAlgorithms) {
		t.Fatalf("forced H1 carries %d signature algorithms, want %d",
			len(got), len(p.SignatureAlgorithms))
	}
	for i, want := range p.SignatureAlgorithms {
		w := uint16(want)
		if w == 0x0a0a {
			// A GREASE placeholder is substituted per connection, so all this
			// position can say is that the result is a GREASE value.
			//
			// Deliberately not asserting it differs from 0x0a0a. That is one of
			// the sixteen valid GREASE values, so a correct substitution lands on
			// it one connection in sixteen, and a test that reads it as "still
			// the placeholder" fails at that rate for no reason. Whether the
			// substitution happens at all is a question about several
			// connections, not one, and TestForcedH1GreaseVaries asks it.
			if got[i]&0x0f0f != 0x0a0a {
				t.Errorf("algorithm %d is %#04x, which is not a GREASE value", i, got[i])
			}
			continue
		}
		if got[i] != w {
			t.Errorf("algorithm %d is %#04x, want %#04x from the preset", i, got[i], w)
		}
	}
}

// The GREASE placeholder has to be substituted per connection, not once.
//
// One connection cannot tell substituted from not: 0x0a0a is itself a valid
// GREASE value, so a working substitution produces the placeholder's own value
// one time in sixteen. Several connections can. A profile that never substitutes
// emits the same value every time, which is a stable fake algorithm on the wire
// and the opposite of what GREASE is for.
func TestForcedH1GreaseVaries(t *testing.T) {
	p := fingerprint.GetStrict("chrome-152-windows")
	if p == nil {
		t.Skip("chrome-152-windows is unavailable")
	}
	if len(p.SignatureAlgorithms) == 0 || uint16(p.SignatureAlgorithms[0]) != 0x0a0a {
		t.Skip("preset does not lead with the GREASE placeholder")
	}

	seen := map[uint16]bool{}
	const runs = 24
	for i := 0; i < runs; i++ {
		conn := helloOf(t, "chrome-152-windows")
		for _, ext := range conn.Extensions {
			if e, ok := ext.(*utls.SignatureAlgorithmsExtension); ok && len(e.SupportedSignatureAlgorithms) > 0 {
				v := uint16(e.SupportedSignatureAlgorithms[0])
				if v&0x0f0f != 0x0a0a {
					t.Fatalf("run %d: first signature algorithm %#04x is not a GREASE value", i, v)
				}
				seen[v] = true
			}
		}
	}
	// Sixteen possible values over 24 draws: seeing only one means it is fixed.
	if len(seen) < 2 {
		t.Errorf("%d connections all emitted the same GREASE signature algorithm (%v); "+
			"the placeholder is not being substituted per connection", runs, seen)
	}
}
