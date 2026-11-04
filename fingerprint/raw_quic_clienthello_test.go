package fingerprint

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"io"
	"strings"
	"testing"

	utls "github.com/sardanioss/utls"
)

// A Chrome QUIC hello with transport parameters filled in, so extension 57
// carries a body the way it does on the wire: max_idle_timeout 30000 and
// initial_max_data 15728640, each a varint id, varint length and varint value.
var chromeQUICTransportParams = []byte{
	0x01, 0x04, 0x80, 0x00, 0x75, 0x30,
	0x04, 0x04, 0x80, 0xf0, 0x00, 0x00,
}

func buildRawQUICHelloBytes(t *testing.T) []byte {
	t.Helper()
	spec, err := utls.UTLSIdToSpecWithSeed(utls.HelloChrome_143_QUIC, 1)
	if err != nil {
		t.Fatalf("cannot build a reference QUIC hello: %v", err)
	}
	for _, ext := range spec.Extensions {
		if qtp, ok := ext.(*utls.QUICTransportParametersExtension); ok {
			qtp.RawData = chromeQUICTransportParams
		}
	}
	conn := utls.UClient(nil, &utls.Config{
		ServerName:         "example.com",
		InsecureSkipVerify: true,
		OmitEmptyPsk:       true,
	}, utls.HelloCustom)
	if err := conn.ApplyPreset(&spec); err != nil {
		t.Fatalf("cannot apply the reference QUIC spec: %v", err)
	}
	if err := conn.BuildHandshakeState(); err != nil {
		t.Fatalf("cannot build the QUIC handshake state: %v", err)
	}
	hello := conn.HandshakeState.Hello.Raw
	rec := []byte{0x16, 0x03, 0x01, byte(len(hello) >> 8), byte(len(hello))}
	return append(rec, hello...)
}

// extensionOrder reads each extension's id off its own wire encoding, which
// covers every type, GREASE and generic ones included.
func extensionOrder(t *testing.T, spec *utls.ClientHelloSpec) []uint16 {
	t.Helper()
	out := make([]uint16, 0, len(spec.Extensions))
	for _, ext := range spec.Extensions {
		if ext.Len() == 0 {
			continue // padding sized to zero is not on the wire
		}
		buf := make([]byte, ext.Len())
		if _, err := ext.Read(buf); err != nil && !errors.Is(err, io.EOF) {
			t.Fatalf("read %T: %v", ext, err)
		}
		out = append(out, binary.BigEndian.Uint16(buf))
	}
	return out
}

func loadRawQUICPreset(t *testing.T, name, tlsBlock string) *Preset {
	t.Helper()
	p, err := LoadAndBuildPresetFromJSON([]byte(`{"preset":{"name":"` + name +
		`","based_on":"chrome-latest","tls":{` + tlsBlock + `}}}`))
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	return p
}

func b64(raw []byte) string { return base64.StdEncoding.EncodeToString(raw) }

// The point of the field: one preset replays a TCP capture on TCP and a QUIC
// capture on QUIC. Before it, raw_client_hello held one or the other.
func TestOnePresetCarriesATCPAndAQUICCapture(t *testing.T) {
	tcp, quic := buildRawHelloBytes(t), buildRawQUICHelloBytes(t)
	p := loadRawQUICPreset(t, "both-captures",
		`"raw_client_hello":"`+b64(tcp)+`","raw_quic_client_hello":"`+b64(quic)+`"`)

	quicSpec, src, err := ResolveQUICClientHelloSpec(p, false, 1)
	if err != nil {
		t.Fatalf("resolve quic: %v", err)
	}
	if src != SourceRawQUIC {
		t.Errorf("QUIC took source %v, want the QUIC capture", src)
	}
	want, err := SpecFromRawClientHello(quic, false, false)
	if err != nil {
		t.Fatalf("parse fixture: %v", err)
	}
	if got, want := extensionOrder(t, quicSpec), extensionOrder(t, want); !equalIDs(got, want) {
		t.Errorf("QUIC hello is not the capture:\n got %v\nwant %v", got, want)
	}

	tcpSpec, src, err := ResolveClientHelloSpec(p, "", nil, false, 1)
	if err != nil {
		t.Fatalf("resolve tcp: %v", err)
	}
	if src != SourceRaw {
		t.Errorf("TCP took source %v, want the TCP capture", src)
	}
	if SpecHasQUICTransportParameters(tcpSpec) {
		t.Error("TCP was handed the QUIC capture")
	}
}

func TestRawQUICPSKVariantIsUsedOnlyWhenResuming(t *testing.T) {
	quic := buildRawQUICHelloBytes(t)
	p := loadRawQUICPreset(t, "quic-psk",
		`"raw_quic_client_hello":"`+b64(quic)+`","raw_quic_psk_client_hello":"`+b64(withPSKExtension(t, quic))+`"`)

	if !HasQUICPSKVariant(p) {
		t.Fatal("a preset carrying raw_quic_psk_client_hello reported no QUIC PSK variant")
	}
	fresh, _, err := ResolveQUICClientHelloSpec(p, false, 1)
	if err != nil {
		t.Fatalf("resolve fresh: %v", err)
	}
	if SpecHasPSKExtension(fresh) {
		t.Error("a fresh connection got the resumption hello")
	}
	resumed, src, err := ResolveQUICClientHelloSpec(p, true, 1)
	if err != nil {
		t.Fatalf("resolve resumed: %v", err)
	}
	if src != SourceRawQUIC || !SpecHasPSKExtension(resumed) {
		t.Errorf("resuming got source %v with psk=%v, want the captured PSK hello",
			src, SpecHasPSKExtension(resumed))
	}
}

// A QUIC capture is the whole QUIC fingerprint, so the inherited QUIC ids go,
// and with them the PSK variant they implied. Resuming from a named id under a
// captured hello would be a PSK hello from a different client.
func TestRawQUICCaptureReplacesTheInheritedQUICIdentity(t *testing.T) {
	p := loadRawQUICPreset(t, "quic-no-psk", `"raw_quic_client_hello":"`+b64(buildRawQUICHelloBytes(t))+`"`)

	if p.QUICClientHelloID.Client != "" || p.QUICPSKClientHelloID.Client != "" {
		t.Errorf("QUIC ids survived a QUIC capture: %+v / %+v", p.QUICClientHelloID, p.QUICPSKClientHelloID)
	}
	if HasQUICPSKVariant(p) {
		t.Error("reported a QUIC PSK variant with no captured one")
	}
	if p.ClientHelloID.Client == "" {
		t.Error("the TCP identity was cleared by a QUIC capture")
	}
}

func TestQUICClientHelloReplacesAnInheritedRawQUICCapture(t *testing.T) {
	parent := loadRawQUICPreset(t, "raw-quic-parent", `"raw_quic_client_hello":"`+b64(buildRawQUICHelloBytes(t))+`"`)
	Register(parent.Name, parent)
	defer Unregister(parent.Name)

	child, err := LoadAndBuildPresetFromJSON([]byte(`{"preset":{"name":"raw-quic-child",` +
		`"based_on":"raw-quic-parent","tls":{"quic_client_hello":"chrome-146-quic"}}}`))
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if _, src, err := ResolveQUICClientHelloSpec(child, false, 1); err != nil || src != SourceClientHelloID {
		t.Errorf("child resolved source %v (err %v); the declared quic_client_hello should win", src, err)
	}
}

func TestRawQUICClientHelloLoadErrors(t *testing.T) {
	tcp, quic := b64(buildRawHelloBytes(t)), b64(buildRawQUICHelloBytes(t))

	for _, tc := range []struct {
		name, tls, want string
	}{
		{"TCP capture", `"raw_quic_client_hello":"` + tcp + `"`, "quic_transport_parameters"},
		{"with ja3", `"raw_quic_client_hello":"` + quic + `","ja3":"771,4865-4866,0-23-65281-10-11,29-23,0"`, "ja3"},
		{"with quic_client_hello", `"raw_quic_client_hello":"` + quic + `","quic_client_hello":"chrome-146-quic"`, "mutually exclusive"},
		{"psk without capture", `"raw_quic_psk_client_hello":"` + quic + `"`, "requires raw_quic_client_hello"},
		{"psk is TCP", `"raw_quic_client_hello":"` + quic + `","raw_quic_psk_client_hello":"` + tcp + `"`, "quic_transport_parameters"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := LoadAndBuildPresetFromJSON([]byte(`{"preset":{"name":"bad-raw-quic",` +
				`"based_on":"chrome-latest","tls":{` + tc.tls + `}}}`))
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("got %v, want an error mentioning %q", err, tc.want)
			}
		})
	}
}

// allow_blunt_mimicry and the permute keys describe how a capture is parsed
// and replayed, so a QUIC capture alone is enough to make them meaningful.
func TestCaptureOptionsApplyToARawQUICCaptureAlone(t *testing.T) {
	quic := b64(buildRawQUICHelloBytes(t))
	for _, extra := range []string{
		`,"allow_blunt_mimicry":true`,
		`,"permute_raw_hello":true`,
		`,"permute_extensions":true`,
	} {
		if _, err := LoadAndBuildPresetFromJSON([]byte(`{"preset":{"name":"raw-quic-opts",` +
			`"based_on":"chrome-latest","tls":{"raw_quic_client_hello":"` + quic + `"` + extra + `}}}`)); err != nil {
			t.Errorf("%s: %v", extra, err)
		}
	}
}

func TestRawQUICCapturePermutesOnlyWhenDeclared(t *testing.T) {
	quic := b64(buildRawQUICHelloBytes(t))
	for _, permute := range []bool{false, true} {
		block := `"raw_quic_client_hello":"` + quic + `"`
		if permute {
			block += `,"permute_raw_hello":true`
		}
		p := loadRawQUICPreset(t, "raw-quic-permute", block)

		seen := map[string]bool{}
		for i := 0; i < 8; i++ {
			spec, _, err := ResolveQUICClientHelloSpec(p, false, 1)
			if err != nil {
				t.Fatalf("resolve: %v", err)
			}
			seen[string(idBytes(extensionOrder(t, spec)))] = true
		}
		if permute && len(seen) < 2 {
			t.Error("permute_raw_hello set, but 8 QUIC handshakes repeated one extension order")
		}
		if !permute && len(seen) != 1 {
			t.Errorf("no permutation declared, but the QUIC capture went out in %d orders", len(seen))
		}
	}
}

func TestDescribeKeepsBothCaptures(t *testing.T) {
	tcp, quic := buildRawHelloBytes(t), buildRawQUICHelloBytes(t)
	quicPSK := withPSKExtension(t, quic)
	p := loadRawQUICPreset(t, "describe-both-captures",
		`"raw_client_hello":"`+b64(tcp)+`","raw_quic_client_hello":"`+b64(quic)+
			`","raw_quic_psk_client_hello":"`+b64(quicPSK)+`","permute_raw_hello":true`)
	Register(p.Name, p)
	defer Unregister(p.Name)

	out, err := Describe(p.Name)
	if err != nil {
		t.Fatalf("describe: %v", err)
	}
	rt, err := LoadAndBuildPresetFromJSON([]byte(out))
	if err != nil {
		t.Fatalf("load described preset: %v\n%s", err, out)
	}
	for _, f := range []struct {
		name      string
		got, want []byte
	}{
		{"raw_client_hello", rt.RawClientHello, tcp},
		{"raw_quic_client_hello", rt.RawQUICClientHello, quic},
		{"raw_quic_psk_client_hello", rt.RawQUICPSKClientHello, quicPSK},
	} {
		if !bytes.Equal(f.got, f.want) {
			t.Errorf("%s did not survive describe", f.name)
		}
	}
	if !rt.RawPermuteExtensions {
		t.Error("permute_raw_hello did not survive describe")
	}
}

func equalIDs(a, b []uint16) bool { return bytes.Equal(idBytes(a), idBytes(b)) }

func idBytes(ids []uint16) []byte {
	out := make([]byte, 0, 2*len(ids))
	for _, id := range ids {
		out = binary.BigEndian.AppendUint16(out, id)
	}
	return out
}
