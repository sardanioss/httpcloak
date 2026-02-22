package fingerprint

import (
	"fmt"
	"strconv"
	"strings"

	tls "github.com/sardanioss/utls"
)

// JA3Extras provides extension data that JA3 cannot capture.
// JA3 only encodes extension IDs, not the data within them.
type JA3Extras struct {
	SignatureAlgorithms []tls.SignatureScheme
	ALPN               []string
	CertCompAlgs       []tls.CertCompressionAlgo
	PermuteExtensions  bool
	RecordSizeLimit    uint16 // default: 0x4001
}

// defaultJA3Extras returns sensible defaults matching modern Chrome.
func defaultJA3Extras() *JA3Extras {
	return &JA3Extras{
		SignatureAlgorithms: []tls.SignatureScheme{
			tls.ECDSAWithP256AndSHA256,
			tls.PSSWithSHA256,
			tls.PKCS1WithSHA256,
			tls.ECDSAWithP384AndSHA384,
			tls.PSSWithSHA384,
			tls.PKCS1WithSHA384,
			tls.PSSWithSHA512,
			tls.PKCS1WithSHA512,
		},
		ALPN:            []string{"h2", "http/1.1"},
		CertCompAlgs:    []tls.CertCompressionAlgo{tls.CertCompressionBrotli},
		RecordSizeLimit: 0x4001,
	}
}

// isGREASE returns true if the value is a TLS GREASE value (RFC 8701).
func isGREASE(v uint16) bool {
	return (v & 0x0f0f) == 0x0a0a
}

// ParseJA3 parses a JA3 fingerprint string into a *tls.ClientHelloSpec.
// Format: TLSVersion,CipherSuites,Extensions,EllipticCurves,PointFormats
// Fields use dash-separated decimal values.
// If extras is nil, sensible defaults (matching modern Chrome) are used.
func ParseJA3(ja3 string, extras *JA3Extras) (*tls.ClientHelloSpec, error) {
	if extras == nil {
		extras = defaultJA3Extras()
	} else {
		// Make a shallow copy to avoid mutating the caller's struct, then
		// apply defaults for any fields not explicitly set. This handles
		// the case where extras is partially filled (e.g., only
		// PermuteExtensions set) — nil fields would produce empty TLS
		// extensions that cause handshake failures.
		merged := *extras
		extras = &merged
		defaults := defaultJA3Extras()
		if len(extras.SignatureAlgorithms) == 0 {
			extras.SignatureAlgorithms = defaults.SignatureAlgorithms
		}
		if len(extras.ALPN) == 0 {
			extras.ALPN = defaults.ALPN
		}
		if len(extras.CertCompAlgs) == 0 {
			extras.CertCompAlgs = defaults.CertCompAlgs
		}
		if extras.RecordSizeLimit == 0 {
			extras.RecordSizeLimit = defaults.RecordSizeLimit
		}
	}

	parts := strings.Split(ja3, ",")
	if len(parts) != 5 {
		return nil, fmt.Errorf("ja3: expected 5 comma-separated fields, got %d", len(parts))
	}

	// Parse TLS version
	tlsVersion, err := strconv.ParseUint(strings.TrimSpace(parts[0]), 10, 16)
	if err != nil {
		return nil, fmt.Errorf("ja3: invalid TLS version %q: %w", parts[0], err)
	}

	// Parse cipher suites
	cipherSuites, err := parseDashSeparatedUint16(parts[1])
	if err != nil {
		return nil, fmt.Errorf("ja3: invalid cipher suites: %w", err)
	}
	// Filter GREASE from cipher suites
	var filteredCiphers []uint16
	for _, cs := range cipherSuites {
		if !isGREASE(cs) {
			filteredCiphers = append(filteredCiphers, cs)
		}
	}

	// Parse extension IDs
	extensionIDs, err := parseDashSeparatedUint16(parts[2])
	if err != nil {
		return nil, fmt.Errorf("ja3: invalid extensions: %w", err)
	}

	// Parse elliptic curves (supported groups)
	curves, err := parseDashSeparatedUint16(parts[3])
	if err != nil {
		return nil, fmt.Errorf("ja3: invalid elliptic curves: %w", err)
	}
	var filteredCurves []tls.CurveID
	for _, c := range curves {
		if !isGREASE(c) {
			filteredCurves = append(filteredCurves, tls.CurveID(c))
		}
	}

	// Parse point formats
	pointFormats, err := parseDashSeparatedUint8(parts[4])
	if err != nil {
		return nil, fmt.Errorf("ja3: invalid point formats: %w", err)
	}

	// Build extensions list
	extensions, err := buildExtensions(extensionIDs, extras, filteredCurves, pointFormats)
	if err != nil {
		return nil, fmt.Errorf("ja3: %w", err)
	}

	// Determine TLS version range.
	// JA3 records the ClientHello version field which is always 0x0303 (TLS 1.2)
	// even for TLS 1.3 clients (actual version is in supported_versions extension).
	// If supported_versions (ext 43) is present, set max to TLS 1.3.
	// MinVersion is TLS 1.2 — modern servers reject TLS 1.0/1.1, and ApplyPreset
	// can override the utls.Config MinVersion with the spec's value.
	minVersion := uint16(tls.VersionTLS12)
	maxVersion := uint16(tlsVersion)
	for _, id := range extensionIDs {
		if id == 43 { // supported_versions
			maxVersion = tls.VersionTLS13
			break
		}
	}
	if maxVersion < tls.VersionTLS10 {
		maxVersion = tls.VersionTLS12
	}

	// Shuffle extensions if requested (Chrome 106+ shuffles to avoid ossification)
	if extras.PermuteExtensions {
		extensions = tls.ShuffleChromeTLSExtensions(extensions)
	}

	spec := &tls.ClientHelloSpec{
		TLSVersMin:         minVersion,
		TLSVersMax:         maxVersion,
		CipherSuites:       filteredCiphers,
		CompressionMethods: []uint8{0}, // null compression
		Extensions:         extensions,
	}

	return spec, nil
}

// buildExtensions converts extension IDs to tls.TLSExtension objects.
func buildExtensions(ids []uint16, extras *JA3Extras, curves []tls.CurveID, pointFormats []uint8) ([]tls.TLSExtension, error) {
	var extensions []tls.TLSExtension

	for _, id := range ids {
		if isGREASE(id) {
			extensions = append(extensions, &tls.UtlsGREASEExtension{})
			continue
		}

		ext := extensionForID(id, extras, curves, pointFormats)
		extensions = append(extensions, ext)
	}

	return extensions, nil
}

// extensionForID returns the appropriate TLSExtension for a given extension ID.
func extensionForID(id uint16, extras *JA3Extras, curves []tls.CurveID, pointFormats []uint8) tls.TLSExtension {
	switch id {
	case 0: // server_name (SNI)
		return &tls.SNIExtension{}

	case 5: // status_request (OCSP stapling)
		return &tls.StatusRequestExtension{}

	case 10: // supported_groups (elliptic curves)
		return &tls.SupportedCurvesExtension{Curves: curves}

	case 11: // ec_point_formats
		return &tls.SupportedPointsExtension{SupportedPoints: pointFormats}

	case 13: // signature_algorithms
		return &tls.SignatureAlgorithmsExtension{
			SupportedSignatureAlgorithms: extras.SignatureAlgorithms,
		}

	case 16: // ALPN
		return &tls.ALPNExtension{AlpnProtocols: extras.ALPN}

	case 17: // status_request_v2
		return &tls.StatusRequestV2Extension{}

	case 18: // signed_certificate_timestamp (SCT)
		return &tls.SCTExtension{}

	case 21: // padding
		return &tls.UtlsPaddingExtension{GetPaddingLen: tls.BoringPaddingStyle}

	case 22: // encrypt_then_mac — utls has no dedicated type; use GenericExtension
		return &tls.GenericExtension{Id: 22}

	case 23: // extended_master_secret
		return &tls.UtlsExtendedMasterSecretExtension{}

	case 27: // compress_certificate
		return &tls.UtlsCompressCertExtension{
			Algorithms: extras.CertCompAlgs,
		}

	case 28: // record_size_limit
		limit := extras.RecordSizeLimit
		if limit == 0 {
			limit = 0x4001
		}
		return &tls.FakeRecordSizeLimitExtension{Limit: limit}

	case 34: // delegated_credentials
		return &tls.DelegatedCredentialsExtension{
			SupportedSignatureAlgorithms: []tls.SignatureScheme{
				tls.ECDSAWithP256AndSHA256,
				tls.ECDSAWithP384AndSHA384,
				tls.ECDSAWithP521AndSHA512,
				tls.ECDSAWithSHA1,
			},
		}

	case 35: // session_ticket
		return &tls.SessionTicketExtension{}

	case 41: // pre_shared_key (PSK) — placeholder, actual data set during handshake
		return &tls.UtlsPreSharedKeyExtension{}

	case 43: // supported_versions
		return &tls.SupportedVersionsExtension{
			Versions: []uint16{
				tls.VersionTLS13,
				tls.VersionTLS12,
			},
		}

	case 44: // cookie
		return &tls.CookieExtension{}

	case 45: // psk_key_exchange_modes
		return &tls.PSKKeyExchangeModesExtension{
			Modes: []uint8{tls.PskModeDHE},
		}

	case 49: // post_handshake_auth
		return &tls.GenericExtension{Id: 49}

	case 50: // signature_algorithms_cert
		// Chrome sends a broader list for cert verification than for handshake
		// signatures (ext 13). This includes legacy algorithms needed to verify
		// certificate chains signed with older algorithms.
		return &tls.SignatureAlgorithmsCertExtension{
			SupportedSignatureAlgorithms: []tls.SignatureScheme{
				tls.ECDSAWithP256AndSHA256,
				tls.PSSWithSHA256,
				tls.PKCS1WithSHA256,
				tls.ECDSAWithP384AndSHA384,
				tls.PSSWithSHA384,
				tls.PKCS1WithSHA384,
				tls.PSSWithSHA512,
				tls.PKCS1WithSHA512,
				tls.PKCS1WithSHA1,
			},
		}

	case 51: // key_share
		// Real browsers only generate a key share for the first (preferred) curve.
		// Generating shares for all curves is a detectable fingerprinting signal.
		// The server sends HelloRetryRequest if it prefers a different group.
		var keyShares []tls.KeyShare
		for _, curve := range curves {
			if !isGREASE(uint16(curve)) {
				keyShares = append(keyShares, tls.KeyShare{Group: curve})
				break
			}
		}
		return &tls.KeyShareExtension{KeyShares: keyShares}

	case 57: // quic_transport_parameters — skip for TCP TLS
		return &tls.GenericExtension{Id: 57}

	case 17513: // application_settings (ALPS)
		return &tls.ApplicationSettingsExtension{
			SupportedProtocols: extras.ALPN,
		}

	case 65037: // encrypted_client_hello (ECH)
		// Empty struct — GREASEEncryptedClientHelloExtension auto-generates
		// cipher suite and payload length when fields are left zero/nil.
		return &tls.GREASEEncryptedClientHelloExtension{}

	case 65281: // renegotiation_info
		return &tls.RenegotiationInfoExtension{Renegotiation: tls.RenegotiateOnceAsClient}

	default:
		// Unknown extension — use GenericExtension with empty data
		return &tls.GenericExtension{Id: id}
	}
}

// parseDashSeparatedUint16 parses a dash-separated string of decimal uint16 values.
func parseDashSeparatedUint16(s string) ([]uint16, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, nil
	}
	parts := strings.Split(s, "-")
	result := make([]uint16, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		v, err := strconv.ParseUint(p, 10, 16)
		if err != nil {
			return nil, fmt.Errorf("invalid value %q: %w", p, err)
		}
		result = append(result, uint16(v))
	}
	return result, nil
}

// parseDashSeparatedUint8 parses a dash-separated string of decimal uint8 values.
func parseDashSeparatedUint8(s string) ([]uint8, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, nil
	}
	parts := strings.Split(s, "-")
	result := make([]uint8, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		v, err := strconv.ParseUint(p, 10, 8)
		if err != nil {
			return nil, fmt.Errorf("invalid value %q: %w", p, err)
		}
		result = append(result, uint8(v))
	}
	return result, nil
}
