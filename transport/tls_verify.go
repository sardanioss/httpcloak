package transport

import (
	stdtls "crypto/tls"
	"crypto/x509"

	utls "github.com/sardanioss/utls"
)

// TLSVerify carries caller-supplied certificate verification hooks.
//
// This is deliberately not a full *tls.Config. Accepting an arbitrary config
// would let callers set CipherSuites, MinVersion, CurvePreferences, NextProtos
// and friends, every one of which rewrites the ClientHello and destroys the
// browser fingerprint this library exists to reproduce - silently, and only
// visible to whoever is fingerprinting on the other end. The verification hooks
// are the part of a tls.Config that a caller genuinely needs and that cannot
// change a single byte on the wire, so they are the part exposed.
//
// The hooks use standard library types. Internally the TLS stack is uTLS, whose
// ConnectionState is a distinct type, so the state is translated on the way
// through rather than leaking the fork's type into the public API.
type TLSVerify struct {
	// VerifyPeerCertificate mirrors crypto/tls.Config.VerifyPeerCertificate.
	// It is called after the normal certificate checks, with the raw
	// certificates and any chains the default verifier built. Returning an
	// error aborts the handshake.
	VerifyPeerCertificate func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error

	// VerifyConnection mirrors crypto/tls.Config.VerifyConnection. It is called
	// after VerifyPeerCertificate, for every handshake including resumptions.
	VerifyConnection func(cs stdtls.ConnectionState) error
}

// IsEmpty reports whether there is nothing to install.
func (v *TLSVerify) IsEmpty() bool {
	return v == nil || (v.VerifyPeerCertificate == nil && v.VerifyConnection == nil)
}

// Apply installs the hooks onto a uTLS config. Safe to call with a nil or empty
// receiver, in which case the config is left untouched.
func (v *TLSVerify) Apply(cfg *utls.Config) {
	if v.IsEmpty() || cfg == nil {
		return
	}
	if v.VerifyPeerCertificate != nil {
		cfg.VerifyPeerCertificate = v.VerifyPeerCertificate
	}
	if v.VerifyConnection != nil {
		fn := v.VerifyConnection
		cfg.VerifyConnection = func(ucs utls.ConnectionState) error {
			return fn(ToStdConnectionState(ucs))
		}
	}
}

// ToStdConnectionState converts a uTLS handshake state into the standard
// library shape so callers can work with crypto/tls types.
//
// Fields with no standard-library counterpart (uTLS's PeerApplicationSettings)
// are dropped, and the unexported plumbing the standard library uses for
// ExportKeyingMaterial cannot be reconstructed from outside crypto/tls, so
// ExportKeyingMaterial on the returned value is unusable. Everything a
// verification callback actually inspects - version, cipher suite, ALPN, SNI,
// peer certificates, verified chains, SCTs, OCSP - carries across.
func ToStdConnectionState(s utls.ConnectionState) stdtls.ConnectionState {
	return stdtls.ConnectionState{
		Version:                     s.Version,
		HandshakeComplete:           s.HandshakeComplete,
		DidResume:                   s.DidResume,
		CipherSuite:                 s.CipherSuite,
		NegotiatedProtocol:          s.NegotiatedProtocol,
		NegotiatedProtocolIsMutual:  s.NegotiatedProtocolIsMutual,
		ServerName:                  s.ServerName,
		PeerCertificates:            s.PeerCertificates,
		VerifiedChains:              s.VerifiedChains,
		SignedCertificateTimestamps: s.SignedCertificateTimestamps,
		OCSPResponse:                s.OCSPResponse,
	}
}
