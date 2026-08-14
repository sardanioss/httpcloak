package session

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sardanioss/httpcloak/protocol"
)

// Regression lock: saving a session drops its certificate verification hooks,
// because they are Go functions and a *x509.CertPool that JSON cannot carry.
// What it does NOT drop is InsecureSkipVerify, which is a plain bool and
// serialises fine.
//
// So a session saved with "skip the default chain check, I pin the certificate
// myself" used to come back as "skip the default chain check" with nothing in
// its place. That is weaker than either half on its own: weaker than pinning,
// and weaker than plain verification. Nothing at any layer reported it. The
// restored session just accepted certificates the saved one would have thrown
// out.
//
// The fix records which hooks were configured and refuses a plain load of such
// a session, so the downgrade cannot happen quietly.

func verifiedConfig() *protocol.SessionConfig {
	return &protocol.SessionConfig{
		Preset:             "chrome-146",
		InsecureSkipVerify: true,
		TLSVerifyPeerCertificate: func(_ [][]byte, _ [][]*x509.Certificate) error {
			return nil
		},
	}
}

// The saved file must record that verification was configured, otherwise a
// loader has no way to know anything went missing.
func TestMarshalRecordsVerificationHooks(t *testing.T) {
	s := NewSession("", verifiedConfig())
	defer s.Close()

	data, err := s.Marshal()
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var state SessionState
	if err := json.Unmarshal(data, &state); err != nil {
		t.Fatalf("unmarshal state: %v", err)
	}

	if state.TLSVerify == nil {
		t.Fatal("saved state does not record that a verification hook was configured, " +
			"so a later load cannot tell it is dropping one")
	}
	if !state.TLSVerify.PeerCertificate {
		t.Error("TLSVerify.PeerCertificate = false, want true")
	}
	// Only what was actually set.
	if state.TLSVerify.Connection || state.TLSVerify.RootCAs {
		t.Error("recorded hooks that were never configured")
	}
}

// A session with no hooks must not grow the key, so existing files and the
// common case are untouched.
func TestMarshalOmitsVerifyStateWhenUnused(t *testing.T) {
	s := NewSession("", &protocol.SessionConfig{Preset: "chrome-146"})
	defer s.Close()

	data, err := s.Marshal()
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if strings.Contains(string(data), "tls_verify") {
		t.Errorf("a session with no verification hooks wrote a tls_verify key:\n%s", data)
	}
}

// The core of the fix: a plain load of a session that had hooks must fail
// rather than hand back the weakened session.
func TestPlainLoadRefusesToDropVerification(t *testing.T) {
	s := NewSession("", verifiedConfig())
	defer s.Close()

	data, err := s.Marshal()
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	restored, err := UnmarshalSession(data)
	if err == nil {
		restored.Close()
		t.Fatal("UnmarshalSession restored a session whose verification hook was silently dropped, " +
			"leaving InsecureSkipVerify in place with nothing replacing it")
	}
	if !strings.Contains(err.Error(), "TLSVerifyPeerCertificate") {
		t.Errorf("error does not name the missing hook, so the caller cannot tell what to pass: %v", err)
	}
	if !strings.Contains(err.Error(), "WithOptions") {
		t.Errorf("error does not point at the way to fix it: %v", err)
	}
}

// Supplying the hook back restores the session intact.
func TestLoadWithOptionsRestoresVerification(t *testing.T) {
	s := NewSession("", verifiedConfig())
	defer s.Close()

	path := filepath.Join(t.TempDir(), "session.json")
	if err := s.Save(path); err != nil {
		t.Fatalf("save: %v", err)
	}

	called := false
	restored, err := LoadSessionWithOptions(path, &SessionLoadOptions{
		TLSVerifyPeerCertificate: func(_ [][]byte, _ [][]*x509.Certificate) error {
			called = true
			return nil
		},
	})
	if err != nil {
		t.Fatalf("load with options: %v", err)
	}
	defer restored.Close()

	if restored.Config == nil || restored.Config.TLSVerifyPeerCertificate == nil {
		t.Fatal("the supplied hook did not reach the restored session's config")
	}
	// Prove it is the caller's function and not some placeholder.
	if err := restored.Config.TLSVerifyPeerCertificate(nil, nil); err != nil {
		t.Fatalf("calling the restored hook: %v", err)
	}
	if !called {
		t.Fatal("the restored hook is not the one that was supplied")
	}
}

// Partially supplying is still a downgrade and must be refused, otherwise a
// caller who remembers one hook and forgets another gets the original bug back
// for the forgotten one.
func TestLoadWithOptionsRefusesPartialRestore(t *testing.T) {
	s := NewSession("", &protocol.SessionConfig{
		Preset:                   "chrome-146",
		TLSVerifyPeerCertificate: func(_ [][]byte, _ [][]*x509.Certificate) error { return nil },
		TLSVerifyConnection:      func(_ tls.ConnectionState) error { return nil },
		TLSRootCAs:               x509.NewCertPool(),
	})
	defer s.Close()

	data, err := s.Marshal()
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	restored, err := UnmarshalSessionWithOptions(data, &SessionLoadOptions{
		TLSVerifyPeerCertificate: func(_ [][]byte, _ [][]*x509.Certificate) error { return nil },
	})
	if err == nil {
		restored.Close()
		t.Fatal("a partial restore was accepted, so the hooks left out were dropped silently")
	}
	for _, want := range []string{"TLSVerifyConnection", "TLSRootCAs"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error does not name the missing %s: %v", want, err)
		}
	}
	if strings.Contains(err.Error(), "TLSVerifyPeerCertificate") {
		t.Errorf("error names a hook that WAS supplied: %v", err)
	}
}

// Files written before any of this existed carry no record, and must keep
// loading exactly as they did.
func TestOlderSessionFilesStillLoadPlainly(t *testing.T) {
	s := NewSession("", &protocol.SessionConfig{Preset: "chrome-146"})
	defer s.Close()

	data, err := s.Marshal()
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	restored, err := UnmarshalSession(data)
	if err != nil {
		t.Fatalf("a session with no verification hooks failed to load: %v", err)
	}
	defer restored.Close()

	// And the state version is unchanged, so a file written now still loads on
	// the previous release.
	var state SessionState
	if err := json.Unmarshal(data, &state); err != nil {
		t.Fatalf("unmarshal state: %v", err)
	}
	if state.Version != 5 {
		t.Fatalf("session state version = %d, want 5; bumping it makes every file "+
			"written here hard-fail on older releases", state.Version)
	}
}
