package h3build

import (
	"testing"

	"github.com/sardanioss/httpcloak/fingerprint"
	utls "github.com/sardanioss/utls"
)

func ticket(t *testing.T, earlyData bool) *utls.ClientSessionState {
	t.Helper()
	cs, err := utls.NewResumptionState([]byte("ticket"), &utls.SessionState{EarlyData: earlyData})
	if err != nil {
		t.Fatal(err)
	}
	return cs
}

func hasEarlyData(spec *utls.ClientHelloSpec) bool {
	for _, e := range spec.Extensions {
		switch e := e.(type) {
		case *utls.FakeEarlyDataExtension:
			return true
		case *utls.GenericExtension:
			if e.Id == extensionEarlyData {
				return true
			}
		}
	}
	return false
}

// early_data stays in a resuming hello only when the ticket allows 0-RTT and
// the preset does not turn it off, whichever way the spec carries it.
func TestDropEarlyDataUnlessAllowed(t *testing.T) {
	no0RTT := false
	off := &fingerprint.Preset{H3Config: &fingerprint.H3FingerprintConfig{QUICAllow0RTT: &no0RTT}}
	on := &fingerprint.Preset{}
	for _, tc := range []struct {
		name   string
		preset *fingerprint.Preset
		ticket *utls.ClientSessionState
		keep   bool
	}{
		{"ticket allows early data", on, ticket(t, true), true},
		{"ticket without early data", on, ticket(t, false), false},
		{"no ticket", on, nil, false},
		{"empty ticket", on, &utls.ClientSessionState{}, false},
		{"preset turns 0-RTT off", off, ticket(t, true), false},
	} {
		for _, ext := range []struct {
			name string
			ext  utls.TLSExtension
		}{
			{"FakeEarlyDataExtension", &utls.FakeEarlyDataExtension{}},
			{"captured early_data", &utls.GenericExtension{Id: extensionEarlyData}},
		} {
			t.Run(tc.name+"/"+ext.name, func(t *testing.T) {
				spec := &utls.ClientHelloSpec{Extensions: []utls.TLSExtension{
					ext.ext,
					&utls.SNIExtension{},
					&utls.UtlsPreSharedKeyExtension{},
				}}
				DropEarlyDataUnlessAllowed(spec, tc.preset, tc.ticket)
				if got := hasEarlyData(spec); got != tc.keep {
					t.Errorf("early_data in the hello: %v, want %v", got, tc.keep)
				}
				if n := len(spec.Extensions); n != 2 && !tc.keep || n != 3 && tc.keep {
					t.Errorf("%d extensions left; only early_data may go", n)
				}
				if _, ok := spec.Extensions[len(spec.Extensions)-1].(*utls.UtlsPreSharedKeyExtension); !ok {
					t.Error("pre_shared_key is no longer the last extension")
				}
			})
		}
	}
}
