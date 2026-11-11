package h3build

import (
	"github.com/sardanioss/httpcloak/fingerprint"
	utls "github.com/sardanioss/utls"
)

// extensionEarlyData is the early_data extension's ID (RFC 8446, Section 4.2.10).
const extensionEarlyData = 42

// DropEarlyDataUnlessAllowed takes the early_data extension out of a resuming
// connection's hello unless the ticket it resumes allows 0-RTT and the preset
// allows it too. spec must be the dial's own copy.
//
// The resuming specs carry early_data unconditionally, and utls's
// FakeEarlyDataExtension switches 0-RTT on whatever the ticket says. A server
// whose tickets do not allow early data then rejects the 0-RTT, the http3 layer
// cannot open its control stream on the rejected connection and abandons it
// with H3_INTERNAL_ERROR, twice, before the ticket is dropped and the next dial
// does a full handshake. Chrome 156 and Firefox 159, captured against tickets
// with and without early data, offer early_data only on a ticket that allows
// it, and otherwise resume in one handshake with the PSK alone.
//
// A spec parsed from a captured hello carries early_data as a GenericExtension,
// so the extension is matched by its ID as well as by type.
func DropEarlyDataUnlessAllowed(spec *utls.ClientHelloSpec, p *fingerprint.Preset, ticket *utls.ClientSessionState) {
	if spec == nil || TicketAllowsEarlyData(p, ticket) {
		return
	}
	exts := make([]utls.TLSExtension, 0, len(spec.Extensions))
	for _, e := range spec.Extensions {
		switch e := e.(type) {
		case *utls.FakeEarlyDataExtension:
			continue
		case *utls.GenericExtension:
			if e.Id == extensionEarlyData {
				continue
			}
		}
		exts = append(exts, e)
	}
	spec.Extensions = exts
}

// TicketAllowsEarlyData reports whether a connection resuming ticket may send
// 0-RTT: the server allowed early data on it (max_early_data_size 0xffffffff,
// RFC 9001 Section 4.6.1), and the preset does not turn 0-RTT off. With
// FakeEarlyDataExtension in the hello, the client sends 0-RTT whatever quic-go
// decides when it resumes, so the checks are made here, before the hello is
// built.
func TicketAllowsEarlyData(p *fingerprint.Preset, ticket *utls.ClientSessionState) bool {
	if ticket == nil || (p != nil && !p.H3QUICAllow0RTT()) {
		return false
	}
	_, state, err := ticket.ResumptionState()
	return err == nil && state != nil && state.EarlyData
}
