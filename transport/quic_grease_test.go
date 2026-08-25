package transport

import (
	"encoding/binary"
	"testing"
)

// Locks on the QUIC GREASE a client mixes into version_information.
//
// A server reads all of this off the handshake for free: no request, no
// capture tooling, one connection. quiche's own generator, for reference:
//
//	QuicVersionLabel CreateRandomVersionLabelForNegotiation() {
//	  QuicVersionLabel result;
//	  if (!GetQuicFlag(quic_disable_version_negotiation_grease_randomness)) {
//	    QuicRandom::GetInstance()->RandBytes(&result, sizeof(result));
//	  } else {
//	    result = MakeVersionLabel(0xd1, 0x57, 0x38, 0x3f);
//	  }
//	  result &= 0xf0f0f0f0;
//	  result |= 0x0a0a0a0a;
//	  return result;
//	}
//
// Four independent bytes, so four independent high nibbles: 65536 labels. The
// flag that would pin it defaults false and is not overridden in the browser
// tree.

// The label is well formed and its four high nibbles are drawn independently.
//
// Repeating one nibble four times produces 16 labels, and every one of them has
// all four nibbles equal. A real client manages that about once in 4096
// connections, so a single observed label is already strong evidence.
func TestGREASEVersionNibblesAreIndependent(t *testing.T) {
	const runs = 500
	labels := map[uint32]bool{}
	equalNibbles := 0

	for i := 0; i < runs; i++ {
		v := generateGREASEVersion()
		if v&0x0f0f0f0f != 0x0a0a0a0a {
			t.Fatalf("label %08x is not of the form 0x?a?a?a?a", v)
		}
		labels[v] = true
		n0 := (v >> 28) & 0xf
		if (v>>20)&0xf == n0 && (v>>12)&0xf == n0 && (v>>4)&0xf == n0 {
			equalNibbles++
		}
	}

	// One nibble repeated gives exactly 16 possible labels.
	if len(labels) <= 16 {
		t.Fatalf("%d draws produced only %d distinct labels; four independent "+
			"nibbles give 65536 and one repeated nibble gives 16", runs, len(labels))
	}
	// Chance of all four matching is 1/4096, so about 0.12 of 500 draws.
	if equalNibbles > runs/20 {
		t.Fatalf("%d of %d labels had all four nibbles equal; a real client "+
			"produces that about one time in 4096", equalNibbles, runs)
	}
}

// The GREASE label's position in available_versions is a coin flip, not a
// constant. Upstream inserts it at a uniformly chosen index of the version
// list, so half of real connections lead with it and half do not.
func TestGREASEVersionPositionVaries(t *testing.T) {
	const runs = 400
	greaseFirst := 0

	for i := 0; i < runs; i++ {
		params := BuildChromeTransportParams()
		vi := params[tpVersionInformation]
		if len(vi) != 12 {
			t.Fatalf("version_information is %d bytes, want 12 "+
				"(chosen version plus two available)", len(vi))
		}
		if got := binary.BigEndian.Uint32(vi[0:4]); got != 0x00000001 {
			t.Fatalf("chosen version = %08x, want 00000001", got)
		}
		first := binary.BigEndian.Uint32(vi[4:8])
		second := binary.BigEndian.Uint32(vi[8:12])

		switch {
		case first&0x0f0f0f0f == 0x0a0a0a0a && second == 0x00000001:
			greaseFirst++
		case second&0x0f0f0f0f == 0x0a0a0a0a && first == 0x00000001:
			// GREASE second, the other half of the coin.
		default:
			t.Fatalf("available_versions is %08x,%08x; want QUICv1 and one "+
				"GREASE label in some order", first, second)
		}
	}

	// Anything inside 25 to 75 percent is a coin flip; the defect pinned it at
	// 0 or 100. At 400 draws the standard error is about 2.5 points, so this
	// cannot flake on what it measures.
	if greaseFirst < runs/4 || greaseFirst > 3*runs/4 {
		t.Fatalf("the GREASE label led available_versions %d times out of %d; "+
			"upstream inserts it at a random index, so this should be near half",
			greaseFirst, runs)
	}
}
