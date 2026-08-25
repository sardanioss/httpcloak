package transport

import (
	"testing"

	"github.com/sardanioss/httpcloak/internal/h3build"
)

// Locks on the reserved SETTINGS entry a client advertises on its HTTP/3
// control stream. A server reads it off the handshake with no request sent.
//
// quiche, QuicSendControlStream::MaybeSendSettingsFrame:
//
//	uint32_t result;
//	QuicRandom::GetInstance()->RandBytes(&result, sizeof(result));
//	uint64_t setting_id = 0x1fULL * static_cast<uint64_t>(result) + 0x21ULL;
//	QuicRandom::GetInstance()->RandBytes(&result, sizeof(result));
//	settings.values[setting_id] = result;
//
// RFC 9114 section 7.2.4.1 reserves identifiers of the form 0x1f * N + 0x21.

// The identifier inverts to something that fits the uint32 upstream draws.
//
// The old range was N in [1e9, 1e10), so about 63 percent of identifiers sat
// above 0x1f*2^32 + 0x21, which quiche cannot reach. That is checkable from a
// single connection by inverting one varint. Measured against a live origin
// before this fix, 2 of 5 connections carried an impossible identifier.
func TestGREASESettingIDFitsTheDrawSpace(t *testing.T) {
	const runs = 500
	const oldFloor = uint64(0x1f*1000000000 + 0x21)

	ids := map[uint64]bool{}
	var belowOldFloor int
	for i := 0; i < runs; i++ {
		id, _ := h3build.GREASESetting()
		if (id-0x21)%0x1f != 0 {
			t.Fatalf("setting id %d is not of the form 0x1f*N + 0x21, which "+
				"RFC 9114 reserves for greasing", id)
		}
		result := (id - 0x21) / 0x1f
		if result >= 1<<32 {
			t.Fatalf("setting id %d inverts to %d, which does not fit the "+
				"uint32 upstream draws; a server checks exactly this", id, result)
		}
		ids[id] = true
		if id < oldFloor {
			belowOldFloor++
		}
	}
	if len(ids) < runs-1 {
		t.Fatalf("%d draws produced only %d distinct identifiers", runs, len(ids))
	}
	// A uniform uint32 lands below the old floor about 23 percent of the time,
	// and the old implementation reached it exactly never.
	if belowOldFloor < runs/10 {
		t.Errorf("only %d of %d identifiers fell below the old floor of %d; a "+
			"uniform uint32 draw lands there about 23 percent of the time",
			belowOldFloor, runs, oldFloor)
	}
}

// The value is a second, independent uint32. It used to exclude zero on the
// stated grounds that Chrome never sends it, which the source above does not
// support, though at one draw in 2^32 that was never observable. What is
// observable is the value tracking the identifier, so this holds them apart.
func TestGREASESettingValueIsIndependent(t *testing.T) {
	const runs = 500
	var sameAsID int
	for i := 0; i < runs; i++ {
		id, value := h3build.GREASESetting()
		if value >= 1<<32 {
			t.Fatalf("setting value %d does not fit a uint32", value)
		}
		if value == (id-0x21)/0x1f {
			sameAsID++
		}
	}
	if sameAsID > 1 {
		t.Errorf("%d of %d values equalled the identifier's own draw; upstream "+
			"draws the value separately", sameAsID, runs)
	}
}

// Both entrypoints build SETTINGS through the same helper, so neither can
// advertise a differently shaped GREASE entry for one profile.
func TestGREASESettingReachesTheSettingsMap(t *testing.T) {
	p := presetOrSkip(t, "chrome-151-windows")
	if p == nil {
		return
	}
	for i := 0; i < 50; i++ {
		id, value := h3build.GREASESetting()
		s := h3build.Settings(p, id, value)
		got, ok := s[id]
		if !ok {
			t.Fatalf("the GREASE identifier %d is missing from the SETTINGS map", id)
		}
		if got != value {
			t.Fatalf("GREASE setting %d = %d, want %d", id, got, value)
		}
	}
}
