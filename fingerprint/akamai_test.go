package fingerprint

import (
	"testing"
)

func TestParseAkamai_Chrome(t *testing.T) {
	// Chrome 143 Akamai fingerprint
	akamai := "1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p"

	settings, pseudoOrder, err := ParseAkamai(akamai)
	if err != nil {
		t.Fatalf("ParseAkamai failed: %v", err)
	}

	if settings.HeaderTableSize != 65536 {
		t.Errorf("HeaderTableSize: expected 65536, got %d", settings.HeaderTableSize)
	}
	if settings.EnablePush {
		t.Error("EnablePush: expected false")
	}
	if settings.InitialWindowSize != 6291456 {
		t.Errorf("InitialWindowSize: expected 6291456, got %d", settings.InitialWindowSize)
	}
	if settings.MaxHeaderListSize != 262144 {
		t.Errorf("MaxHeaderListSize: expected 262144, got %d", settings.MaxHeaderListSize)
	}
	if settings.ConnectionWindowUpdate != 15663105 {
		t.Errorf("ConnectionWindowUpdate: expected 15663105, got %d", settings.ConnectionWindowUpdate)
	}

	// Verify pseudo-header order
	expectedOrder := []string{":method", ":authority", ":scheme", ":path"}
	if len(pseudoOrder) != len(expectedOrder) {
		t.Fatalf("expected %d pseudo-headers, got %d", len(expectedOrder), len(pseudoOrder))
	}
	for i, ph := range pseudoOrder {
		if ph != expectedOrder[i] {
			t.Errorf("pseudo-header %d: expected %q, got %q", i, expectedOrder[i], ph)
		}
	}
}

func TestParseAkamai_Safari(t *testing.T) {
	// Safari/iOS Akamai fingerprint
	akamai := "2:0;4:2097152;3:100;9:1|10485760|0|m,s,p,a"

	settings, pseudoOrder, err := ParseAkamai(akamai)
	if err != nil {
		t.Fatalf("ParseAkamai failed: %v", err)
	}

	if settings.EnablePush {
		t.Error("EnablePush: expected false")
	}
	if settings.InitialWindowSize != 2097152 {
		t.Errorf("InitialWindowSize: expected 2097152, got %d", settings.InitialWindowSize)
	}
	if settings.MaxConcurrentStreams != 100 {
		t.Errorf("MaxConcurrentStreams: expected 100, got %d", settings.MaxConcurrentStreams)
	}
	if !settings.NoRFC7540Priorities {
		t.Error("NoRFC7540Priorities: expected true")
	}
	if settings.ConnectionWindowUpdate != 10485760 {
		t.Errorf("ConnectionWindowUpdate: expected 10485760, got %d", settings.ConnectionWindowUpdate)
	}

	// Safari uses m,s,p,a order
	expectedOrder := []string{":method", ":scheme", ":path", ":authority"}
	if len(pseudoOrder) != len(expectedOrder) {
		t.Fatalf("expected %d pseudo-headers, got %d", len(expectedOrder), len(pseudoOrder))
	}
	for i, ph := range pseudoOrder {
		if ph != expectedOrder[i] {
			t.Errorf("pseudo-header %d: expected %q, got %q", i, expectedOrder[i], ph)
		}
	}
}

func TestParseAkamai_Firefox(t *testing.T) {
	// Firefox Akamai fingerprint
	akamai := "1:65536;2:1;4:131072|12517377|42|m,a,s,p"

	settings, _, err := ParseAkamai(akamai)
	if err != nil {
		t.Fatalf("ParseAkamai failed: %v", err)
	}

	if settings.HeaderTableSize != 65536 {
		t.Errorf("HeaderTableSize: expected 65536, got %d", settings.HeaderTableSize)
	}
	if !settings.EnablePush {
		t.Error("EnablePush: expected true")
	}
	if settings.InitialWindowSize != 131072 {
		t.Errorf("InitialWindowSize: expected 131072, got %d", settings.InitialWindowSize)
	}
	if settings.ConnectionWindowUpdate != 12517377 {
		t.Errorf("ConnectionWindowUpdate: expected 12517377, got %d", settings.ConnectionWindowUpdate)
	}
	if settings.StreamWeight != 42 {
		t.Errorf("StreamWeight: expected 42, got %d", settings.StreamWeight)
	}
	if !settings.StreamExclusive {
		t.Error("StreamExclusive: expected true when weight > 0")
	}
}

func TestParseAkamai_MalformedInput(t *testing.T) {
	tests := []struct {
		name   string
		akamai string
	}{
		{"empty", ""},
		{"too few fields", "1:65536|15663105"},
		{"too many fields", "1:65536|15663105|0|m,a,s,p|extra"},
		{"invalid settings pair", "abc|15663105|0|m,a,s,p"},
		{"invalid window update", "1:65536|abc|0|m,a,s,p"},
		{"invalid priority", "1:65536|15663105|abc|m,a,s,p"},
		{"invalid pseudo-header", "1:65536|15663105|0|m,a,s,x"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, _, err := ParseAkamai(tt.akamai)
			if err == nil {
				t.Errorf("expected error for %q, got nil", tt.akamai)
			}
		})
	}
}

func TestParseAkamai_EmptySettings(t *testing.T) {
	// Only WINDOW_UPDATE, no settings pairs
	akamai := "|15663105|0|m,a,s,p"

	settings, pseudoOrder, err := ParseAkamai(akamai)
	if err != nil {
		t.Fatalf("ParseAkamai failed: %v", err)
	}

	// All settings should be zero-valued
	if settings.HeaderTableSize != 0 {
		t.Errorf("HeaderTableSize: expected 0, got %d", settings.HeaderTableSize)
	}
	if settings.ConnectionWindowUpdate != 15663105 {
		t.Errorf("ConnectionWindowUpdate: expected 15663105, got %d", settings.ConnectionWindowUpdate)
	}
	if len(pseudoOrder) != 4 {
		t.Errorf("expected 4 pseudo-headers, got %d", len(pseudoOrder))
	}
}

func TestParseAkamai_AllSettingsIDs(t *testing.T) {
	// Test all supported SETTINGS IDs: 1,2,3,4,5,6,9
	akamai := "1:4096;2:1;3:100;4:65535;5:16384;6:8192;9:1|1000|255|m,s,p,a"

	settings, pseudoOrder, err := ParseAkamai(akamai)
	if err != nil {
		t.Fatalf("ParseAkamai failed: %v", err)
	}

	if settings.HeaderTableSize != 4096 {
		t.Errorf("HeaderTableSize: expected 4096, got %d", settings.HeaderTableSize)
	}
	if !settings.EnablePush {
		t.Error("EnablePush: expected true")
	}
	if settings.MaxConcurrentStreams != 100 {
		t.Errorf("MaxConcurrentStreams: expected 100, got %d", settings.MaxConcurrentStreams)
	}
	if settings.InitialWindowSize != 65535 {
		t.Errorf("InitialWindowSize: expected 65535, got %d", settings.InitialWindowSize)
	}
	if settings.MaxFrameSize != 16384 {
		t.Errorf("MaxFrameSize: expected 16384, got %d", settings.MaxFrameSize)
	}
	if settings.MaxHeaderListSize != 8192 {
		t.Errorf("MaxHeaderListSize: expected 8192, got %d", settings.MaxHeaderListSize)
	}
	if !settings.NoRFC7540Priorities {
		t.Error("NoRFC7540Priorities: expected true")
	}
	if settings.StreamWeight != 255 {
		t.Errorf("StreamWeight: expected 255, got %d", settings.StreamWeight)
	}
	if !settings.StreamExclusive {
		t.Error("StreamExclusive: expected true when weight > 0")
	}
	if settings.ConnectionWindowUpdate != 1000 {
		t.Errorf("ConnectionWindowUpdate: expected 1000, got %d", settings.ConnectionWindowUpdate)
	}

	// Safari order: m,s,p,a
	expectedOrder := []string{":method", ":scheme", ":path", ":authority"}
	for i, ph := range pseudoOrder {
		if ph != expectedOrder[i] {
			t.Errorf("pseudo-header %d: expected %q, got %q", i, expectedOrder[i], ph)
		}
	}
}

func TestParseAkamai_ZeroPriority(t *testing.T) {
	// Weight=0 means no priority frame
	akamai := "1:65536|15663105|0|m,a,s,p"

	settings, _, err := ParseAkamai(akamai)
	if err != nil {
		t.Fatalf("ParseAkamai failed: %v", err)
	}

	if settings.StreamWeight != 0 {
		t.Errorf("StreamWeight: expected 0, got %d", settings.StreamWeight)
	}
	if settings.StreamExclusive {
		t.Error("StreamExclusive: expected false when weight is 0")
	}
}

func TestParseAkamai_UnknownSettingID(t *testing.T) {
	// Unknown setting ID (7) should be silently ignored
	akamai := "1:65536;7:999;4:6291456|15663105|0|m,a,s,p"

	settings, _, err := ParseAkamai(akamai)
	if err != nil {
		t.Fatalf("ParseAkamai failed: %v", err)
	}

	if settings.HeaderTableSize != 65536 {
		t.Errorf("HeaderTableSize: expected 65536, got %d", settings.HeaderTableSize)
	}
	if settings.InitialWindowSize != 6291456 {
		t.Errorf("InitialWindowSize: expected 6291456, got %d", settings.InitialWindowSize)
	}
}

func TestParseAkamai_WithMaxFrameSize(t *testing.T) {
	akamai := "1:65536;4:6291456;5:16384;6:262144|15663105|0|m,a,s,p"

	settings, _, err := ParseAkamai(akamai)
	if err != nil {
		t.Fatalf("ParseAkamai failed: %v", err)
	}

	if settings.MaxFrameSize != 16384 {
		t.Errorf("MaxFrameSize: expected 16384, got %d", settings.MaxFrameSize)
	}
}
