package fingerprint

import (
	"fmt"
	"strconv"
	"strings"
)

// ParseAkamai parses an Akamai HTTP/2 fingerprint string into HTTP2Settings
// and pseudo-header order.
//
// Format: SETTINGS|WINDOW_UPDATE|PRIORITY|PSEUDO_HEADER_ORDER
//
// SETTINGS: semicolon-separated "id:value" pairs (e.g., "1:65536;3:1000;4:6291456")
// WINDOW_UPDATE: connection-level window update value
// PRIORITY: "weight" or "0" (stream weight; 0 means default/not sent)
// PSEUDO_HEADER_ORDER: comma-separated single-char pseudo-header identifiers
//
//	m = :method, a = :authority, s = :scheme, p = :path
//
// Example (Chrome): "1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p"
func ParseAkamai(akamai string) (*HTTP2Settings, []string, error) {
	parts := strings.Split(akamai, "|")
	if len(parts) != 4 {
		return nil, nil, fmt.Errorf("akamai: expected 4 pipe-separated fields, got %d", len(parts))
	}

	settings := &HTTP2Settings{}

	// Parse SETTINGS frame
	if parts[0] != "" {
		settingsPairs := strings.Split(parts[0], ";")
		for _, pair := range settingsPairs {
			pair = strings.TrimSpace(pair)
			if pair == "" {
				continue
			}
			kv := strings.SplitN(pair, ":", 2)
			if len(kv) != 2 {
				return nil, nil, fmt.Errorf("akamai: invalid settings pair %q", pair)
			}
			id, err := strconv.ParseUint(strings.TrimSpace(kv[0]), 10, 16)
			if err != nil {
				return nil, nil, fmt.Errorf("akamai: invalid settings id %q: %w", kv[0], err)
			}
			val, err := strconv.ParseUint(strings.TrimSpace(kv[1]), 10, 32)
			if err != nil {
				return nil, nil, fmt.Errorf("akamai: invalid settings value %q: %w", kv[1], err)
			}

			switch id {
			case 1: // HEADER_TABLE_SIZE
				settings.HeaderTableSize = uint32(val)
			case 2: // ENABLE_PUSH
				settings.EnablePush = val != 0
			case 3: // MAX_CONCURRENT_STREAMS
				settings.MaxConcurrentStreams = uint32(val)
			case 4: // INITIAL_WINDOW_SIZE
				settings.InitialWindowSize = uint32(val)
			case 5: // MAX_FRAME_SIZE
				settings.MaxFrameSize = uint32(val)
			case 6: // MAX_HEADER_LIST_SIZE
				settings.MaxHeaderListSize = uint32(val)
			case 8: // SETTINGS_ENABLE_CONNECT_PROTOCOL
				// Ignore for now
			case 9: // SETTINGS_NO_RFC7540_PRIORITIES
				settings.NoRFC7540Priorities = val != 0
			default:
				// Unknown setting ID — ignore
			}
		}
	}

	// Parse WINDOW_UPDATE
	if parts[1] != "" {
		windowUpdate, err := strconv.ParseUint(strings.TrimSpace(parts[1]), 10, 32)
		if err != nil {
			return nil, nil, fmt.Errorf("akamai: invalid window update %q: %w", parts[1], err)
		}
		settings.ConnectionWindowUpdate = uint32(windowUpdate)
	}

	// Parse PRIORITY (stream weight)
	if parts[2] != "" {
		weight, err := strconv.ParseUint(strings.TrimSpace(parts[2]), 10, 16)
		if err != nil {
			return nil, nil, fmt.Errorf("akamai: invalid priority weight %q: %w", parts[2], err)
		}
		if weight > 0 {
			settings.StreamWeight = uint16(weight)
			settings.StreamExclusive = true
		}
	}

	// Parse pseudo-header order
	var pseudoOrder []string
	if parts[3] != "" {
		chars := strings.Split(strings.TrimSpace(parts[3]), ",")
		for _, ch := range chars {
			ch = strings.TrimSpace(ch)
			switch ch {
			case "m":
				pseudoOrder = append(pseudoOrder, ":method")
			case "a":
				pseudoOrder = append(pseudoOrder, ":authority")
			case "s":
				pseudoOrder = append(pseudoOrder, ":scheme")
			case "p":
				pseudoOrder = append(pseudoOrder, ":path")
			default:
				return nil, nil, fmt.Errorf("akamai: unknown pseudo-header identifier %q", ch)
			}
		}
	}

	return settings, pseudoOrder, nil
}
