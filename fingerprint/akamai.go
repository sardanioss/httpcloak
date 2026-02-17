package fingerprint

import (
	"fmt"
	"strconv"
	"strings"
)

// ParseAkamai parses an Akamai HTTP/2 fingerprint string into HTTP2Settings.
//
// Format: SETTINGS|WINDOW_UPDATE|STREAM_PRIORITY|PSEUDO_HEADER_ORDER
//
// SETTINGS: semicolon-separated key:value pairs (HTTP/2 SETTINGS frame parameters)
//   - 1: HEADER_TABLE_SIZE
//   - 2: ENABLE_PUSH
//   - 3: MAX_CONCURRENT_STREAMS
//   - 4: INITIAL_WINDOW_SIZE
//   - 5: MAX_FRAME_SIZE
//   - 6: MAX_HEADER_LIST_SIZE
//
// WINDOW_UPDATE: connection-level window update size
//
// STREAM_PRIORITY: "exclusive:streamDep:weight" or "0" for none
//
// PSEUDO_HEADER_ORDER: comma-separated pseudo header order (m=method, a=authority, s=scheme, p=path)
//
// Example: "1:65536;4:6291456;6:262144|15663105|0|m,a,s,p"
func ParseAkamai(akamai string) (*HTTP2Settings, []string, error) {
	parts := strings.Split(akamai, "|")
	if len(parts) != 4 {
		return nil, nil, fmt.Errorf("invalid Akamai format: expected 4 pipe-separated fields, got %d", len(parts))
	}

	settings := &HTTP2Settings{
		// Chrome defaults
		MaxFrameSize: 16384,
		StreamWeight: 256,
	}

	// Parse SETTINGS
	if parts[0] != "" {
		settingPairs := strings.Split(parts[0], ";")
		for _, pair := range settingPairs {
			kv := strings.SplitN(pair, ":", 2)
			if len(kv) != 2 {
				return nil, nil, fmt.Errorf("invalid setting pair: %q", pair)
			}
			key, err := strconv.Atoi(kv[0])
			if err != nil {
				return nil, nil, fmt.Errorf("invalid setting key: %q", kv[0])
			}
			val, err := strconv.ParseUint(kv[1], 10, 32)
			if err != nil {
				return nil, nil, fmt.Errorf("invalid setting value: %q", kv[1])
			}
			switch key {
			case 1:
				settings.HeaderTableSize = uint32(val)
			case 2:
				settings.EnablePush = val != 0
			case 3:
				settings.MaxConcurrentStreams = uint32(val)
			case 4:
				settings.InitialWindowSize = uint32(val)
			case 5:
				settings.MaxFrameSize = uint32(val)
			case 6:
				settings.MaxHeaderListSize = uint32(val)
			}
		}
	}

	// Parse WINDOW_UPDATE
	if parts[1] != "" && parts[1] != "0" {
		wu, err := strconv.ParseUint(parts[1], 10, 32)
		if err != nil {
			return nil, nil, fmt.Errorf("invalid window update value: %q", parts[1])
		}
		settings.ConnectionWindowUpdate = uint32(wu)
	}

	// Parse STREAM_PRIORITY (simplified - just detect if present)
	// Format: "exclusive:streamDep:weight" or just "0" for none
	if parts[2] != "" && parts[2] != "0" {
		priorityParts := strings.Split(parts[2], ":")
		if len(priorityParts) == 3 {
			settings.StreamExclusive = priorityParts[0] == "1"
			weight, err := strconv.Atoi(priorityParts[2])
			if err == nil {
				settings.StreamWeight = uint16(weight)
			}
		}
	}

	// Parse PSEUDO_HEADER_ORDER
	var pseudoHeaderOrder []string
	if parts[3] != "" {
		orderParts := strings.Split(parts[3], ",")
		pseudoHeaderOrder = make([]string, 0, len(orderParts))
		for _, p := range orderParts {
			switch strings.TrimSpace(p) {
			case "m":
				pseudoHeaderOrder = append(pseudoHeaderOrder, ":method")
			case "a":
				pseudoHeaderOrder = append(pseudoHeaderOrder, ":authority")
			case "s":
				pseudoHeaderOrder = append(pseudoHeaderOrder, ":scheme")
			case "p":
				pseudoHeaderOrder = append(pseudoHeaderOrder, ":path")
			}
		}
	}

	return settings, pseudoHeaderOrder, nil
}
