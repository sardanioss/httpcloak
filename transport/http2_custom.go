package transport

import (
	"bytes"
	"encoding/binary"
	"net"
	"sync"
	"time"

	"github.com/sardanioss/httpcloak/fingerprint"
	"github.com/sardanioss/net/http2/hpack"
	utls "github.com/refraction-networking/utls"
)

// HTTP/2 frame types
const (
	frameTypeSettings     = 0x4
	frameTypeWindowUpdate = 0x8
	frameTypeHeaders      = 0x1
)

// HTTP/2 settings identifiers
const (
	settingHeaderTableSize      = 0x1
	settingEnablePush           = 0x2
	settingMaxConcurrentStreams = 0x3
	settingInitialWindowSize    = 0x4
	settingMaxFrameSize         = 0x5
	settingMaxHeaderListSize    = 0x6
)

// HTTP/2 frame header size
const frameHeaderLen = 9

// http2Conn wraps a connection to intercept and modify HTTP/2 frames
type http2Conn struct {
	net.Conn
	preset        *fingerprint.Preset
	buf           bytes.Buffer
	mu            sync.Mutex
	wrotePreface  bool
	wroteSettings bool
	wroteWindow   bool
	hpackEncoder  *hpack.Encoder
	hpackBuf      bytes.Buffer
}

// newHTTP2Conn creates a new HTTP/2 connection wrapper
func newHTTP2Conn(conn net.Conn, preset *fingerprint.Preset) *http2Conn {
	c := &http2Conn{
		Conn:   conn,
		preset: preset,
	}
	// Initialize HPACK encoder with same table size as preset
	c.hpackEncoder = hpack.NewEncoder(&c.hpackBuf)
	return c
}

// Write intercepts writes to modify HTTP/2 frames
func (c *http2Conn) Write(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Accumulate data
	c.buf.Write(p)
	originalLen := len(p)

	// Process buffered data
	for c.buf.Len() > 0 {
		data := c.buf.Bytes()

		// Check for HTTP/2 preface (first 24 bytes)
		if !c.wrotePreface {
			preface := []byte("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")
			if len(data) >= len(preface) && bytes.Equal(data[:len(preface)], preface) {
				// Write preface as-is
				if _, err := c.Conn.Write(preface); err != nil {
					return 0, err
				}
				c.buf.Next(len(preface))
				c.wrotePreface = true
				continue
			}
			// Not enough data yet
			break
		}

		// Need at least frame header
		if len(data) < frameHeaderLen {
			break
		}

		// Parse frame header
		length := (uint32(data[0]) << 16) | (uint32(data[1]) << 8) | uint32(data[2])
		frameType := data[3]
		// flags := data[4]
		// streamID := binary.BigEndian.Uint32(data[5:9]) & 0x7FFFFFFF

		// Need full frame
		frameSize := int(frameHeaderLen + length)
		if len(data) < frameSize {
			break
		}

		// Handle different frame types
		switch frameType {
		case frameTypeSettings:
			if !c.wroteSettings {
				// Replace with our custom SETTINGS frame
				customFrame := c.buildCustomSettingsFrame()
				if _, err := c.Conn.Write(customFrame); err != nil {
					return 0, err
				}
				c.wroteSettings = true
				c.buf.Next(frameSize)
				continue
			}

		case frameTypeWindowUpdate:
			if !c.wroteWindow {
				// Replace with our custom WINDOW_UPDATE frame
				customFrame := c.buildCustomWindowUpdateFrame()
				if _, err := c.Conn.Write(customFrame); err != nil {
					return 0, err
				}
				c.wroteWindow = true
				c.buf.Next(frameSize)
				continue
			}

		case frameTypeHeaders:
			// Reorder pseudo-headers and add Priority flag
			flags := data[4]
			streamID := binary.BigEndian.Uint32(data[5:9]) & 0x7FFFFFFF

			// Only modify if this is a request (has END_HEADERS)
			hasEndHeaders := flags&0x4 != 0
			if hasEndHeaders && streamID > 0 {
				// Parse and rebuild the HEADERS frame
				customFrame, err := c.buildCustomHeadersFrame(data[:frameSize])
				if err == nil {
					if _, err := c.Conn.Write(customFrame); err != nil {
						return 0, err
					}
					c.buf.Next(frameSize)
					continue
				}
				// If error, fall through to write original frame
			}
		}

		// Write frame as-is
		if _, err := c.Conn.Write(data[:frameSize]); err != nil {
			return 0, err
		}
		c.buf.Next(frameSize)
	}

	return originalLen, nil
}

// buildCustomSettingsFrame builds a SETTINGS frame with preset values
// Chrome sends: 1:65536;2:0;3:0;4:6291456;6:262144
func (c *http2Conn) buildCustomSettingsFrame() []byte {
	settings := c.preset.HTTP2Settings

	// Build settings payload
	// Each setting is 6 bytes: 2 bytes ID + 4 bytes value
	var payload bytes.Buffer

	// HEADER_TABLE_SIZE (1)
	if settings.HeaderTableSize > 0 {
		binary.Write(&payload, binary.BigEndian, uint16(settingHeaderTableSize))
		binary.Write(&payload, binary.BigEndian, settings.HeaderTableSize)
	}

	// ENABLE_PUSH (2) - Chrome sends 0
	binary.Write(&payload, binary.BigEndian, uint16(settingEnablePush))
	if settings.EnablePush {
		binary.Write(&payload, binary.BigEndian, uint32(1))
	} else {
		binary.Write(&payload, binary.BigEndian, uint32(0))
	}

	// MAX_CONCURRENT_STREAMS (3) - Chrome sends 0 (no limit)
	binary.Write(&payload, binary.BigEndian, uint16(settingMaxConcurrentStreams))
	binary.Write(&payload, binary.BigEndian, settings.MaxConcurrentStreams)

	// INITIAL_WINDOW_SIZE (4)
	if settings.InitialWindowSize > 0 {
		binary.Write(&payload, binary.BigEndian, uint16(settingInitialWindowSize))
		binary.Write(&payload, binary.BigEndian, settings.InitialWindowSize)
	}

	// MAX_FRAME_SIZE (5) - Chrome doesn't send this
	// Skip

	// MAX_HEADER_LIST_SIZE (6)
	if settings.MaxHeaderListSize > 0 {
		binary.Write(&payload, binary.BigEndian, uint16(settingMaxHeaderListSize))
		binary.Write(&payload, binary.BigEndian, settings.MaxHeaderListSize)
	}

	// Build frame header
	// Format: Length (3 bytes) + Type (1 byte) + Flags (1 byte) + Stream ID (4 bytes)
	payloadLen := payload.Len()
	frame := make([]byte, frameHeaderLen+payloadLen)
	frame[0] = byte(payloadLen >> 16)
	frame[1] = byte(payloadLen >> 8)
	frame[2] = byte(payloadLen)
	frame[3] = frameTypeSettings // Type: SETTINGS
	frame[4] = 0                 // Flags: none
	// Stream ID: 0 (already zero)
	copy(frame[frameHeaderLen:], payload.Bytes())

	return frame
}

// buildCustomHeadersFrame rebuilds a HEADERS frame with reordered pseudo-headers and Priority flag
// Chrome uses order: :method, :authority, :scheme, :path (m,a,s,p)
// Chrome also includes Priority flag with weight=256, depends_on=0, exclusive=1
func (c *http2Conn) buildCustomHeadersFrame(originalFrame []byte) ([]byte, error) {
	// Parse original frame header
	originalFlags := originalFrame[4]
	streamID := binary.BigEndian.Uint32(originalFrame[5:9]) & 0x7FFFFFFF

	// Check if original has padding or priority (we'll replace priority)
	hasPadding := originalFlags&0x8 != 0
	hasPriority := originalFlags&0x20 != 0

	// Calculate header block start
	headerBlockStart := frameHeaderLen
	if hasPadding {
		headerBlockStart++ // Skip pad length byte
	}
	if hasPriority {
		headerBlockStart += 5 // Skip original priority data
	}

	// Get the header block fragment
	headerBlock := originalFrame[headerBlockStart:]
	if hasPadding && len(originalFrame) > frameHeaderLen {
		padLen := int(originalFrame[frameHeaderLen])
		if padLen < len(headerBlock) {
			headerBlock = headerBlock[:len(headerBlock)-padLen]
		}
	}

	// Decode HPACK headers (use same table size as our HEADER_TABLE_SIZE setting)
	decoder := hpack.NewDecoder(65536, nil)
	headers, err := decoder.DecodeFull(headerBlock)
	if err != nil {
		return nil, err
	}

	// Separate pseudo-headers and regular headers
	var method, authority, scheme, path string
	headerMap := make(map[string]string)
	for _, h := range headers {
		switch h.Name {
		case ":method":
			method = h.Value
		case ":authority":
			authority = h.Value
		case ":scheme":
			scheme = h.Value
		case ":path":
			path = h.Value
		default:
			headerMap[h.Name] = h.Value
		}
	}

	// Chrome 143 header order (exact order matters for fingerprinting!)
	// Order extracted from real Chrome 143 request to tls.peet.ws
	chromeHeaderOrder := []string{
		"sec-ch-ua",
		"sec-ch-ua-mobile",
		"sec-ch-ua-platform",
		"upgrade-insecure-requests",
		"user-agent",
		"accept",
		"sec-fetch-site",
		"sec-fetch-mode",
		"sec-fetch-user",
		"sec-fetch-dest",
		"accept-encoding",
		"accept-language",
		"priority",
		// High-entropy Client Hints (only sent when requested via Accept-CH)
		"sec-ch-ua-arch",
		"sec-ch-ua-bitness",
		"sec-ch-ua-full-version-list",
		"sec-ch-ua-model",
		"sec-ch-ua-platform-version",
		// Other headers
		"cache-control",
		"cookie",
		"origin",
		"pragma",
		"referer",
	}

	// Re-encode headers in Chrome order: m, a, s, p, then regular headers
	c.hpackBuf.Reset()
	c.hpackEncoder.WriteField(hpack.HeaderField{Name: ":method", Value: method})
	c.hpackEncoder.WriteField(hpack.HeaderField{Name: ":authority", Value: authority})
	c.hpackEncoder.WriteField(hpack.HeaderField{Name: ":scheme", Value: scheme})
	c.hpackEncoder.WriteField(hpack.HeaderField{Name: ":path", Value: path})

	// Write headers in Chrome order
	written := make(map[string]bool)
	for _, name := range chromeHeaderOrder {
		if val, ok := headerMap[name]; ok {
			c.hpackEncoder.WriteField(hpack.HeaderField{Name: name, Value: val})
			written[name] = true
		}
	}

	// Write any remaining headers that weren't in the order list
	for name, val := range headerMap {
		if !written[name] {
			c.hpackEncoder.WriteField(hpack.HeaderField{Name: name, Value: val})
		}
	}
	newHeaderBlock := c.hpackBuf.Bytes()

	// Build priority data: 5 bytes
	// Exclusive (1 bit) + Stream Dependency (31 bits) + Weight (8 bits)
	// Chrome uses: exclusive=1, depends_on=0, weight=256 (wire value = 255)
	priorityData := make([]byte, 5)
	// Set exclusive bit (0x80) and depends_on stream 0
	binary.BigEndian.PutUint32(priorityData[0:4], 0x80000000) // exclusive=1, depends_on=0
	// Weight: Chrome sends 256, wire format is weight-1 = 255
	weight := c.preset.HTTP2Settings.StreamWeight
	if weight == 0 {
		weight = 256
	}
	priorityData[4] = byte(weight - 1)

	// Build new frame
	// New flags: add Priority (0x20), keep END_STREAM and END_HEADERS
	newFlags := (originalFlags & 0x05) | 0x20 // Keep END_STREAM (0x1), END_HEADERS (0x4), add PRIORITY (0x20)

	// Calculate new payload length
	newPayloadLen := 5 + len(newHeaderBlock) // 5 bytes priority + header block

	// Build frame
	frame := make([]byte, frameHeaderLen+newPayloadLen)
	frame[0] = byte(newPayloadLen >> 16)
	frame[1] = byte(newPayloadLen >> 8)
	frame[2] = byte(newPayloadLen)
	frame[3] = frameTypeHeaders
	frame[4] = newFlags
	binary.BigEndian.PutUint32(frame[5:9], streamID)

	// Add priority data
	copy(frame[frameHeaderLen:], priorityData)
	// Add header block
	copy(frame[frameHeaderLen+5:], newHeaderBlock)

	return frame, nil
}

// buildCustomWindowUpdateFrame builds a WINDOW_UPDATE frame with preset value
// Chrome sends increment of 15663105
func (c *http2Conn) buildCustomWindowUpdateFrame() []byte {
	increment := c.preset.HTTP2Settings.ConnectionWindowUpdate
	if increment == 0 {
		increment = 15663105 // Default Chrome value
	}

	// WINDOW_UPDATE payload is 4 bytes (increment value)
	frame := make([]byte, frameHeaderLen+4)
	frame[0] = 0 // Length high byte
	frame[1] = 0 // Length mid byte
	frame[2] = 4 // Length low byte (4 bytes payload)
	frame[3] = frameTypeWindowUpdate // Type: WINDOW_UPDATE
	frame[4] = 0                     // Flags: none
	// Stream ID: 0 (connection-level, already zero)

	// Write increment (must not have reserved bit set)
	binary.BigEndian.PutUint32(frame[frameHeaderLen:], increment&0x7FFFFFFF)

	return frame
}

// Read passes through to the underlying connection
func (c *http2Conn) Read(p []byte) (int, error) {
	return c.Conn.Read(p)
}

// Close closes the underlying connection
func (c *http2Conn) Close() error {
	return c.Conn.Close()
}

// LocalAddr returns the local network address
func (c *http2Conn) LocalAddr() net.Addr {
	return c.Conn.LocalAddr()
}

// RemoteAddr returns the remote network address
func (c *http2Conn) RemoteAddr() net.Addr {
	return c.Conn.RemoteAddr()
}

// SetDeadline sets the read and write deadlines
func (c *http2Conn) SetDeadline(t time.Time) error {
	return c.Conn.SetDeadline(t)
}

// SetReadDeadline sets the read deadline
func (c *http2Conn) SetReadDeadline(t time.Time) error {
	return c.Conn.SetReadDeadline(t)
}

// SetWriteDeadline sets the write deadline
func (c *http2Conn) SetWriteDeadline(t time.Time) error {
	return c.Conn.SetWriteDeadline(t)
}

// tlsConnWrapper wraps http2Conn and provides TLS state for http2.Transport
type tlsConnWrapper struct {
	*http2Conn
	tlsConn *utls.UConn
}

// ConnectionState returns the TLS connection state
func (w *tlsConnWrapper) ConnectionState() utls.ConnectionState {
	return w.tlsConn.ConnectionState()
}

// wrapTLSConn wraps a uTLS connection with HTTP/2 frame interception
func wrapTLSConn(tlsConn *utls.UConn, preset *fingerprint.Preset) net.Conn {
	h2Conn := newHTTP2Conn(tlsConn, preset)
	return &tlsConnWrapper{
		http2Conn: h2Conn,
		tlsConn:   tlsConn,
	}
}
