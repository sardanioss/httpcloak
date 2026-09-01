package transport

import (
	"bufio"
	"bytes"

	http "github.com/sardanioss/http"
)

// h1HeaderCasingKey carries the server's own header spelling from the HTTP/1.1
// read, where it is still visible, out to the response builder, where the
// canonicalised names are all that survive.
//
// It rides in the header map the same way the HTTP/2 read path carries arrival
// order there, and is filtered out of the response by buildHeadersMap alongside
// the other bookkeeping keys. The colon keeps it from colliding with a real
// header name, which cannot contain one.
const h1HeaderCasingKey = "Header-Casing:"

// exactHeadersKey marks a request whose headers were supplied verbatim, so the
// HTTP/1.1 writer knows not to add the ones it normally supplies.
//
// It cannot be inferred from the order list: the preset order does not name
// Connection either, so "Connection is absent from the order" is true on the
// normal path as well and would suppress it for every request.
//
// Set on the HTTP/1.1 path only. The fork's HTTP/2 and HTTP/3 encoders skip
// exactly two ordering keys by name and their validator rejects any header name
// containing a colon, so this key would fail the request outright there instead
// of being ignored. HTTP/1.1 is also the only protocol that needs it, since it
// is the only one whose request this transport writes itself.
const exactHeadersKey = "Exact-Headers:"

// stashHeaderCasing records the server's spelling on the response for the
// builder to pick up, doing nothing when the peek came back empty.
func stashHeaderCasing(h http.Header, names []string) {
	if len(names) == 0 || h == nil {
		return
	}
	h[h1HeaderCasingKey] = names
}

// takeHeaderCasing reads the stashed spelling back out.
func takeHeaderCasing(h http.Header) []string {
	if h == nil {
		return nil
	}
	return h[h1HeaderCasingKey]
}

// peekHeaderCasing reads the response header block out of the reader's buffer
// without consuming it, and returns the header names as the server actually
// spelled them.
//
// It exists because HTTP/1.1 is the only protocol where response header casing
// is observable at all. HTTP/2 and HTTP/3 require lowercase on the wire, so
// there is nothing to preserve there. On HTTP/1.1 the server's spelling is
// real, and the parse underneath goes through textproto, which canonicalises:
// a server sending `X-FOO` is reported as `X-Foo` and one sending `etag` as
// `Etag`. Anything relaying a response onward then emits a spelling the origin
// did not use.
//
// Deliberately best-effort. It looks only at bytes already buffered after one
// blocking read, so it costs nothing and cannot stall: a header block split
// across segments, or one larger than the buffer, simply yields nil and the
// caller keeps the canonical names. Correct casing is worth having and not
// worth blocking a response for.
//
// Nothing is consumed, so ReadResponse still sees the full stream.
func peekHeaderCasing(br *bufio.Reader) []string {
	if br == nil {
		return nil
	}
	// Force at most one read so there is something to look at, then take only
	// what has already arrived.
	if _, err := br.Peek(1); err != nil {
		return nil
	}
	buf, err := br.Peek(br.Buffered())
	if err != nil || len(buf) == 0 {
		return nil
	}
	end := bytes.Index(buf, []byte("\r\n\r\n"))
	if end < 0 {
		return nil // header block not fully buffered; not worth another read
	}

	block := buf[:end]
	// Skip the status line.
	nl := bytes.IndexByte(block, '\n')
	if nl < 0 {
		return nil
	}
	block = block[nl+1:]

	var names []string
	for _, line := range bytes.Split(block, []byte("\r\n")) {
		if len(line) == 0 {
			continue
		}
		// A continuation line belongs to the header before it, not a new one.
		if line[0] == ' ' || line[0] == '\t' {
			continue
		}
		c := bytes.IndexByte(line, ':')
		if c <= 0 {
			continue
		}
		names = append(names, string(bytes.TrimSpace(line[:c])))
	}
	return names
}
