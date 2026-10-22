package respheader

import (
	"context"
	"net/textproto"

	http "github.com/sardanioss/http"
	"github.com/sardanioss/http/httptrace"
)

// commonCanonical maps the HTTP/2 layer's common header names to their
// canonical form. It is the list in sardanioss/net's internal/httpcommon
// (headermap.go), which is what that layer consults before textproto when it
// canonicalises a field name with WireCaseResponseHeaders off. Using the same
// list here makes a conversion allocate exactly where that layer would have:
// for a name outside both this list and textproto's own.
var commonCanonical = func() map[string]string {
	names := []string{
		"accept", "accept-charset", "accept-encoding", "accept-language",
		"accept-ranges", "age", "access-control-allow-credentials",
		"access-control-allow-headers", "access-control-allow-methods",
		"access-control-allow-origin", "access-control-expose-headers",
		"access-control-max-age", "access-control-request-headers",
		"access-control-request-method", "allow", "authorization",
		"cache-control", "content-disposition", "content-encoding",
		"content-language", "content-length", "content-location",
		"content-range", "content-type", "cookie", "date", "etag", "expect",
		"expires", "from", "host", "if-match", "if-modified-since",
		"if-none-match", "if-unmodified-since", "last-modified", "link",
		"location", "max-forwards", "origin", "proxy-authenticate",
		"proxy-authorization", "range", "referer", "refresh", "retry-after",
		"server", "set-cookie", "strict-transport-security", "trailer",
		"transfer-encoding", "user-agent", "vary", "via", "www-authenticate",
		"x-forwarded-for", "x-forwarded-proto",
	}
	m := make(map[string]string, len(names))
	for _, n := range names {
		m[n] = textproto.CanonicalMIMEHeaderKey(n)
	}
	return m
}()

// canonicalName is the name the HTTP/2 layer stores a field under with
// WireCaseResponseHeaders off.
func canonicalName(k string) string {
	if c, ok := commonCanonical[k]; ok {
		return c
	}
	return textproto.CanonicalMIMEHeaderKey(k)
}

// Canonical rekeys h in place to the names the HTTP/2 layer uses with
// WireCaseResponseHeaders off, leaving every value slice as it is. The result
// is the map that layer builds in that mode, entry for entry: on HTTP/2 every
// field name is lowercase (the framer refuses anything else), and canonical
// form is one to one on lowercase names, so no two keys can collide; the
// bookkeeping key http.HeaderOrderKey contains a byte textproto does not
// convert past, so it keeps its spelling, as it does in that mode.
//
// The entries are read out, the map cleared and the entries put back.
// Rekeying one entry at a time (insert the new key, delete the old) leaves
// deleted slots behind and grows the map partway through; a cleared map has
// its full capacity again, which the same number of entries fits. Up to 32
// entries are held on the stack, so a response with no more fields than that
// converts with no allocation beyond the names textproto has to build, which
// are the ones the HTTP/2 layer would have built.
//
// It is for the exported boundaries that hand a raw *http.Response from an
// HTTP/2 connection to code outside this module, and must only be given a
// map nothing else is still using. httpcloak's own path keeps the wire's
// lowercase names and never calls it.
func Canonical(h map[string][]string) {
	type entry struct {
		key    string
		values []string
	}
	var stack [32]entry
	entries := stack[:0]
	changed := false
	for k, v := range h {
		c := canonicalName(k)
		changed = changed || c != k
		entries = append(entries, entry{c, v})
	}
	if !changed {
		return
	}
	clear(h)
	for _, e := range entries {
		h[e.key] = e.values
	}
}

// WithCanonical1xx makes the 1xx header maps a caller's ClientTrace receives
// canonical, as they are with WireCaseResponseHeaders off.
//
// The HTTP/2 layer hands a 1xx response's header map to Got1xxResponse while
// the round trip is still running, so converting after RoundTrip returns is
// too late. When ctx carries a trace with that hook, the returned context
// layers a trace in front of it whose Got1xxResponse rekeys the map in place;
// httptrace calls it first and then the caller's own, which therefore sees
// canonical keys. The HTTP/2 layer builds that map for the one call and does
// not touch it afterwards, so rekeying it in place is safe, and a caller that
// keeps it keeps the canonical map. ok is false, and ctx comes back unchanged,
// when there is no such hook, so a request without one pays only the context
// lookup.
func WithCanonical1xx(ctx context.Context) (_ context.Context, ok bool) {
	trace := httptrace.ContextClientTrace(ctx)
	if trace == nil || trace.Got1xxResponse == nil {
		return ctx, false
	}
	return httptrace.WithClientTrace(ctx, &httptrace.ClientTrace{
		Got1xxResponse: func(_ int, h textproto.MIMEHeader) error {
			Canonical(h)
			return nil
		},
	}), true
}

// RestoreRequest undoes, on resp, the request copy WithCanonical1xx made:
// the HTTP/2 layer records the request it was handed in resp.Request, which
// was the copy carrying the layered trace. copied is that copy and orig the
// request the caller passed. A response to any other request (a replay the
// transport built) has its context put back to orig's.
func RestoreRequest(resp *http.Response, copied, orig *http.Request) {
	switch {
	case resp == nil || resp.Request == nil || resp.Request == orig:
	case resp.Request == copied:
		resp.Request = orig
	default:
		resp.Request = resp.Request.WithContext(orig.Context())
	}
}

// KeepWireCase marks a *pool.Manager so the responses its connections return
// keep the wire's lowercase names. Package pool sets it when it loads; this
// package cannot import pool, hence the any. httpcloak's own client calls it
// on the Manager it builds, because it reads those maps through this package.
// Being internal, it is out of reach of code outside this module, whose
// Managers always convert.
var KeepWireCase func(manager any)
