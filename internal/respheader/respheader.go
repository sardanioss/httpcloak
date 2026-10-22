// Package respheader reads response headers whose map keys arrive in one of
// two shapes. The HTTP/1.1 parse and the HTTP/3 stack canonicalise names
// (Content-Encoding), while the HTTP/2 transport keys the map exactly as the
// wire carried them, which HTTP/2 requires to be lowercase
// (WireCaseResponseHeaders in the fork). Every reader of a raw response map
// therefore has to address both key sets; these accessors do, with both
// spellings held as constants so neither lookup converts or allocates.
package respheader

func first(h map[string][]string, canonical, lower string) string {
	if vv := h[canonical]; len(vv) > 0 {
		return vv[0]
	}
	if vv := h[lower]; len(vv) > 0 {
		return vv[0]
	}
	return ""
}

func values(h map[string][]string, canonical, lower string) []string {
	if vv := h[canonical]; len(vv) > 0 {
		return vv
	}
	return h[lower]
}

// ContentEncoding is the first Content-Encoding value, or "".
func ContentEncoding(h map[string][]string) string {
	return first(h, "Content-Encoding", "content-encoding")
}

// Location is the first Location value, or "".
func Location(h map[string][]string) string {
	return first(h, "Location", "location")
}

// WWWAuthenticate is the first WWW-Authenticate value, or "". Note the
// canonical spelling: MIME canonicalisation title-cases each dash segment,
// so a map built through Header.Set stores this name as "Www-Authenticate".
func WWWAuthenticate(h map[string][]string) string {
	return first(h, "Www-Authenticate", "www-authenticate")
}

// SetCookie is every Set-Cookie value in arrival order, or nil.
func SetCookie(h map[string][]string) []string {
	return values(h, "Set-Cookie", "set-cookie")
}
