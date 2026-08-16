package transport

import "testing"

// Regression lock for the one gap in the OnRedirect API as merged.
//
// Redirect.Headers aliases the 3xx response's header map, which is
// lowercase-keyed throughout the library, while the field's own doc comment
// invites callers to read Set-Cookie from it. That access returns nothing:
//
//	r.Headers["Set-Cookie"] -> []                        (silently empty)
//	r.Headers["set-cookie"] -> [sid=abc123; Path=/]
//
// No error, no panic, just a policy callback that never fires. GetHeader and
// GetHeaders exist so the documented spelling resolves.
func TestRedirectHeaderAccessors(t *testing.T) {
	r := &Redirect{Headers: map[string][]string{
		"set-cookie": {"sid=abc123; Path=/", "theme=dark"},
	}}

	// The spelling a caller actually writes, taken from the doc comment.
	if got := r.GetHeader("Set-Cookie"); got != "sid=abc123; Path=/" {
		t.Errorf("GetHeader(\"Set-Cookie\") = %q, want the first cookie; canonical "+
			"casing must resolve or the documented use silently reads nothing", got)
	}
	// Set-Cookie repeats, so the plural form has to carry both.
	if got := r.GetHeaders("Set-Cookie"); len(got) != 2 {
		t.Errorf("GetHeaders(\"Set-Cookie\") returned %d values, want 2: %v", len(got), got)
	}
	// A miss, and a nil map, must stay empty rather than panic.
	if got := r.GetHeader("Nope"); got != "" {
		t.Errorf("absent header returned %q, want empty", got)
	}
	if got := (&Redirect{}).GetHeader("Set-Cookie"); got != "" {
		t.Errorf("GetHeader on a nil map = %q, want empty", got)
	}
}
