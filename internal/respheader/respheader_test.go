package respheader

import (
	"net/textproto"
	"strings"
	"testing"
)

// The two spellings passed to each lookup must be exactly what the two map
// shapes hold: the textproto canonical form (what Header.Set and the HTTP/1.1
// parse produce; note it is "Www-Authenticate", not "WWW-Authenticate") and
// its exact lowering (the HTTP/2 wire form). A wrong spelling quietly
// disables one key set, which is precisely the failure this package exists
// to prevent.
func TestSpellingsAgree(t *testing.T) {
	pairs := [][2]string{
		{"Content-Encoding", "content-encoding"},
		{"Location", "location"},
		{"Www-Authenticate", "www-authenticate"},
		{"Set-Cookie", "set-cookie"},
	}
	for _, p := range pairs {
		if textproto.CanonicalMIMEHeaderKey(p[1]) != p[0] {
			t.Errorf("canonical of %q is %q, accessor uses %q", p[1], textproto.CanonicalMIMEHeaderKey(p[1]), p[0])
		}
		if strings.ToLower(p[0]) != p[1] {
			t.Errorf("%q does not lower to %q", p[0], p[1])
		}
	}
}

func TestBothKeySets(t *testing.T) {
	if got := ContentEncoding(map[string][]string{"Content-Encoding": {"br"}}); got != "br" {
		t.Errorf("canonical: got %q", got)
	}
	if got := ContentEncoding(map[string][]string{"content-encoding": {"gzip"}}); got != "gzip" {
		t.Errorf("wire case: got %q", got)
	}
	if got := ContentEncoding(map[string][]string{}); got != "" {
		t.Errorf("absent: got %q", got)
	}
	if got := Location(map[string][]string{"location": {"/next"}}); got != "/next" {
		t.Errorf("location wire case: got %q", got)
	}
	if got := SetCookie(map[string][]string{"set-cookie": {"a=1", "b=2"}}); len(got) != 2 || got[0] != "a=1" {
		t.Errorf("set-cookie wire case: got %v", got)
	}
	if got := SetCookie(map[string][]string{"Set-Cookie": {"c=3"}}); len(got) != 1 || got[0] != "c=3" {
		t.Errorf("set-cookie canonical: got %v", got)
	}
	if got := WWWAuthenticate(map[string][]string{"www-authenticate": {"Digest x"}}); got != "Digest x" {
		t.Errorf("www-authenticate wire case: got %q", got)
	}
}
