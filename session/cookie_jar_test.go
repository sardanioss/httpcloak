package session

import (
	"strings"
	"testing"
	"time"

	"github.com/sardanioss/httpcloak/protocol"
)

// The jar takes response cookies as RFC 6265 has a browser take them (and
// RFC 6265bis where Chrome follows it), so a session sends the cookies Chrome
// would, and only those.

func jarSession(t *testing.T) *Session {
	t.Helper()
	s := NewSession("", &protocol.SessionConfig{Preset: "chrome-latest"})
	t.Cleanup(s.Close)
	return s
}

// received has the session take setCookies from a response to url.
func received(s *Session, url string, setCookies ...string) {
	s.extractCookies(map[string][]string{"Set-Cookie": setCookies}, url)
}

// sent is the Cookie header a request to url carries.
func sent(s *Session, url string) string {
	var pairs []string
	for _, c := range s.CookiesFor(url) {
		pairs = append(pairs, c.Name+"="+c.Value)
	}
	return strings.Join(pairs, "; ")
}

func stored(s *Session, name string) *CookieState {
	for _, c := range s.GetCookies() {
		if c.Name == name {
			return &c
		}
	}
	return nil
}

const page = "https://www.shop.com.au/checkout/pay"

func TestMaxAgeDecidesTheExpiry(t *testing.T) {
	s := jarSession(t)
	past := "Thu, 01 Jan 2015 00:00:00 GMT"
	future := time.Now().Add(48 * time.Hour).UTC().Format(time.RFC1123)
	received(s, page,
		"over=1; Path=/; Expires="+past+"; Max-Age=3600",
		"after=1; Path=/; Max-Age=3600; Expires="+past,
		"negative=1; Path=/; Max-Age=-1; Expires="+future,
		"junk=1; Path=/; Max-Age=12abc",
		"lastvalid=1; Path=/; Max-Age=60; Max-Age=junk",
	)
	for _, name := range []string{"over", "after"} {
		c := stored(s, name)
		if c == nil || c.Expires == nil || time.Until(*c.Expires) < 59*time.Minute || time.Until(*c.Expires) > time.Hour {
			t.Errorf("%s: Max-Age=3600 should decide over Expires, got %+v", name, c)
		}
	}
	if c := stored(s, "negative"); c != nil {
		t.Errorf("a Max-Age below zero has the cookie expired, whatever Expires says; stored %+v", c)
	}
	if c := stored(s, "junk"); c == nil || c.Expires != nil {
		t.Errorf("a Max-Age that is not a number is ignored, leaving a session cookie; got %+v", c)
	}
	if c := stored(s, "lastvalid"); c == nil || c.Expires == nil || time.Until(*c.Expires) > time.Minute {
		t.Errorf("an invalid Max-Age leaves the last valid one; got %+v", c)
	}
	if c := stored(s, "over"); c.MaxAge != 0 {
		t.Errorf("the jar keeps the expiry, not the Max-Age, which reads back as zero; got %d", c.MaxAge)
	}
}

func TestACookieExpiresWithItsMaxAge(t *testing.T) {
	s := jarSession(t)
	received(s, page, "brief=1; Path=/; Max-Age=1")
	if got := sent(s, page); got != "brief=1" {
		t.Fatalf("sent %q, want the cookie while it lasts", got)
	}
	time.Sleep(1100 * time.Millisecond)
	if got := sent(s, page); got != "" {
		t.Fatalf("sent %q after its Max-Age, want nothing", got)
	}
}

func TestAnExpiredCookieDeletesTheStoredOne(t *testing.T) {
	for _, deletion := range []string{
		"Max-Age=0",
		"Expires=Thu, 01 Jan 1970 00:00:10 GMT",
		"Expires=Thu, 01-Jan-1970 00:00:10 GMT", // the dashed date PHP and Java send
	} {
		t.Run(deletion, func(t *testing.T) {
			s := jarSession(t)
			received(s, page, "session=abc; Path=/", "session=other; Path=/checkout")
			received(s, page, "session=; Path=/; "+deletion)
			if got := sent(s, page); got != "session=other" {
				t.Fatalf("sent %q, want only the cookie on the other path", got)
			}
		})
	}
}

func TestExpiryIsCappedAt400Days(t *testing.T) {
	s := jarSession(t)
	far := time.Now().AddDate(5, 0, 0).UTC().Format(time.RFC1123)
	received(s, page, "aged=1; Max-Age=999999999999999999999", "dated=1; Expires="+far)
	limit := time.Now().Add(400 * 24 * time.Hour)
	for _, name := range []string{"aged", "dated"} {
		c := stored(s, name)
		if c == nil || c.Expires == nil || c.Expires.After(limit) || c.Expires.Before(limit.Add(-time.Minute)) {
			t.Errorf("%s: want the expiry 400 days out, got %+v", name, c)
		}
	}
}

func TestTheDefaultPathIsTheRequestsDirectory(t *testing.T) {
	s := jarSession(t)
	received(s, "https://www.shop.com.au/a/b/c?x=1", "dir=1", "relative=1; Path=elsewhere")
	for _, name := range []string{"dir", "relative"} {
		if c := stored(s, name); c == nil || c.Path != "/a/b" {
			t.Errorf("%s: want path /a/b, got %+v", name, c)
		}
	}
	for url, want := range map[string]int{
		"https://www.shop.com.au/a/b":     2,
		"https://www.shop.com.au/a/b/d":   2,
		"https://www.shop.com.au/a/b/c/d": 2,
		"https://www.shop.com.au/a":       0,
		"https://www.shop.com.au/c":       0,
		"https://www.shop.com.au/a/bc":    0,
		"https://www.shop.com.au/":        0,
	} {
		if got := s.CookiesFor(url); len(got) != want {
			t.Errorf("%s: sent %d cookies, want %d", url, len(got), want)
		}
	}
	received(s, "https://www.shop.com.au/top", "root=1")
	if c := stored(s, "root"); c == nil || c.Path != "/" {
		t.Errorf("a path with no directory gives /, got %+v", c)
	}
}

func TestAPublicSuffixIsNoCookieDomain(t *testing.T) {
	s := jarSession(t)
	received(s, page, "suffix=1; Domain=com.au", "dotted=1; Domain=.com.au", "site=1; Domain=shop.com.au")
	received(s, "https://jbhifi.myshopify.com/", "private=1; Domain=myshopify.com")
	received(s, "http://localhost:8080/", "local=1; Domain=localhost")
	received(s, "http://1.2.3.4/", "ip=1; Domain=2.3.4")
	for _, name := range []string{"suffix", "dotted", "private", "ip"} {
		if c := stored(s, name); c != nil {
			t.Errorf("%s: stored %+v, want it refused", name, c)
		}
	}
	if c := stored(s, "site"); c == nil || c.Domain != ".shop.com.au" {
		t.Errorf("a registrable domain the host is under is a cookie domain; got %+v", c)
	}
	// A suffix that is the host itself makes a host-only cookie.
	if c := stored(s, "local"); c == nil || c.Domain != "localhost" {
		t.Errorf("want a host-only cookie for localhost, got %+v", c)
	}
	if got := sent(s, "https://other.com.au/"); got != "" {
		t.Errorf("another site under the suffix got %q", got)
	}
}

func TestAValuesBytesPassThroughWhole(t *testing.T) {
	s := jarSession(t)
	received(s, page, "name=café ☕; Path=/")
	if c := stored(s, "name"); c == nil || c.Value != "café ☕" {
		t.Fatalf("want the UTF-8 value intact, got %+v", c)
	}
}

// Replacing a cookie keeps its place in the Cookie header, as Chrome keeps
// the replaced cookie's creation time (RFC 6265 5.3 step 11).
func TestAReplacedCookieKeepsItsPlace(t *testing.T) {
	s := jarSession(t)
	received(s, page, "first=1; Path=/")
	time.Sleep(2 * time.Millisecond)
	received(s, page, "second=1; Path=/")
	time.Sleep(2 * time.Millisecond)
	received(s, page, "first=2; Path=/", "deep=1; Path=/checkout")
	if got := sent(s, page); got != "deep=1; first=2; second=1" {
		t.Fatalf("sent %q, want the longer path first, then by creation", got)
	}
}

// Cookies a caller sets follow the same expiry rules.
func TestSetCookieTakesMaxAgeAndDeletesWithAnExpiry(t *testing.T) {
	s := jarSession(t)
	s.SetCookie("kept", "1", "www.shop.com.au", "/", true, false, "", 0, nil)
	s.SetCookie("kept", "2", "www.shop.com.au", "/checkout", true, false, "", 0, nil)
	s.SetCookie("timed", "1", "www.shop.com.au", "/", true, false, "", 60, nil)
	if c := stored(s, "timed"); c == nil || c.Expires == nil || time.Until(*c.Expires) > time.Minute || time.Until(*c.Expires) < 59*time.Second {
		t.Fatalf("a Max-Age of 60 expires a minute out, got %+v", c)
	}
	past := time.Unix(10, 0)
	s.SetCookie("kept", "", "www.shop.com.au", "/", true, false, "", 0, &past)
	s.SetCookie("timed", "", "www.shop.com.au", "/", true, false, "", -1, nil)
	if got := sent(s, page); got != "kept=2" {
		t.Fatalf("sent %q, want only the cookie on the other path", got)
	}
}
