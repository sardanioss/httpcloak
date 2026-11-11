package session

import (
	"strconv"
	"testing"
	"time"
)

func TestParseMaxAge(t *testing.T) {
	overflow := strconv.Itoa(int(^uint(0)>>1)) + "0"
	for _, tc := range []struct {
		value string
		want  int
		valid bool
	}{
		{"60", 60, true},
		{"00060", 60, true},
		{"0", -1, true},
		{"-0", -1, true},
		{"-60", -1, true},
		{"", 0, false},
		{"-", 0, false},
		{"+60", 0, false},
		{"60seconds", 0, false},
		{"1.5", 0, false},
		{" 60", 0, false},
		{overflow, maxCookieAgeSeconds, true},
		{"34560000", 34560000, true},
		{"34560001", maxCookieAgeSeconds, true},
		{"-" + overflow, -1, true},
	} {
		t.Run(tc.value, func(t *testing.T) {
			got, valid := parseMaxAge(tc.value)
			if got != tc.want || valid != tc.valid {
				t.Fatalf("parseMaxAge(%q) = (%d, %v), want (%d, %v)", tc.value, got, valid, tc.want, tc.valid)
			}
		})
	}
}

func TestCookieMaxAgeDeadlineAndReplacement(t *testing.T) {
	jar := NewCookieJar()
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	past, future := now.Add(-time.Hour), now.Add(time.Hour)
	key := cookieKey("/", "token")

	// Fixed receipt times test TTL arithmetic without waiting for expiration.
	jar.receive(&CookieData{Name: "token", Value: "old", Domain: "example.test", Path: "/", MaxAge: 10, Expires: &past}, now)
	first := jar.cookies["example.test"][key]
	if first.Expires == nil || !first.Expires.Equal(now.Add(10*time.Second)) {
		t.Fatalf("Max-Age did not override expired Expires: %+v", first)
	}
	updatedAt := now.Add(5 * time.Second)
	jar.receive(&CookieData{Name: "token", Value: "new", Domain: "example.test", Path: "/", MaxAge: 20, Expires: &future}, updatedAt)
	updated := jar.cookies["example.test"][key]
	if !updated.Expires.Equal(updatedAt.Add(20 * time.Second)) {
		t.Fatalf("renewal deadline = %s, want %s", updated.Expires, updatedAt.Add(20*time.Second))
	}
	if !updated.CreatedAt.Equal(now) {
		t.Fatalf("replacement changed header ordering timestamp: %s", updated.CreatedAt)
	}
	newAt := now.Add(time.Minute)
	jar.receive(&CookieData{Name: "token", Domain: "example.test", Path: "/", MaxAge: 20}, newAt)
	if !jar.cookies["example.test"][key].CreatedAt.Equal(newAt) {
		t.Fatal("replacement of an expired cookie retained its old creation time")
	}
	jar.receive(&CookieData{Name: "token", Domain: "example.test", Path: "/", Expires: &newAt}, newAt)
	if jar.Count() != 0 {
		t.Fatal("cookie at its expiration deadline was not deleted")
	}
}

func TestCookieMaxAgeLargeLifetimeDoesNotOverflow(t *testing.T) {
	jar := NewCookieJar()
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	jar.receive(&CookieData{Name: "long", Domain: "example.test", Path: "/", MaxAge: int(^uint(0) >> 1)}, now)
	cookie := jar.cookies["example.test"][cookieKey("/", "long")]
	if cookie == nil || cookie.Expires == nil || !cookie.Expires.After(now) {
		t.Fatalf("large positive Max-Age wrapped into the past: %+v", cookie)
	}
}

func TestCookieMaxAgeReplacementPreservesHeaderOrder(t *testing.T) {
	jar := NewCookieJar()
	created := time.Unix(0, 0)
	jar.store(&CookieData{Name: "first", Value: "old", Domain: "example.test", Path: "/"}, created)
	jar.store(&CookieData{Name: "second", Value: "other", Domain: "example.test", Path: "/"}, created.Add(time.Second))
	jar.Set("example.test", &CookieData{Name: "first", Value: "updated", Path: "/", MaxAge: 3600}, true)
	if got := jar.BuildCookieHeader("example.test", "/", true); got != "first=updated; second=other" {
		t.Fatalf("replacement changed the cookie header order: %q", got)
	}
}

func TestCookieMaxAgeSettersAndScopedDeletion(t *testing.T) {
	for _, api := range []string{"Set", "SetSimple"} {
		t.Run(api, func(t *testing.T) {
			jar := NewCookieJar()
			set := func(c *CookieData) {
				if api == "Set" {
					jar.Set("www.example.test", c, true)
					return
				}
				jar.SetSimple(c.Name, c.Value, c.Domain, c.Path, c.Secure, c.HttpOnly, c.SameSite, c.MaxAge, c.Expires)
			}
			// Max-Age beats Expires on a Set-Cookie header. SetSimple takes an
			// Expires as already resolved, so it gets Max-Age alone here.
			var past *time.Time
			if api == "Set" {
				p := time.Now().Add(-time.Hour)
				past = &p
			}
			before := time.Now()
			set(&CookieData{Name: "token", Value: "root", Domain: ".example.test", Path: "/", MaxAge: 60, Expires: past})
			after := time.Now()
			cookie := jar.cookies[".example.test"][cookieKey("/", "token")]
			if cookie == nil || cookie.Expires == nil || cookie.Expires.Before(before.Add(time.Minute)) || cookie.Expires.After(after.Add(time.Minute)) {
				t.Fatalf("Max-Age deadline outside receipt bounds: %+v", cookie)
			}
			set(&CookieData{Name: "token", Value: "path", Domain: ".example.test", Path: "/account"})
			set(&CookieData{Name: "token", Value: "domain", Domain: ".www.example.test", Path: "/"})
			future := time.Now().Add(time.Hour)
			set(&CookieData{Name: "token", Domain: ".example.test", Path: "/", MaxAge: -1, Expires: &future})
			if jar.Count() != 2 {
				t.Fatalf("scoped deletion left %d cookies, want 2", jar.Count())
			}
			if jar.cookies[".example.test"][cookieKey("/", "token")] != nil ||
				jar.cookies[".example.test"][cookieKey("/account", "token")] == nil ||
				jar.cookies[".www.example.test"][cookieKey("/", "token")] == nil {
				t.Fatal("deletion affected cookies outside the specified domain and path")
			}
		})
	}
}

func TestCookieMaxAgeExtractCookies(t *testing.T) {
	overflow := strconv.Itoa(int(^uint(0)>>1)) + "0"
	for _, tc := range []struct {
		attributes string
		wantAge    int
		deleted    bool
	}{
		{"", 0, false},
		{"Max-Age=60", 60, false},
		{"Max-Age=0", -1, true},
		{"Max-Age=-60", -1, true},
		{"Max-Age=60; Expires=Thu, 01 Jan 1970 00:00:00 GMT", 60, false},
		{"Expires=Thu, 01 Jan 1970 00:00:00 GMT; Max-Age=60", 60, false},
		{"Max-Age=garbage", 0, false},
		{"Max-Age=60bad", 0, false},
		// Too large is capped at 400 days, as in Chromium, not dropped.
		{"Max-Age=" + overflow, maxCookieAgeSeconds, false},
		{"Max-Age=99999999", maxCookieAgeSeconds, false},
		{"Max-Age=garbage; Expires=Thu, 01 Jan 1970 00:00:00 GMT", 0, true},
		{"Max-Age=garbage; Expires=Fri, 31 Dec 9999 23:59:59 GMT", 0, false},
		// The last Max-Age decides, and an invalid one leaves none.
		{"Max-Age=60; Max-Age=bad", 0, false},
		{"Max-Age=60; Max-Age=0", -1, true},
	} {
		t.Run(tc.attributes, func(t *testing.T) {
			s := &Session{cookies: NewCookieJar()}
			s.cookies.Set("example.test", &CookieData{Name: "token", Value: "old", Path: "/"}, true)
			s.extractCookies(map[string][]string{"Set-Cookie": {"token=new; Path=/; " + tc.attributes}}, "https://example.test/")
			cookies := s.cookies.Get("example.test", "/", true)
			if tc.deleted {
				if len(cookies) != 0 || s.cookies.Count() != 0 {
					t.Fatalf("deletion header left cookies: %+v", cookies)
				}
				return
			}
			if len(cookies) != 1 || cookies[0].Value != "new" || cookies[0].MaxAge != tc.wantAge {
				t.Fatalf("parsed cookie = %+v, want one updated cookie with MaxAge %d", cookies, tc.wantAge)
			}
			if tc.wantAge > 0 && cookies[0].Expires == nil {
				t.Fatal("positive Max-Age has no absolute expiration")
			}
		})
	}
}

func TestCookieMaxAgeImportKeepsAbsoluteDeadline(t *testing.T) {
	jar := NewCookieJar()
	jar.SetSimple("token", "value", "example.test", "/", false, false, "", 3600, nil)
	saved := jar.Export()
	expiration, created := *saved["example.test"][0].Expires, *saved["example.test"][0].CreatedAt
	restored := NewCookieJar()
	restored.Import(saved)
	got := restored.GetAll()
	if len(got) != 1 || !got[0].Expires.Equal(expiration) || !got[0].CreatedAt.Equal(created) {
		t.Fatalf("import changed persisted deadline or creation time: %+v", got)
	}
	// Loading an expired snapshot must not restart its positive Max-Age.
	past := time.Now().Add(-time.Hour)
	saved["example.test"][0].Expires = &past
	restored = NewCookieJar()
	restored.Import(saved)
	restored.ImportV4(saved["example.test"])
	if restored.Count() != 0 {
		t.Fatal("import revived an expired Max-Age cookie")
	}
	// Old snapshots may contain deletion markers; do not revive those either.
	saved["example.test"][0].Expires = nil
	saved["example.test"][0].MaxAge = -1
	restored.Import(saved)
	restored.ImportV4(saved["example.test"])
	if restored.Count() != 0 {
		t.Fatal("import revived a deletion marker")
	}
}

func TestCookieMaxAgeExpiredCookiesAreFiltered(t *testing.T) {
	jar := NewCookieJar()
	// Fixed historical receipt time makes this expire without a sleep.
	jar.receive(&CookieData{Name: "token", Domain: "example.test", Path: "/", MaxAge: 10}, time.Unix(0, 0))
	if len(jar.Get("example.test", "/", false)) != 0 || len(jar.GetAll()) != 0 || len(jar.Export()) != 0 {
		t.Fatal("expired Max-Age cookie is visible in requests or saved state")
	}
	jar.ClearExpired()
	if jar.Count() != 0 {
		t.Fatal("ClearExpired retained an expired Max-Age cookie")
	}
}

// Copying cookies from one session to another, or back into the same one,
// must keep each cookie's deadline. GetCookies hands back the Max-Age next to
// the Expires it was resolved into, and resolving it again would push the
// deadline out by the full lifetime on every copy.
func TestCookieMaxAgeCopyKeepsDeadline(t *testing.T) {
	src := NewCookieJar()
	src.Set("www.example.test", &CookieData{Name: "sid", Value: "v", Path: "/", MaxAge: 3600}, true)
	want := *src.GetAll()[0].Expires

	time.Sleep(20 * time.Millisecond)
	dst := NewCookieJar()
	for _, c := range src.GetAll() {
		dst.SetSimple(c.Name, c.Value, c.Domain, c.Path, c.Secure, c.HttpOnly, c.SameSite, c.MaxAge, c.Expires)
	}
	got := dst.GetAll()
	if len(got) != 1 || got[0].Expires == nil || !got[0].Expires.Equal(want) {
		t.Fatalf("copied cookie expires = %v, want %v", got, want)
	}
}

// The 400-day cap applies however a cookie reaches the jar, not only to a
// Set-Cookie header: SetCookie and saved state from 1.7.3, which stored
// Max-Age as received, hand it a raw value. A value past 32 bits reached the
// bindings, which read max_age as a 32-bit int on Android.
func TestCookieMaxAgeCappedFromEverySource(t *testing.T) {
	const huge = 99999999999
	j := NewCookieJar()
	j.SetSimple("set", "1", "example.test", "/", true, false, "", huge, nil)
	j.Import(map[string][]CookieState{"example.test": {{Name: "imported", Value: "1", Domain: "example.test", Path: "/", MaxAge: huge}}})
	j.ImportV4([]CookieState{{Name: "imported4", Value: "1", Domain: "example.test", Path: "/", MaxAge: huge}})
	seen := 0
	for _, cs := range j.Export() {
		for _, c := range cs {
			seen++
			if c.MaxAge != maxCookieAgeSeconds {
				t.Errorf("%s: MaxAge = %d, want %d", c.Name, c.MaxAge, maxCookieAgeSeconds)
			}
		}
	}
	if seen != 3 {
		t.Fatalf("exported %d cookies, want 3", seen)
	}
	got := j.Get("example.test", "/", true)
	for _, c := range got {
		if c.Name == "set" && (c.Expires == nil || c.Expires.After(time.Now().Add(401*24*time.Hour))) {
			t.Errorf("SetCookie deadline %v is past 400 days", c.Expires)
		}
	}
}
