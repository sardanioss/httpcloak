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
		{overflow, 0, false},
		{"-" + overflow, 0, false},
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
	jar.store(&CookieData{Name: "token", Value: "old", Domain: "example.test", Path: "/", MaxAge: 10, Expires: &past}, now)
	first := jar.cookies["example.test"][key]
	if first.Expires == nil || !first.Expires.Equal(now.Add(10*time.Second)) {
		t.Fatalf("Max-Age did not override expired Expires: %+v", first)
	}
	updatedAt := now.Add(5 * time.Second)
	jar.store(&CookieData{Name: "token", Value: "new", Domain: "example.test", Path: "/", MaxAge: 20, Expires: &future}, updatedAt)
	updated := jar.cookies["example.test"][key]
	if !updated.Expires.Equal(updatedAt.Add(20 * time.Second)) {
		t.Fatalf("renewal deadline = %s, want %s", updated.Expires, updatedAt.Add(20*time.Second))
	}
	if !updated.CreatedAt.Equal(now) {
		t.Fatalf("replacement changed header ordering timestamp: %s", updated.CreatedAt)
	}
	newAt := now.Add(time.Minute)
	jar.store(&CookieData{Name: "token", Domain: "example.test", Path: "/", MaxAge: 20}, newAt)
	if !jar.cookies["example.test"][key].CreatedAt.Equal(newAt) {
		t.Fatal("replacement of an expired cookie retained its old creation time")
	}
	jar.store(&CookieData{Name: "token", Domain: "example.test", Path: "/", Expires: &newAt}, newAt)
	if jar.Count() != 0 {
		t.Fatal("cookie at its expiration deadline was not deleted")
	}
}

func TestCookieMaxAgeLargeLifetimeDoesNotOverflow(t *testing.T) {
	jar := NewCookieJar()
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	jar.store(&CookieData{Name: "long", Domain: "example.test", Path: "/", MaxAge: int(^uint(0) >> 1)}, now)
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
			past := time.Now().Add(-time.Hour)
			before := time.Now()
			set(&CookieData{Name: "token", Value: "root", Domain: ".example.test", Path: "/", MaxAge: 60, Expires: &past})
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
		{"Max-Age=" + overflow, 0, false},
		{"Max-Age=garbage; Expires=Thu, 01 Jan 1970 00:00:00 GMT", 0, true},
		{"Max-Age=garbage; Expires=Fri, 31 Dec 9999 23:59:59 GMT", 0, false},
		{"Max-Age=60; Max-Age=bad", 60, false},
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
	jar.store(&CookieData{Name: "token", Domain: "example.test", Path: "/", MaxAge: 10}, time.Unix(0, 0))
	if len(jar.Get("example.test", "/", false)) != 0 || len(jar.GetAll()) != 0 || len(jar.Export()) != 0 {
		t.Fatal("expired Max-Age cookie is visible in requests or saved state")
	}
	jar.ClearExpired()
	if jar.Count() != 0 {
		t.Fatal("ClearExpired retained an expired Max-Age cookie")
	}
}
