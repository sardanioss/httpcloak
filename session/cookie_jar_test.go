package session

import (
	"strings"
	"testing"
	"time"
)

func TestCookieJarReplacementPreservesHeaderOrder(t *testing.T) {
	jar := NewCookieJar()
	jar.Set("example.com", &CookieData{Name: "first", Value: "one", Path: "/"}, true)
	// Windows clock resolution can make two immediate Set calls share CreatedAt.
	// Cookie order is only defined once those times differ.
	waitUntilClockAdvances(t, cookieCreatedAt(t, jar, "first"))
	jar.Set("example.com", &CookieData{Name: "second", Value: "two", Path: "/"}, true)

	before := cookieCreatedAt(t, jar, "first")
	jar.Set("example.com", &CookieData{Name: "first", Value: "updated", Path: "/"}, true)
	after := cookieCreatedAt(t, jar, "first")
	if !after.Equal(before) {
		t.Fatalf("replacement reset CreatedAt from %v to %v", before, after)
	}

	header := jar.BuildCookieHeader("example.com", "/", true)
	if !strings.HasPrefix(header, "first=updated; second=two") {
		t.Fatalf("replacement changed cookie order: %q", header)
	}
}

func cookieCreatedAt(t *testing.T, jar *CookieJar, name string) time.Time {
	t.Helper()
	for _, c := range jar.Get("example.com", "/", true) {
		if c.Name == name {
			return c.CreatedAt
		}
	}
	t.Fatalf("cookie %q not found", name)
	return time.Time{}
}

func waitUntilClockAdvances(t *testing.T, previous time.Time) {
	t.Helper()
	deadline := time.Now().Add(200 * time.Millisecond)
	for !time.Now().After(previous) {
		if time.Now().After(deadline) {
			t.Fatal("clock did not advance")
		}
		time.Sleep(time.Millisecond)
	}
}
