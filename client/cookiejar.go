package client

import (
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"
)

// CookieJar stores cookies and provides thread-safe access
type CookieJar struct {
	mu      sync.RWMutex
	cookies map[string][]*Cookie // domain -> cookies
}

// NewCookieJar creates a new empty cookie jar
func NewCookieJar() *CookieJar {
	return &CookieJar{
		cookies: make(map[string][]*Cookie),
	}
}

// SetCookies adds cookies from Set-Cookie headers to the jar
func (j *CookieJar) SetCookies(u *url.URL, cookies []*Cookie) {
	if len(cookies) == 0 {
		return
	}

	j.mu.Lock()
	defer j.mu.Unlock()

	for _, cookie := range cookies {
		if cookie == nil || cookie.Name == "" {
			continue
		}

		// Get the domain key
		domain := j.domainKey(cookie.Domain)

		// Remove existing cookie with same name, domain, and path
		existing := j.cookies[domain]
		filtered := make([]*Cookie, 0, len(existing))
		for _, c := range existing {
			if c.Name != cookie.Name || c.Path != cookie.Path {
				filtered = append(filtered, c)
			}
		}

		// Add new cookie if not expired
		if !cookie.IsExpired() {
			filtered = append(filtered, cookie)
		}

		j.cookies[domain] = filtered
	}
}

// SetCookiesFromHeaders parses Set-Cookie headers and adds them to the jar
func (j *CookieJar) SetCookiesFromHeaders(u *url.URL, headers map[string]string) {
	// Look for Set-Cookie header (case-insensitive)
	for key, value := range headers {
		if strings.ToLower(key) == "set-cookie" {
			// Single Set-Cookie header
			if cookie := ParseSetCookie(value, u); cookie != nil {
				j.SetCookies(u, []*Cookie{cookie})
			}
		}
	}
}

// SetCookiesFromHeaderList handles multiple Set-Cookie headers
func (j *CookieJar) SetCookiesFromHeaderList(u *url.URL, setCookieHeaders []string) {
	cookies := make([]*Cookie, 0, len(setCookieHeaders))
	for _, header := range setCookieHeaders {
		if cookie := ParseSetCookie(header, u); cookie != nil {
			cookies = append(cookies, cookie)
		}
	}
	j.SetCookies(u, cookies)
}

// Cookies returns the cookies to send for the given URL
func (j *CookieJar) Cookies(u *url.URL) []*Cookie {
	j.mu.RLock()
	defer j.mu.RUnlock()

	now := time.Now()
	var result []*Cookie

	// Check all domains that could match
	host := u.Host
	if idx := strings.LastIndex(host, ":"); idx != -1 {
		host = host[:idx]
	}
	host = strings.ToLower(host)

	// Get cookies from exact domain and parent domains
	domains := j.getMatchingDomains(host)

	for _, domain := range domains {
		cookies := j.cookies[domain]
		for _, cookie := range cookies {
			// Check expiration
			if cookie.MaxAge < 0 {
				continue
			}
			if !cookie.Expires.IsZero() && now.After(cookie.Expires) {
				continue
			}

			// Check if cookie matches URL
			if cookie.Matches(u) {
				result = append(result, cookie)
			}
		}
	}

	// Sort by path length (longer paths first) for proper precedence
	sort.Slice(result, func(i, j int) bool {
		return len(result[i].Path) > len(result[j].Path)
	})

	return result
}

// CookieHeader returns the Cookie header value for the given URL
func (j *CookieJar) CookieHeader(u *url.URL) string {
	cookies := j.Cookies(u)
	if len(cookies) == 0 {
		return ""
	}

	parts := make([]string, len(cookies))
	for i, c := range cookies {
		parts[i] = c.String()
	}

	return strings.Join(parts, "; ")
}

// Clear removes all cookies from the jar
func (j *CookieJar) Clear() {
	j.mu.Lock()
	defer j.mu.Unlock()
	j.cookies = make(map[string][]*Cookie)
}

// ClearDomain removes all cookies for a specific domain
func (j *CookieJar) ClearDomain(domain string) {
	j.mu.Lock()
	defer j.mu.Unlock()
	delete(j.cookies, j.domainKey(domain))
}

// ClearExpired removes all expired cookies
func (j *CookieJar) ClearExpired() {
	j.mu.Lock()
	defer j.mu.Unlock()

	now := time.Now()
	for domain, cookies := range j.cookies {
		filtered := make([]*Cookie, 0, len(cookies))
		for _, c := range cookies {
			if c.MaxAge >= 0 && (c.Expires.IsZero() || now.Before(c.Expires)) {
				filtered = append(filtered, c)
			}
		}
		if len(filtered) > 0 {
			j.cookies[domain] = filtered
		} else {
			delete(j.cookies, domain)
		}
	}
}

// Count returns the total number of cookies in the jar
func (j *CookieJar) Count() int {
	j.mu.RLock()
	defer j.mu.RUnlock()

	count := 0
	for _, cookies := range j.cookies {
		count += len(cookies)
	}
	return count
}

// AllCookies returns all cookies in the jar (for debugging)
func (j *CookieJar) AllCookies() map[string][]*Cookie {
	j.mu.RLock()
	defer j.mu.RUnlock()

	result := make(map[string][]*Cookie)
	for domain, cookies := range j.cookies {
		copied := make([]*Cookie, len(cookies))
		copy(copied, cookies)
		result[domain] = copied
	}
	return result
}

// domainKey normalizes domain for map key
func (j *CookieJar) domainKey(domain string) string {
	domain = strings.ToLower(domain)
	domain = strings.TrimPrefix(domain, ".")
	return domain
}

// getMatchingDomains returns all domain keys that could have matching cookies
func (j *CookieJar) getMatchingDomains(host string) []string {
	var domains []string

	// Exact domain
	if _, ok := j.cookies[host]; ok {
		domains = append(domains, host)
	}

	// Parent domains
	parts := strings.Split(host, ".")
	for i := 1; i < len(parts); i++ {
		parent := strings.Join(parts[i:], ".")
		if _, ok := j.cookies[parent]; ok {
			domains = append(domains, parent)
		}
	}

	return domains
}

// SetCookie adds a single cookie to the jar
func (j *CookieJar) SetCookie(u *url.URL, name, value string) {
	cookie := &Cookie{
		Name:   name,
		Value:  value,
		Domain: u.Host,
		Path:   "/",
	}
	j.SetCookies(u, []*Cookie{cookie})
}
