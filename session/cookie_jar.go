package session

import (
	"net"
	"sort"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/publicsuffix"
)

// CookieJar manages cookies with proper domain and path scoping
// Cookies are stored by domain, then by (path, name) tuple
type CookieJar struct {
	mu sync.RWMutex
	// Primary key: domain (normalized)
	// Secondary key: path + "\x00" + name
	cookies map[string]map[string]*CookieData
}

// CookieData extends CookieState with creation time for sorting
type CookieData struct {
	Name      string
	Value     string
	Domain    string // Normalized domain (with leading dot for domain cookies)
	HostOnly  bool   // True if cookie should only be sent to exact host
	Path      string
	Expires   *time.Time
	MaxAge    int
	Secure    bool
	HttpOnly  bool
	SameSite  string
	CreatedAt time.Time
}

// NewCookieJar creates a new empty cookie jar
func NewCookieJar() *CookieJar {
	return &CookieJar{
		cookies: make(map[string]map[string]*CookieData),
	}
}

// cookieKey generates a unique key for a cookie within a domain
func cookieKey(path, name string) string {
	return path + "\x00" + name
}

// cookieAgeLimit is the longest a cookie is kept from when it is set: RFC
// 6265bis caps a cookie's expiry at 400 days, whether it comes from Max-Age or
// Expires, as Chrome does.
const cookieAgeLimit = 400 * 24 * time.Hour

// expiry is when a cookie set at now expires, nil for a session cookie. Max-Age
// (in seconds, when the cookie has a valid one) decides over Expires (RFC
// 6265 5.3 step 3); either is capped at cookieAgeLimit, and a Max-Age of zero
// or less has the cookie expired already (5.2.2).
func expiry(now time.Time, maxAge *int64, expires *time.Time) *time.Time {
	var at time.Time
	switch {
	case maxAge != nil && *maxAge <= 0:
		at = time.Unix(0, 0)
	case maxAge != nil && *maxAge < int64(cookieAgeLimit/time.Second):
		at = now.Add(time.Duration(*maxAge) * time.Second)
	case maxAge != nil:
		at = now.Add(cookieAgeLimit)
	case expires != nil && expires.After(now.Add(cookieAgeLimit)):
		at = now.Add(cookieAgeLimit)
	case expires != nil:
		at = *expires
	default:
		return nil
	}
	return &at
}

// put stores c under domain, replacing the cookie with the same name, domain
// and path and keeping its creation time, which orders the Cookie header (RFC
// 6265 5.3 step 11). An already expired c only removes that cookie. Caller
// holds j.mu.
func (j *CookieJar) put(domain string, c *CookieData, now time.Time) {
	key := cookieKey(c.Path, c.Name)
	old := j.cookies[domain][key]
	if c.Expires != nil && !c.Expires.After(now) {
		if old != nil {
			delete(j.cookies[domain], key)
			if len(j.cookies[domain]) == 0 {
				delete(j.cookies, domain)
			}
		}
		return
	}
	c.CreatedAt = now
	if old != nil {
		c.CreatedAt = old.CreatedAt
	}
	if j.cookies[domain] == nil {
		j.cookies[domain] = make(map[string]*CookieData)
	}
	j.cookies[domain][key] = c
}

// Set takes a cookie from a Set-Cookie header of a response to requestHost
// and requestPath, over HTTPS when requestSecure, as RFC 6265 section 5.3 has
// a browser store it. The cookie's Expires is the expiry its Max-Age and
// Expires gave (see expiry), and a cookie already expired removes the one it
// would replace. A Domain makes it a domain cookie when the host is under it;
// one naming another site, or a public suffix other than the host itself, is
// refused, so no site can set a cookie for every site under a suffix (com.au,
// myshopify.com). Without a Path, or with one that does not start with "/", its
// path is the request path's directory. A Secure cookie from plain HTTP is
// refused.
func (j *CookieJar) Set(requestHost, requestPath string, cookie *CookieData, requestSecure bool) {
	j.mu.Lock()
	defer j.mu.Unlock()

	// Normalize the request host (lowercase, no port)
	requestHost = strings.ToLower(requestHost)
	if idx := strings.LastIndex(requestHost, ":"); idx != -1 {
		// Check if it's not an IPv6 address
		if !strings.Contains(requestHost, "]") || idx > strings.Index(requestHost, "]") {
			requestHost = requestHost[:idx]
		}
	}

	// A Domain attribute loses its leading dot (5.2.3). The jar keeps a domain
	// cookie under the domain with a dot in front, and a host-only one under
	// the host.
	domain := requestHost
	hostOnly := true
	if attribute := strings.TrimPrefix(strings.ToLower(cookie.Domain), "."); attribute != "" {
		// A public suffix is no domain to share cookies across (5.3 step 5),
		// unless it is the host itself, which then gets a host-only cookie.
		suffix, _ := publicsuffix.PublicSuffix(attribute)
		switch {
		case suffix == attribute && attribute != requestHost:
			return
		case suffix == attribute:
		case !isDomainMatch(requestHost, attribute):
			return // a domain the host is not under
		default:
			domain = "." + attribute
			hostOnly = false
		}
	}

	// Secure cookies can only be set over HTTPS
	if cookie.Secure && !requestSecure {
		return // Reject
	}

	path := cookie.Path
	if path == "" || path[0] != '/' {
		path = defaultPath(requestPath)
	}

	j.put(domain, &CookieData{
		Name:     cookie.Name,
		Value:    cookie.Value,
		Domain:   domain,
		HostOnly: hostOnly,
		Path:     path,
		Expires:  cookie.Expires,
		Secure:   cookie.Secure,
		HttpOnly: cookie.HttpOnly,
		SameSite: cookie.SameSite,
	}, time.Now())
}

// defaultPath is a cookie's path when its Set-Cookie gives none: the request
// path's directory (RFC 6265 5.1.4), "/" for a path with no directory.
func defaultPath(requestPath string) string {
	if requestPath == "" || requestPath[0] != '/' {
		return "/"
	}
	i := strings.LastIndexByte(requestPath, '/')
	if i == 0 {
		return "/"
	}
	return requestPath[:i]
}

// Get returns all cookies that should be sent for a request
// requestHost is the target host
// requestPath is the request path
// requestSecure is true if the request is over HTTPS
func (j *CookieJar) Get(requestHost, requestPath string, requestSecure bool) []*CookieData {
	j.mu.RLock()
	defer j.mu.RUnlock()

	// Normalize
	requestHost = strings.ToLower(requestHost)
	if idx := strings.LastIndex(requestHost, ":"); idx != -1 {
		if !strings.Contains(requestHost, "]") || idx > strings.Index(requestHost, "]") {
			requestHost = requestHost[:idx]
		}
	}

	if requestPath == "" {
		requestPath = "/"
	}

	now := time.Now()
	var matches []*CookieData

	// Check all domains that might match
	for domain, domainCookies := range j.cookies {
		// Check if this domain matches the request host
		if !j.domainMatchesHost(domain, requestHost) {
			continue
		}

		for _, cookie := range domainCookies {
			// Host-only check
			if cookie.HostOnly && domain != requestHost {
				continue
			}

			// Path match
			if !isPathMatch(requestPath, cookie.Path) {
				continue
			}

			// Secure check
			if cookie.Secure && !requestSecure {
				continue
			}

			// Expiration check
			if cookie.Expires != nil && cookie.Expires.Before(now) {
				continue
			}

			matches = append(matches, cookie)
		}
	}

	// Sort: longer path first, then older creation time first
	sort.Slice(matches, func(i, k int) bool {
		if len(matches[i].Path) != len(matches[k].Path) {
			return len(matches[i].Path) > len(matches[k].Path)
		}
		return matches[i].CreatedAt.Before(matches[k].CreatedAt)
	})

	return matches
}

// GetAll returns all non-expired cookies with full metadata
func (j *CookieJar) GetAll() []CookieState {
	j.mu.RLock()
	defer j.mu.RUnlock()

	now := time.Now()
	var result []CookieState

	for _, domainCookies := range j.cookies {
		for _, c := range domainCookies {
			// Skip expired cookies
			if c.Expires != nil && c.Expires.Before(now) {
				continue
			}
			result = append(result, c.state())
		}
	}

	// Sort by domain, then path, then name for deterministic output
	sort.Slice(result, func(i, k int) bool {
		if result[i].Domain != result[k].Domain {
			return result[i].Domain < result[k].Domain
		}
		if result[i].Path != result[k].Path {
			return result[i].Path < result[k].Path
		}
		return result[i].Name < result[k].Name
	})

	return result
}

// SetSimple sets a cookie with full metadata.
// If domain is empty, creates a global cookie (sent to all domains).
// If domain is provided, normalizes it and stores as a domain-scoped cookie.
//
// maxAge is a Max-Age in seconds, as net/http's Cookie.MaxAge has it: above
// zero, the cookie expires that long from now, whatever expires says; below
// zero, it is expired now; zero means none. Either way the expiry is capped
// at 400 days from now, and a cookie already expired removes the one with the
// same name, domain and path instead of being stored. The jar keeps the
// expiry, not the Max-Age, which reads back as zero.
func (j *CookieJar) SetSimple(name, value, domain, path string, secure, httpOnly bool, sameSite string, maxAge int, expires *time.Time) {
	j.mu.Lock()
	defer j.mu.Unlock()

	hostOnly := false
	if domain == "" {
		// Global cookie — matches all domains
	} else {
		// Normalize domain
		domain = strings.ToLower(domain)
		if !strings.HasPrefix(domain, ".") {
			// Bare domain → host-only cookie
			hostOnly = true
		}
	}

	if path == "" {
		path = "/"
	}

	var age *int64
	if maxAge != 0 {
		seconds := int64(maxAge)
		age = &seconds
	}
	now := time.Now()
	j.put(domain, &CookieData{
		Name:     name,
		Value:    value,
		Domain:   domain,
		HostOnly: hostOnly,
		Path:     path,
		Expires:  expiry(now, age, expires),
		Secure:   secure,
		HttpOnly: httpOnly,
		SameSite: sameSite,
	}, now)
}

// Delete removes cookies by name. If domain is empty, removes ALL cookies with
// that name across all domains. If domain is provided, removes only from that domain.
func (j *CookieJar) Delete(name, domain string) {
	j.mu.Lock()
	defer j.mu.Unlock()

	if domain == "" {
		// Delete from all domains
		for d, domainCookies := range j.cookies {
			for key, cookie := range domainCookies {
				if cookie.Name == name {
					delete(domainCookies, key)
				}
			}
			if len(domainCookies) == 0 {
				delete(j.cookies, d)
			}
		}
	} else {
		// Normalize and delete from specific domain
		domain = strings.ToLower(domain)
		domainCookies, ok := j.cookies[domain]
		if !ok {
			return
		}
		for key, cookie := range domainCookies {
			if cookie.Name == name {
				delete(domainCookies, key)
			}
		}
		if len(domainCookies) == 0 {
			delete(j.cookies, domain)
		}
	}
}

// Clear removes all cookies
func (j *CookieJar) Clear() {
	j.mu.Lock()
	defer j.mu.Unlock()
	j.cookies = make(map[string]map[string]*CookieData)
}

// ClearExpired removes all expired cookies
func (j *CookieJar) ClearExpired() {
	j.mu.Lock()
	defer j.mu.Unlock()

	now := time.Now()
	for domain, domainCookies := range j.cookies {
		for key, cookie := range domainCookies {
			if cookie.Expires != nil && cookie.Expires.Before(now) {
				delete(domainCookies, key)
			}
		}
		if len(domainCookies) == 0 {
			delete(j.cookies, domain)
		}
	}
}

// Count returns the total number of cookies across all domains
func (j *CookieJar) Count() int {
	j.mu.RLock()
	defer j.mu.RUnlock()

	count := 0
	for _, domainCookies := range j.cookies {
		count += len(domainCookies)
	}
	return count
}

// Export exports all cookies grouped by domain for serialization
func (j *CookieJar) Export() map[string][]CookieState {
	j.mu.RLock()
	defer j.mu.RUnlock()

	now := time.Now()
	result := make(map[string][]CookieState)

	for domain, domainCookies := range j.cookies {
		var cookies []CookieState
		for _, c := range domainCookies {
			// Skip expired cookies
			if c.Expires != nil && c.Expires.Before(now) {
				continue
			}
			cookies = append(cookies, c.state())
		}
		if len(cookies) > 0 {
			result[domain] = cookies
		}
	}

	return result
}

// Import imports cookies from the v5 format (domain-keyed)
func (j *CookieJar) Import(cookies map[string][]CookieState) {
	j.mu.Lock()
	defer j.mu.Unlock()

	now := time.Now()

	for domain, domainCookies := range cookies {
		if j.cookies[domain] == nil {
			j.cookies[domain] = make(map[string]*CookieData)
		}

		for _, c := range domainCookies {
			// Skip expired cookies
			if c.Expires != nil && c.Expires.Before(now) {
				continue
			}

			path := c.Path
			if path == "" {
				path = "/"
			}

			// Determine if host-only based on domain format
			hostOnly := !strings.HasPrefix(c.Domain, ".")

			// Use saved CreatedAt if available, otherwise use current time
			createdAt := now
			if c.CreatedAt != nil {
				createdAt = *c.CreatedAt
			}

			j.cookies[domain][cookieKey(path, c.Name)] = &CookieData{
				Name:      c.Name,
				Value:     c.Value,
				Domain:    c.Domain,
				HostOnly:  hostOnly,
				Path:      path,
				Expires:   c.Expires,
				MaxAge:    c.MaxAge,
				Secure:    c.Secure,
				HttpOnly:  c.HttpOnly,
				SameSite:  c.SameSite,
				CreatedAt: createdAt,
			}
		}
	}
}

// ImportV4 imports cookies from the v4 format (flat list)
func (j *CookieJar) ImportV4(cookies []CookieState) {
	j.mu.Lock()
	defer j.mu.Unlock()

	now := time.Now()

	for _, c := range cookies {
		// Skip expired cookies
		if c.Expires != nil && c.Expires.Before(now) {
			continue
		}

		// Determine domain key
		domain := c.Domain
		hostOnly := false

		if domain == "" {
			// No domain in v4 means it was stored by name only
			// We'll store it as a "global" cookie
			domain = ""
		} else {
			// Normalize domain
			domain = strings.ToLower(domain)
			if !strings.HasPrefix(domain, ".") {
				hostOnly = true
			}
		}

		path := c.Path
		if path == "" {
			path = "/"
		}

		if j.cookies[domain] == nil {
			j.cookies[domain] = make(map[string]*CookieData)
		}

		j.cookies[domain][cookieKey(path, c.Name)] = &CookieData{
			Name:      c.Name,
			Value:     c.Value,
			Domain:    domain,
			HostOnly:  hostOnly,
			Path:      path,
			Expires:   c.Expires,
			MaxAge:    c.MaxAge,
			Secure:    c.Secure,
			HttpOnly:  c.HttpOnly,
			SameSite:  c.SameSite,
			CreatedAt: now,
		}
	}
}

// domainMatchesHost checks if a cookie domain matches a request host
func (j *CookieJar) domainMatchesHost(cookieDomain, requestHost string) bool {
	// Empty domain (global cookies) matches everything
	if cookieDomain == "" {
		return true
	}

	// Exact match (for host-only cookies stored without dot)
	if cookieDomain == requestHost {
		return true
	}

	// Domain cookie (with leading dot)
	if strings.HasPrefix(cookieDomain, ".") {
		domainWithoutDot := cookieDomain[1:]
		// Matches the domain itself
		if requestHost == domainWithoutDot {
			return true
		}
		// Matches subdomains
		if strings.HasSuffix(requestHost, cookieDomain) {
			return true
		}
	}

	return false
}

// isDomainMatch reports whether host domain-matches domain (RFC 6265 5.1.3):
// it is domain, or a host name (not an IP address) under it.
func isDomainMatch(host, domain string) bool {
	return host == domain || (strings.HasSuffix(host, "."+domain) && net.ParseIP(host) == nil)
}

// isPathMatch checks if request path matches cookie path
func isPathMatch(requestPath, cookiePath string) bool {
	if requestPath == cookiePath {
		return true
	}

	// Cookie path must be a prefix of request path
	if strings.HasPrefix(requestPath, cookiePath) {
		// Exact prefix match with /
		if strings.HasSuffix(cookiePath, "/") {
			return true
		}
		// Or the next char in request path is /
		if len(requestPath) > len(cookiePath) && requestPath[len(cookiePath)] == '/' {
			return true
		}
	}

	return false
}

// state is the cookie as the jar reports it.
func (c *CookieData) state() CookieState {
	createdAt := c.CreatedAt
	return CookieState{
		Name:      c.Name,
		Value:     c.Value,
		Domain:    c.Domain,
		Path:      c.Path,
		Expires:   c.Expires,
		MaxAge:    c.MaxAge,
		Secure:    c.Secure,
		HttpOnly:  c.HttpOnly,
		SameSite:  c.SameSite,
		CreatedAt: &createdAt,
	}
}

// For returns the cookies a request to requestHost and requestPath, over
// HTTPS when requestSecure, carries, in the order its Cookie header lists them.
func (j *CookieJar) For(requestHost, requestPath string, requestSecure bool) []CookieState {
	cookies := j.Get(requestHost, requestPath, requestSecure)
	states := make([]CookieState, len(cookies))
	for i, c := range cookies {
		states[i] = c.state()
	}
	return states
}

// BuildCookieHeader builds the Cookie header value for a request
func (j *CookieJar) BuildCookieHeader(requestHost, requestPath string, requestSecure bool) string {
	cookies := j.Get(requestHost, requestPath, requestSecure)
	if len(cookies) == 0 {
		return ""
	}

	var parts []string
	for _, c := range cookies {
		parts = append(parts, c.Name+"="+c.Value)
	}

	return strings.Join(parts, "; ")
}
