package session

import (
	"sort"
	"strings"
	"sync"
	"time"
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
	Domain    string     // Normalized domain (with leading dot for domain cookies)
	HostOnly  bool       // True if cookie should only be sent to exact host
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

// Set adds or updates a cookie from a Set-Cookie header
// requestHost is the host that sent the Set-Cookie header
// requestSecure is true if the request was over HTTPS
func (j *CookieJar) Set(requestHost string, cookie *CookieData, requestSecure bool) {
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

	// Determine effective domain
	var domain string
	var hostOnly bool

	if cookie.Domain == "" {
		// No Domain attribute: host-only cookie
		domain = requestHost
		hostOnly = true
	} else {
		// Domain attribute specified
		domain = strings.ToLower(cookie.Domain)

		// Remove leading dot for comparison (we'll add it back for storage)
		domainWithoutDot := strings.TrimPrefix(domain, ".")

		// Validate: request host must be the domain or a subdomain of it
		if !isDomainMatch(requestHost, domainWithoutDot) {
			return // Reject: can't set cookie for unrelated domain
		}

		// Store with leading dot to indicate it's a domain cookie
		domain = "." + domainWithoutDot
		hostOnly = false
	}

	// Secure cookies can only be set over HTTPS
	if cookie.Secure && !requestSecure {
		return // Reject
	}

	// Default path if not specified
	path := cookie.Path
	if path == "" || path[0] != '/' {
		path = "/"
	}

	// Create the stored cookie
	stored := &CookieData{
		Name:      cookie.Name,
		Value:     cookie.Value,
		Domain:    domain,
		HostOnly:  hostOnly,
		Path:      path,
		Expires:   cookie.Expires,
		MaxAge:    cookie.MaxAge,
		Secure:    cookie.Secure,
		HttpOnly:  cookie.HttpOnly,
		SameSite:  cookie.SameSite,
		CreatedAt: time.Now(),
	}

	// Store the cookie
	if j.cookies[domain] == nil {
		j.cookies[domain] = make(map[string]*CookieData)
	}
	j.cookies[domain][cookieKey(path, cookie.Name)] = stored
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

			createdAt := c.CreatedAt
			result = append(result, CookieState{
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
			})
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

	if j.cookies[domain] == nil {
		j.cookies[domain] = make(map[string]*CookieData)
	}
	j.cookies[domain][cookieKey(path, name)] = &CookieData{
		Name:      name,
		Value:     value,
		Domain:    domain,
		HostOnly:  hostOnly,
		Path:      path,
		Expires:   expires,
		MaxAge:    maxAge,
		Secure:    secure,
		HttpOnly:  httpOnly,
		SameSite:  sameSite,
		CreatedAt: time.Now(),
	}
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

			createdAt := c.CreatedAt
			cookies = append(cookies, CookieState{
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
			})
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

// isDomainMatch checks if host is equal to or a subdomain of domain
func isDomainMatch(host, domain string) bool {
	if host == domain {
		return true
	}
	// host must be a subdomain of domain
	if strings.HasSuffix(host, "."+domain) {
		return true
	}
	return false
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
