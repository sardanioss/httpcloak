package client

import (
	"crypto/md5"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net/http"
	"strings"
)

// Auth interface for authentication methods
type Auth interface {
	// Apply applies authentication to the request
	Apply(req *http.Request) error
	// HandleChallenge handles authentication challenge from 401 response
	HandleChallenge(resp *http.Response, req *http.Request) (bool, error)
}

// BasicAuth implements HTTP Basic authentication
type BasicAuth struct {
	Username string
	Password string
}

// NewBasicAuth creates a new BasicAuth
func NewBasicAuth(username, password string) *BasicAuth {
	return &BasicAuth{
		Username: username,
		Password: password,
	}
}

// Apply applies Basic auth header to request
func (a *BasicAuth) Apply(req *http.Request) error {
	auth := a.Username + ":" + a.Password
	encoded := base64.StdEncoding.EncodeToString([]byte(auth))
	req.Header.Set("Authorization", "Basic "+encoded)
	return nil
}

// HandleChallenge handles 401 response - Basic auth doesn't retry
func (a *BasicAuth) HandleChallenge(resp *http.Response, req *http.Request) (bool, error) {
	// Basic auth doesn't have a challenge-response mechanism
	return false, nil
}

// DigestAuth implements HTTP Digest authentication
type DigestAuth struct {
	Username string
	Password string

	// Stored challenge parameters
	realm     string
	nonce     string
	qop       string
	opaque    string
	algorithm string
	nc        int
}

// NewDigestAuth creates a new DigestAuth
func NewDigestAuth(username, password string) *DigestAuth {
	return &DigestAuth{
		Username: username,
		Password: password,
		nc:       0,
	}
}

// Apply applies Digest auth header to request (if challenge has been received)
func (a *DigestAuth) Apply(req *http.Request) error {
	if a.nonce == "" {
		// No challenge received yet, don't add auth header
		return nil
	}
	return a.applyDigestHeader(req)
}

// HandleChallenge parses WWW-Authenticate header and prepares auth
func (a *DigestAuth) HandleChallenge(resp *http.Response, req *http.Request) (bool, error) {
	if resp.StatusCode != http.StatusUnauthorized {
		return false, nil
	}

	wwwAuth := resp.Header.Get("WWW-Authenticate")
	if wwwAuth == "" || !strings.HasPrefix(strings.ToLower(wwwAuth), "digest ") {
		return false, nil
	}

	// Parse challenge
	if err := a.parseChallenge(wwwAuth); err != nil {
		return false, err
	}

	return true, nil
}

// parseChallenge parses the WWW-Authenticate header
func (a *DigestAuth) parseChallenge(wwwAuth string) error {
	// Remove "Digest " prefix
	params := strings.TrimPrefix(wwwAuth, "Digest ")
	params = strings.TrimPrefix(params, "digest ")

	// Parse parameters
	for _, part := range strings.Split(params, ",") {
		part = strings.TrimSpace(part)
		idx := strings.Index(part, "=")
		if idx < 0 {
			continue
		}

		key := strings.ToLower(strings.TrimSpace(part[:idx]))
		value := strings.TrimSpace(part[idx+1:])
		value = strings.Trim(value, `"`)

		switch key {
		case "realm":
			a.realm = value
		case "nonce":
			a.nonce = value
		case "qop":
			a.qop = value
		case "opaque":
			a.opaque = value
		case "algorithm":
			a.algorithm = value
		}
	}

	if a.nonce == "" {
		return fmt.Errorf("digest auth: missing nonce in challenge")
	}

	return nil
}

// applyDigestHeader generates and applies the Digest Authorization header
func (a *DigestAuth) applyDigestHeader(req *http.Request) error {
	a.nc++
	nc := fmt.Sprintf("%08x", a.nc)

	// Generate cnonce
	cnonce := generateCnonce()

	// Calculate response hash
	uri := req.URL.RequestURI()
	method := req.Method
	if method == "" {
		method = "GET"
	}

	// HA1 = MD5(username:realm:password)
	ha1 := md5Hash(fmt.Sprintf("%s:%s:%s", a.Username, a.realm, a.Password))

	// HA2 = MD5(method:uri)
	ha2 := md5Hash(fmt.Sprintf("%s:%s", method, uri))

	// Response
	var response string
	if a.qop == "auth" || a.qop == "auth-int" {
		// response = MD5(HA1:nonce:nc:cnonce:qop:HA2)
		response = md5Hash(fmt.Sprintf("%s:%s:%s:%s:%s:%s", ha1, a.nonce, nc, cnonce, a.qop, ha2))
	} else {
		// response = MD5(HA1:nonce:HA2)
		response = md5Hash(fmt.Sprintf("%s:%s:%s", ha1, a.nonce, ha2))
	}

	// Build Authorization header
	auth := fmt.Sprintf(`Digest username="%s", realm="%s", nonce="%s", uri="%s", response="%s"`,
		a.Username, a.realm, a.nonce, uri, response)

	if a.qop != "" {
		auth += fmt.Sprintf(`, qop=%s, nc=%s, cnonce="%s"`, a.qop, nc, cnonce)
	}

	if a.opaque != "" {
		auth += fmt.Sprintf(`, opaque="%s"`, a.opaque)
	}

	if a.algorithm != "" {
		auth += fmt.Sprintf(`, algorithm=%s`, a.algorithm)
	}

	req.Header.Set("Authorization", auth)
	return nil
}

// md5Hash returns MD5 hash as hex string
func md5Hash(s string) string {
	hash := md5.Sum([]byte(s))
	return hex.EncodeToString(hash[:])
}

// generateCnonce generates a random client nonce
func generateCnonce() string {
	b := make([]byte, 8)
	rand.Read(b)
	return hex.EncodeToString(b)
}

// BearerAuth implements Bearer token authentication
type BearerAuth struct {
	Token string
}

// NewBearerAuth creates a new BearerAuth
func NewBearerAuth(token string) *BearerAuth {
	return &BearerAuth{Token: token}
}

// Apply applies Bearer auth header to request
func (a *BearerAuth) Apply(req *http.Request) error {
	req.Header.Set("Authorization", "Bearer "+a.Token)
	return nil
}

// HandleChallenge handles 401 response - Bearer auth doesn't retry
func (a *BearerAuth) HandleChallenge(resp *http.Response, req *http.Request) (bool, error) {
	return false, nil
}
