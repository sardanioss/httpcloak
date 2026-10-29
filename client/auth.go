package client

import (
	"context"
	"crypto/md5"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	http "github.com/sardanioss/http"
	"strconv"
	"strings"
)

// Auth interface for authentication methods
type Auth interface {
	// Apply applies authentication to the request
	Apply(req *http.Request) error
	// HandleChallenge handles authentication challenge from 401 response
	HandleChallenge(resp *http.Response, req *http.Request) (bool, error)
}

// maxAuthResends bounds how many times doOnce resends one hop's request
// because its Auth asked to answer a 401. Chrome counts a request's restarts
// and refuses the one that would be the 32nd (kMaxRestarts), so the request
// goes out 32 times at most, and then fails. A server that answers every
// answer with stale=true, or an Auth whose HandleChallenge always says retry,
// would otherwise get the request again and again until the context ran out.
const maxAuthResends = 31

// authResendsKey is the context key under which doOnce carries the count of
// resends so far. The count belongs to one hop, the request at that position
// in its redirect chain. Chrome follows each hop with a new transaction, and
// so a new count.
type authResendsKey struct{}

type authResends struct {
	hop int // len(redirectHistory) for the hop being resent
	n   int
}

// authResendsSoFar returns how many times doOnce has resent the hop's request.
func authResendsSoFar(ctx context.Context, hop int) int {
	if r, ok := ctx.Value(authResendsKey{}).(authResends); ok && r.hop == hop {
		return r.n
	}
	return 0
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
	stale, err := a.parseChallenge(wwwAuth)
	if err != nil {
		return false, err
	}

	// A request that carried an answer and still got a challenge was refused.
	// Chrome, Firefox and curl answer again only when the new challenge says
	// stale=true: the nonce had expired, but the credentials were right. Any
	// other challenge to an answer made for this request means the credentials
	// were wrong, and the browsers drop them and ask the user. Here the 401
	// goes back to the caller, and the challenge is forgotten so that later
	// requests stop answering it.
	//
	// An answer sent up front, to the challenge an earlier request got, is
	// answered once more instead: the server may have moved to a new nonce
	// without saying stale=true. That is what Chrome sends when the user gives
	// the same credentials again. Such an answer reuses its nonce, so its
	// nonce count is above 00000001, where the first answer to a challenge is
	// at 00000001; if that one is refused in turn, the 401 goes back.
	if req != nil && !stale {
		if sent := req.Header.Get("Authorization"); strings.HasPrefix(strings.ToLower(sent), "digest ") {
			if nc, ok := sentNonceCount(sent); !ok || nc <= 1 {
				a.nonce = ""
				return false, nil
			}
		}
	}

	return true, nil
}

// sentNonceCount returns the nonce count of the Digest answer in an
// Authorization header. An answer carries one only when its challenge named a
// qop; without one, ok is false.
func sentNonceCount(authorization string) (nc uint64, ok bool) {
	for _, part := range strings.Split(authorization[len("digest "):], ",") {
		key, value, found := strings.Cut(strings.TrimSpace(part), "=")
		if found && strings.EqualFold(strings.TrimSpace(key), "nc") {
			n, err := strconv.ParseUint(strings.Trim(strings.TrimSpace(value), `"`), 16, 64)
			return n, err == nil
		}
	}
	return 0, false
}

// parseChallenge parses the WWW-Authenticate header, and reports whether it
// says stale=true. A challenge replaces the one before it, so nothing of the
// earlier one goes into the next answer, and the nonce count starts again:
// it counts the requests sent with one nonce (RFC 7616), so the first answer
// to a challenge carries 00000001, as Chrome, Firefox and curl send it. A
// challenge that fails to parse leaves the earlier one in place.
func (a *DigestAuth) parseChallenge(wwwAuth string) (bool, error) {
	// Remove "Digest " prefix
	params := strings.TrimPrefix(wwwAuth, "Digest ")
	params = strings.TrimPrefix(params, "digest ")

	var realm, nonce, qop, opaque, algorithm string
	stale := false

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
			realm = value
		case "nonce":
			nonce = value
		case "qop":
			qop = value
		case "opaque":
			opaque = value
		case "algorithm":
			algorithm = value
		case "stale":
			stale = strings.EqualFold(value, "true")
		}
	}

	if nonce == "" {
		return false, fmt.Errorf("digest auth: missing nonce in challenge")
	}

	a.realm, a.nonce, a.qop, a.opaque, a.algorithm = realm, nonce, qop, opaque, algorithm
	a.nc = 0
	return stale, nil
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
