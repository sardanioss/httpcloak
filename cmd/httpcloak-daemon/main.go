package main

import (
	"bufio"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/sardanioss/httpcloak/client"
	"github.com/sardanioss/httpcloak/fingerprint"
	"github.com/sardanioss/httpcloak/protocol"
)

const version = "1.0.0"

// Daemon manages IPC communication and sessions
type Daemon struct {
	sessions map[string]*Session
	mu       sync.RWMutex
	stdin    *bufio.Reader
	stdout   *json.Encoder
	outputMu sync.Mutex
}

// Session represents a persistent HTTP session with cookies
type Session struct {
	ID        string
	Client    *client.Client
	Config    *protocol.SessionConfig
	CreatedAt time.Time
}

// NewDaemon creates a new IPC daemon
func NewDaemon() *Daemon {
	return &Daemon{
		sessions: make(map[string]*Session),
		stdin:    bufio.NewReader(os.Stdin),
		stdout:   json.NewEncoder(os.Stdout),
	}
}

// Run starts the daemon main loop
func (d *Daemon) Run() error {
	for {
		line, err := d.stdin.ReadString('\n')
		if err != nil {
			return err // EOF or error
		}

		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		// Parse the message type first
		var msg struct {
			ID   string               `json:"id"`
			Type protocol.MessageType `json:"type"`
		}
		if err := json.Unmarshal([]byte(line), &msg); err != nil {
			d.sendError("", protocol.ErrCodeInvalidRequest, "Invalid JSON: "+err.Error())
			continue
		}

		// Route to handler based on type
		d.handleMessage(msg.Type, msg.ID, []byte(line))
	}
}

// handleMessage routes messages to appropriate handlers
func (d *Daemon) handleMessage(msgType protocol.MessageType, reqID string, data []byte) {
	switch msgType {
	case protocol.TypePing:
		d.handlePing(reqID)
	case protocol.TypeShutdown:
		os.Exit(0)
	case protocol.TypePresetList:
		d.handlePresetList(reqID)
	case protocol.TypeSessionCreate:
		d.handleSessionCreate(data)
	case protocol.TypeSessionClose:
		d.handleSessionClose(data)
	case protocol.TypeSessionList:
		d.handleSessionList(reqID)
	case protocol.TypeRequest:
		d.handleRequest(data)
	case protocol.TypeCookieGet:
		d.handleCookieGet(data)
	case protocol.TypeCookieSet:
		d.handleCookieSet(data)
	case protocol.TypeCookieClear:
		d.handleCookieClear(data)
	case protocol.TypeCookieAll:
		d.handleCookieAll(data)
	default:
		d.sendError(reqID, protocol.ErrCodeInvalidRequest, "Unknown message type: "+string(msgType))
	}
}

// handlePing responds to ping requests
func (d *Daemon) handlePing(reqID string) {
	d.send(&protocol.PingResponse{
		ID:      reqID,
		Type:    protocol.TypePong,
		Version: version,
	})
}

// handlePresetList returns available presets
func (d *Daemon) handlePresetList(reqID string) {
	d.send(&protocol.PresetListResponse{
		ID:      reqID,
		Type:    protocol.TypePresetList,
		Presets: fingerprint.Available(),
	})
}

// handleSessionCreate creates a new session
func (d *Daemon) handleSessionCreate(data []byte) {
	var req protocol.SessionCreateRequest
	if err := json.Unmarshal(data, &req); err != nil {
		d.sendError("", protocol.ErrCodeInvalidRequest, "Invalid session create request: "+err.Error())
		return
	}

	// Generate session ID
	sessionID := fmt.Sprintf("session-%d", time.Now().UnixNano())

	// Create client options
	var opts []client.Option

	config := req.Options
	if config == nil {
		config = &protocol.SessionConfig{}
	}

	// Preset (default to chrome-143)
	preset := config.Preset
	if preset == "" {
		preset = "chrome-143"
	}

	// Proxy
	if config.Proxy != "" {
		opts = append(opts, client.WithProxy(config.Proxy))
	}

	// Timeout
	if config.Timeout > 0 {
		opts = append(opts, client.WithTimeout(time.Duration(config.Timeout)*time.Millisecond))
	}

	// Redirect behavior
	if config.FollowRedirects || config.MaxRedirects > 0 {
		maxRedir := config.MaxRedirects
		if maxRedir == 0 {
			maxRedir = 10 // default
		}
		opts = append(opts, client.WithRedirects(config.FollowRedirects, maxRedir))
	}

	// Retry configuration
	if config.RetryEnabled {
		waitMin := time.Duration(config.RetryWaitMin) * time.Millisecond
		waitMax := time.Duration(config.RetryWaitMax) * time.Millisecond
		if waitMin == 0 {
			waitMin = 100 * time.Millisecond
		}
		if waitMax == 0 {
			waitMax = 2 * time.Second
		}
		opts = append(opts, client.WithRetryConfig(
			config.MaxRetries,
			waitMin,
			waitMax,
			config.RetryOnStatus,
		))
	}

	// TLS options
	if config.InsecureSkipVerify {
		opts = append(opts, client.WithInsecureSkipVerify())
	}

	// HTTP/3
	if config.DisableHTTP3 {
		opts = append(opts, client.WithDisableHTTP3())
	}

	// Create session with cookies enabled
	c := client.NewSession(preset, opts...)

	// Set authentication if provided
	if config.Auth != nil {
		switch config.Auth.Type {
		case "basic":
			c.SetBasicAuth(config.Auth.Username, config.Auth.Password)
		case "bearer":
			c.SetBearerAuth(config.Auth.Token)
		}
	}

	// Store session
	session := &Session{
		ID:        sessionID,
		Client:    c,
		Config:    config,
		CreatedAt: time.Now(),
	}

	d.mu.Lock()
	d.sessions[sessionID] = session
	d.mu.Unlock()

	d.send(&protocol.SessionCreateResponse{
		ID:      req.ID,
		Type:    protocol.TypeSessionCreate,
		Session: sessionID,
	})
}

// handleSessionClose closes a session
func (d *Daemon) handleSessionClose(data []byte) {
	var req protocol.SessionCloseRequest
	if err := json.Unmarshal(data, &req); err != nil {
		d.sendError("", protocol.ErrCodeInvalidRequest, "Invalid session close request: "+err.Error())
		return
	}

	d.mu.Lock()
	session, ok := d.sessions[req.Session]
	if ok {
		session.Client.Close()
		delete(d.sessions, req.Session)
	}
	d.mu.Unlock()

	if !ok {
		d.sendError(req.ID, protocol.ErrCodeInvalidSession, "Session not found: "+req.Session)
		return
	}

	d.send(&protocol.Response{
		ID:      req.ID,
		Type:    protocol.TypeSessionClose,
		Session: req.Session,
	})
}

// handleSessionList lists all active sessions
func (d *Daemon) handleSessionList(reqID string) {
	d.mu.RLock()
	sessions := make([]string, 0, len(d.sessions))
	for id := range d.sessions {
		sessions = append(sessions, id)
	}
	d.mu.RUnlock()

	d.send(&protocol.SessionListResponse{
		ID:       reqID,
		Type:     protocol.TypeSessionList,
		Sessions: sessions,
	})
}

// handleRequest executes an HTTP request
func (d *Daemon) handleRequest(data []byte) {
	var req protocol.Request
	if err := json.Unmarshal(data, &req); err != nil {
		d.sendError("", protocol.ErrCodeInvalidRequest, "Invalid request: "+err.Error())
		return
	}

	// Get or create client
	var c *client.Client
	if req.Session != "" {
		d.mu.RLock()
		session, ok := d.sessions[req.Session]
		d.mu.RUnlock()
		if !ok {
			d.sendError(req.ID, protocol.ErrCodeInvalidSession, "Session not found: "+req.Session)
			return
		}
		c = session.Client
	} else {
		// One-shot request without session
		preset := "chrome-143"
		if req.Options != nil && req.Options.ForceProtocol != "" {
			// Could use different preset based on protocol preference
		}
		c = client.NewClient(preset)
		defer c.Close()
	}

	// Build request
	method := req.Method
	if method == "" {
		method = "GET"
	}

	// Parse body
	var body []byte
	if req.Body != "" {
		if req.Options != nil && req.Options.BodyEncoding == "base64" {
			var err error
			body, err = base64.StdEncoding.DecodeString(req.Body)
			if err != nil {
				d.sendError(req.ID, protocol.ErrCodeInvalidRequest, "Invalid base64 body: "+err.Error())
				return
			}
		} else {
			body = []byte(req.Body)
		}
	}

	// Build client request
	clientReq := &client.Request{
		Method:  method,
		URL:     req.URL,
		Headers: req.Headers,
		Body:    body,
	}

	// Apply options
	if req.Options != nil {
		opts := req.Options

		if opts.Timeout > 0 {
			clientReq.Timeout = time.Duration(opts.Timeout) * time.Millisecond
		}

		if opts.FollowRedirects != nil {
			clientReq.FollowRedirects = opts.FollowRedirects
		}
		if opts.MaxRedirects > 0 {
			clientReq.MaxRedirects = opts.MaxRedirects
		}

		if opts.ForceProtocol != "" {
			switch opts.ForceProtocol {
			case "h2":
				clientReq.ForceProtocol = client.ProtocolHTTP2
			case "h3":
				clientReq.ForceProtocol = client.ProtocolHTTP3
			}
		}

		if opts.FetchMode != "" {
			switch opts.FetchMode {
			case "navigate":
				clientReq.FetchMode = client.FetchModeNavigate
			case "cors":
				clientReq.FetchMode = client.FetchModeCORS
			}
		}

		if opts.FetchSite != "" {
			switch opts.FetchSite {
			case "none":
				clientReq.FetchSite = client.FetchSiteNone
			case "same-origin":
				clientReq.FetchSite = client.FetchSiteSameOrigin
			case "same-site":
				clientReq.FetchSite = client.FetchSiteSameSite
			case "cross-site":
				clientReq.FetchSite = client.FetchSiteCrossSite
			}
		}

		if opts.Referer != "" {
			clientReq.Referer = opts.Referer
		}

		if opts.UserAgent != "" {
			clientReq.UserAgent = opts.UserAgent
		}

		if opts.Params != nil {
			clientReq.Params = opts.Params
		}

		if opts.DisableRetry {
			clientReq.DisableRetry = true
		}

		if opts.Auth != nil {
			switch opts.Auth.Type {
			case "basic":
				clientReq.Auth = client.NewBasicAuth(opts.Auth.Username, opts.Auth.Password)
			case "bearer":
				clientReq.Auth = client.NewBearerAuth(opts.Auth.Token)
			}
		}
	}

	// Execute request
	ctx := context.Background()
	if clientReq.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, clientReq.Timeout)
		defer cancel()
	}

	resp, err := c.Do(ctx, clientReq)
	if err != nil {
		// Categorize error
		code := protocol.ErrCodeInternal
		errMsg := err.Error()

		if strings.Contains(errMsg, "timeout") || strings.Contains(errMsg, "deadline") {
			code = protocol.ErrCodeTimeout
		} else if strings.Contains(errMsg, "connection refused") {
			code = protocol.ErrCodeConnectionRefused
		} else if strings.Contains(errMsg, "no such host") || strings.Contains(errMsg, "lookup") {
			code = protocol.ErrCodeDNSFailure
		} else if strings.Contains(errMsg, "tls") || strings.Contains(errMsg, "certificate") {
			code = protocol.ErrCodeTLSFailure
		} else if strings.Contains(errMsg, "invalid URL") {
			code = protocol.ErrCodeInvalidURL
		}

		d.sendError(req.ID, code, errMsg)
		return
	}

	// Build response
	response := &protocol.Response{
		ID:       req.ID,
		Type:     protocol.TypeResponse,
		Session:  req.Session,
		Status:   resp.StatusCode,
		Headers:  resp.Headers,
		URL:      resp.FinalURL,
		Protocol: resp.Protocol,
	}

	// Handle body encoding
	bodyStr := string(resp.Body)
	if isTextContent(resp.Headers) {
		response.Body = bodyStr
		response.BodyEncoding = "text"
	} else {
		response.Body = base64.StdEncoding.EncodeToString(resp.Body)
		response.BodyEncoding = "base64"
	}
	response.BodySize = len(resp.Body)

	// Add timing if available
	if resp.Timing != nil {
		response.Timing = resp.Timing
	}

	d.send(response)
}

// handleCookieGet gets cookies for a URL
func (d *Daemon) handleCookieGet(data []byte) {
	var req protocol.CookieGetRequest
	if err := json.Unmarshal(data, &req); err != nil {
		d.sendError("", protocol.ErrCodeInvalidRequest, "Invalid cookie get request: "+err.Error())
		return
	}

	d.mu.RLock()
	session, ok := d.sessions[req.Session]
	d.mu.RUnlock()
	if !ok {
		d.sendError(req.ID, protocol.ErrCodeInvalidSession, "Session not found: "+req.Session)
		return
	}

	jar := session.Client.Cookies()
	if jar == nil {
		d.sendError(req.ID, protocol.ErrCodeInvalidRequest, "Session has no cookie jar")
		return
	}

	u, err := url.Parse(req.URL)
	if err != nil {
		d.sendError(req.ID, protocol.ErrCodeInvalidURL, "Invalid URL: "+err.Error())
		return
	}

	cookies := jar.Cookies(u)
	cookieMap := make(map[string]string)
	for _, c := range cookies {
		cookieMap[c.Name] = c.Value
	}

	d.send(&protocol.CookieResponse{
		ID:      req.ID,
		Type:    protocol.TypeCookieGet,
		Cookies: cookieMap,
	})
}

// handleCookieSet sets a cookie
func (d *Daemon) handleCookieSet(data []byte) {
	var req protocol.CookieSetRequest
	if err := json.Unmarshal(data, &req); err != nil {
		d.sendError("", protocol.ErrCodeInvalidRequest, "Invalid cookie set request: "+err.Error())
		return
	}

	d.mu.RLock()
	session, ok := d.sessions[req.Session]
	d.mu.RUnlock()
	if !ok {
		d.sendError(req.ID, protocol.ErrCodeInvalidSession, "Session not found: "+req.Session)
		return
	}

	jar := session.Client.Cookies()
	if jar == nil {
		d.sendError(req.ID, protocol.ErrCodeInvalidRequest, "Session has no cookie jar")
		return
	}

	u, err := url.Parse(req.URL)
	if err != nil {
		d.sendError(req.ID, protocol.ErrCodeInvalidURL, "Invalid URL: "+err.Error())
		return
	}

	// Build cookie
	cookie := &client.Cookie{
		Name:   req.Name,
		Value:  req.Value,
		Domain: req.Domain,
		Path:   req.Path,
		Secure: req.Secure,
	}
	if req.Expires > 0 {
		cookie.Expires = time.Unix(req.Expires, 0)
	}

	jar.SetCookies(u, []*client.Cookie{cookie})

	d.send(&protocol.Response{
		ID:      req.ID,
		Type:    protocol.TypeCookieSet,
		Session: req.Session,
	})
}

// handleCookieClear clears all cookies for a session
func (d *Daemon) handleCookieClear(data []byte) {
	var req protocol.CookieClearRequest
	if err := json.Unmarshal(data, &req); err != nil {
		d.sendError("", protocol.ErrCodeInvalidRequest, "Invalid cookie clear request: "+err.Error())
		return
	}

	d.mu.RLock()
	session, ok := d.sessions[req.Session]
	d.mu.RUnlock()
	if !ok {
		d.sendError(req.ID, protocol.ErrCodeInvalidSession, "Session not found: "+req.Session)
		return
	}

	session.Client.ClearCookies()

	d.send(&protocol.Response{
		ID:      req.ID,
		Type:    protocol.TypeCookieClear,
		Session: req.Session,
	})
}

// handleCookieAll gets all cookies for a session
func (d *Daemon) handleCookieAll(data []byte) {
	var req protocol.CookieAllRequest
	if err := json.Unmarshal(data, &req); err != nil {
		d.sendError("", protocol.ErrCodeInvalidRequest, "Invalid cookie all request: "+err.Error())
		return
	}

	d.mu.RLock()
	session, ok := d.sessions[req.Session]
	d.mu.RUnlock()
	if !ok {
		d.sendError(req.ID, protocol.ErrCodeInvalidSession, "Session not found: "+req.Session)
		return
	}

	jar := session.Client.Cookies()
	if jar == nil {
		d.sendError(req.ID, protocol.ErrCodeInvalidRequest, "Session has no cookie jar")
		return
	}

	allCookies := jar.AllCookies()
	result := make(map[string][]protocol.Cookie)
	for domain, cookies := range allCookies {
		protoCookies := make([]protocol.Cookie, 0, len(cookies))
		for _, c := range cookies {
			var expires int64
			if !c.Expires.IsZero() {
				expires = c.Expires.Unix()
			}
			protoCookies = append(protoCookies, protocol.Cookie{
				Name:    c.Name,
				Value:   c.Value,
				Domain:  c.Domain,
				Path:    c.Path,
				Secure:  c.Secure,
				Expires: expires,
			})
		}
		result[domain] = protoCookies
	}

	d.send(&protocol.CookieResponse{
		ID:   req.ID,
		Type: protocol.TypeCookieAll,
		All:  result,
	})
}

// send writes a response to stdout
func (d *Daemon) send(v interface{}) {
	d.outputMu.Lock()
	defer d.outputMu.Unlock()
	if err := d.stdout.Encode(v); err != nil {
		log.Printf("Error writing response: %v", err)
	}
}

// sendError writes an error response
func (d *Daemon) sendError(reqID string, code string, message string) {
	d.send(protocol.NewErrorResponse(reqID, code, message))
}

// isTextContent checks if the content type indicates text
func isTextContent(headers map[string]string) bool {
	contentType := ""
	for k, v := range headers {
		if strings.ToLower(k) == "content-type" {
			contentType = strings.ToLower(v)
			break
		}
	}

	if contentType == "" {
		return true // Assume text if no content type
	}

	textTypes := []string{
		"text/",
		"application/json",
		"application/xml",
		"application/javascript",
		"application/x-www-form-urlencoded",
	}

	for _, t := range textTypes {
		if strings.Contains(contentType, t) {
			return true
		}
	}

	return false
}

func main() {
	daemon := NewDaemon()
	if err := daemon.Run(); err != nil {
		log.Fatal(err)
	}
}
