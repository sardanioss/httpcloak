package transport

import (
	"errors"
	"fmt"
	"net"
	"strings"

	utls "github.com/sardanioss/utls"
)

// Error categories for better error handling
var (
	// ErrConnection represents connection-level errors
	ErrConnection = errors.New("connection error")

	// ErrTLS represents TLS/SSL related errors
	ErrTLS = errors.New("TLS error")

	// ErrDNS represents DNS resolution errors
	ErrDNS = errors.New("DNS error")

	// ErrTimeout represents timeout errors
	ErrTimeout = errors.New("timeout error")

	// ErrProxy represents proxy-related errors
	ErrProxy = errors.New("proxy error")

	// ErrProtocol represents protocol negotiation errors
	ErrProtocol = errors.New("protocol error")

	// ErrRequest represents request-level errors
	ErrRequest = errors.New("request error")

	// ErrResponse represents response-level errors
	ErrResponse = errors.New("response error")

	// ErrClosed represents errors when transport is closed
	ErrClosed = errors.New("transport closed")

	// ErrALPNMismatch represents ALPN protocol negotiation mismatch
	ErrALPNMismatch = errors.New("ALPN mismatch")
)

// ALPNMismatchError is returned when ALPN negotiates a different protocol than expected.
// It carries the TLS connection so it can be reused for the negotiated protocol.
type ALPNMismatchError struct {
	Expected   string      // Expected protocol (e.g., "h2")
	Negotiated string      // Actually negotiated protocol (e.g., "http/1.1")
	TLSConn    *utls.UConn // The TLS connection (caller should close if not reusing)
	Host       string      // Target host
	Port       string      // Target port
}

func (e *ALPNMismatchError) Error() string {
	return fmt.Sprintf("ALPN mismatch: expected %s, got %s", e.Expected, e.Negotiated)
}

func (e *ALPNMismatchError) Unwrap() error {
	return ErrALPNMismatch
}

// TransportError provides detailed error information
type TransportError struct {
	Op        string // Operation that failed (e.g., "dial", "tls_handshake", "request")
	Host      string // Target host
	Port      string // Target port
	Protocol  string // Protocol (h1, h2, h3)
	Cause     error  // Underlying error
	Category  error  // Error category (ErrConnection, ErrTLS, etc.)
	Retryable bool   // Whether the operation can be retried
}

// Error implements the error interface
func (e *TransportError) Error() string {
	var sb strings.Builder
	sb.WriteString(e.Op)
	if e.Host != "" {
		sb.WriteString(" ")
		sb.WriteString(e.Host)
		if e.Port != "" && e.Port != "443" && e.Port != "80" {
			sb.WriteString(":")
			sb.WriteString(e.Port)
		}
	}
	if e.Protocol != "" {
		sb.WriteString(" [")
		sb.WriteString(e.Protocol)
		sb.WriteString("]")
	}
	if e.Cause != nil {
		sb.WriteString(": ")
		sb.WriteString(e.Cause.Error())
	}
	return sb.String()
}

// Unwrap returns the underlying error
func (e *TransportError) Unwrap() error {
	return e.Cause
}

// Is checks if the error matches the target
func (e *TransportError) Is(target error) bool {
	if e.Category != nil && errors.Is(e.Category, target) {
		return true
	}
	return errors.Is(e.Cause, target)
}

// IsRetryable returns whether the error is retryable
func (e *TransportError) IsRetryable() bool {
	return e.Retryable
}

// NewConnectionError creates a connection error
func NewConnectionError(op, host, port, protocol string, cause error) *TransportError {
	return &TransportError{
		Op:        op,
		Host:      host,
		Port:      port,
		Protocol:  protocol,
		Cause:     cause,
		Category:  ErrConnection,
		Retryable: isRetryableError(cause),
	}
}

// NewTLSError creates a TLS error
func NewTLSError(op, host, port, protocol string, cause error) *TransportError {
	return &TransportError{
		Op:        op,
		Host:      host,
		Port:      port,
		Protocol:  protocol,
		Cause:     cause,
		Category:  ErrTLS,
		Retryable: false, // TLS errors are generally not retryable
	}
}

// NewDNSError creates a DNS error
func NewDNSError(host string, cause error) *TransportError {
	return &TransportError{
		Op:        "dns_resolve",
		Host:      host,
		Cause:     cause,
		Category:  ErrDNS,
		Retryable: true, // DNS failures can be transient
	}
}

// NewTimeoutError creates a timeout error
func NewTimeoutError(op, host, port, protocol string, cause error) *TransportError {
	return &TransportError{
		Op:        op,
		Host:      host,
		Port:      port,
		Protocol:  protocol,
		Cause:     cause,
		Category:  ErrTimeout,
		Retryable: true, // Timeouts are retryable
	}
}

// NewProxyError creates a proxy error
func NewProxyError(op, host, port string, cause error) *TransportError {
	return &TransportError{
		Op:        op,
		Host:      host,
		Port:      port,
		Cause:     cause,
		Category:  ErrProxy,
		Retryable: false,
	}
}

// NewProtocolError creates a protocol negotiation error
func NewProtocolError(host, port, protocol string, cause error) *TransportError {
	return &TransportError{
		Op:        "protocol_negotiation",
		Host:      host,
		Port:      port,
		Protocol:  protocol,
		Cause:     cause,
		Category:  ErrProtocol,
		Retryable: false,
	}
}

// NewRequestError creates a request error
func NewRequestError(op, host, port, protocol string, cause error) *TransportError {
	return &TransportError{
		Op:        op,
		Host:      host,
		Port:      port,
		Protocol:  protocol,
		Cause:     cause,
		Category:  ErrRequest,
		Retryable: isRetryableError(cause),
	}
}

// WrapError wraps an error with transport context
func WrapError(op, host, port, protocol string, cause error) error {
	if cause == nil {
		return nil
	}

	// Check if already wrapped
	var te *TransportError
	if errors.As(cause, &te) {
		return cause
	}

	// Categorize the error
	category := categorizeError(cause)
	retryable := isRetryableError(cause)

	return &TransportError{
		Op:        op,
		Host:      host,
		Port:      port,
		Protocol:  protocol,
		Cause:     cause,
		Category:  category,
		Retryable: retryable,
	}
}

// categorizeError determines the error category from the underlying error
func categorizeError(err error) error {
	if err == nil {
		return nil
	}

	errStr := strings.ToLower(err.Error())

	// Check for timeout
	if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
		return ErrTimeout
	}

	// Check for DNS errors
	if _, ok := err.(*net.DNSError); ok {
		return ErrDNS
	}

	// Check for TLS errors
	if strings.Contains(errStr, "tls") ||
		strings.Contains(errStr, "certificate") ||
		strings.Contains(errStr, "x509") ||
		strings.Contains(errStr, "handshake") {
		return ErrTLS
	}

	// Check for connection errors
	if strings.Contains(errStr, "connection refused") ||
		strings.Contains(errStr, "connection reset") ||
		strings.Contains(errStr, "broken pipe") ||
		strings.Contains(errStr, "no route to host") ||
		strings.Contains(errStr, "network is unreachable") {
		return ErrConnection
	}

	// Check for proxy errors
	if strings.Contains(errStr, "proxy") {
		return ErrProxy
	}

	// Check for protocol errors
	if strings.Contains(errStr, "protocol") ||
		strings.Contains(errStr, "http2") ||
		strings.Contains(errStr, "alpn") {
		return ErrProtocol
	}

	// Default to connection error
	return ErrConnection
}

// isRetryableError determines if an error is retryable
func isRetryableError(err error) bool {
	if err == nil {
		return false
	}

	// Timeouts are retryable
	if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
		return true
	}

	// Temporary errors are retryable
	if netErr, ok := err.(net.Error); ok && netErr.Temporary() {
		return true
	}

	errStr := strings.ToLower(err.Error())

	// Connection reset/refused can be retried
	if strings.Contains(errStr, "connection reset") ||
		strings.Contains(errStr, "connection refused") ||
		strings.Contains(errStr, "broken pipe") {
		return true
	}

	// DNS failures can be transient
	if _, ok := err.(*net.DNSError); ok {
		return true
	}

	// EOF can sometimes be retried
	if strings.Contains(errStr, "eof") {
		return true
	}

	return false
}

// IsTimeout checks if an error is a timeout error
func IsTimeout(err error) bool {
	if err == nil {
		return false
	}
	var te *TransportError
	if errors.As(err, &te) {
		return errors.Is(te.Category, ErrTimeout)
	}
	if netErr, ok := err.(net.Error); ok {
		return netErr.Timeout()
	}
	return false
}

// IsTLSError checks if an error is a TLS error
func IsTLSError(err error) bool {
	if err == nil {
		return false
	}
	var te *TransportError
	if errors.As(err, &te) {
		return errors.Is(te.Category, ErrTLS)
	}
	return strings.Contains(strings.ToLower(err.Error()), "tls")
}

// IsDNSError checks if an error is a DNS error
func IsDNSError(err error) bool {
	if err == nil {
		return false
	}
	var te *TransportError
	if errors.As(err, &te) {
		return errors.Is(te.Category, ErrDNS)
	}
	_, ok := err.(*net.DNSError)
	return ok
}

// IsConnectionError checks if an error is a connection error
func IsConnectionError(err error) bool {
	if err == nil {
		return false
	}
	var te *TransportError
	if errors.As(err, &te) {
		return errors.Is(te.Category, ErrConnection)
	}
	return false
}

// IsProxyError checks if an error is a proxy error
func IsProxyError(err error) bool {
	if err == nil {
		return false
	}
	var te *TransportError
	if errors.As(err, &te) {
		return errors.Is(te.Category, ErrProxy)
	}
	return strings.Contains(strings.ToLower(err.Error()), "proxy")
}

// HTTPError represents an HTTP-level error (4xx, 5xx responses)
type HTTPError struct {
	StatusCode int
	Status     string
	Body       []byte
	Headers    map[string]string
}

// Error implements the error interface
func (e *HTTPError) Error() string {
	return fmt.Sprintf("HTTP %d: %s", e.StatusCode, e.Status)
}

// IsClientError returns true for 4xx errors
func (e *HTTPError) IsClientError() bool {
	return e.StatusCode >= 400 && e.StatusCode < 500
}

// IsServerError returns true for 5xx errors
func (e *HTTPError) IsServerError() bool {
	return e.StatusCode >= 500
}

// IsRetryable returns true for errors that should be retried
func (e *HTTPError) IsRetryable() bool {
	switch e.StatusCode {
	case 408, 425, 429, 500, 502, 503, 504:
		return true
	default:
		return false
	}
}

// NewHTTPError creates an HTTP error from status code
func NewHTTPError(statusCode int, status string, body []byte, headers map[string]string) *HTTPError {
	return &HTTPError{
		StatusCode: statusCode,
		Status:     status,
		Body:       body,
		Headers:    headers,
	}
}
