// Package keylog provides TLS key logging for traffic analysis with Wireshark.
//
// This implements the SSLKEYLOGFILE format that allows Wireshark to decrypt
// TLS traffic when the key log file is configured in Wireshark's settings.
//
// Usage:
//
//	// Automatic: reads from SSLKEYLOGFILE environment variable
//	// Just set SSLKEYLOGFILE=/path/to/keys.log before running
//
//	// Manual: set a specific file
//	keylog.SetKeyLogFile("/path/to/keys.log")
//
//	// Custom writer
//	keylog.SetKeyLogWriter(myWriter)
package keylog

import (
	"io"
	"os"
	"sync"
)

var (
	globalWriter io.Writer
	globalMu     sync.RWMutex
	initialized  bool
)

// init checks the SSLKEYLOGFILE environment variable on startup
func init() {
	initFromEnv()
}

// initFromEnv initializes the global writer from SSLKEYLOGFILE env var
func initFromEnv() {
	globalMu.Lock()
	defer globalMu.Unlock()

	if initialized {
		return
	}
	initialized = true

	path := os.Getenv("SSLKEYLOGFILE")
	if path == "" {
		return
	}

	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0600)
	if err != nil {
		// Silently ignore errors - this is a debug feature
		return
	}
	globalWriter = f
}

// GetWriter returns the global key log writer, or nil if not configured.
// This is used internally by transport code to set tls.Config.KeyLogWriter.
func GetWriter() io.Writer {
	globalMu.RLock()
	defer globalMu.RUnlock()
	return globalWriter
}

// SetKeyLogFile sets the global key log file path.
// This overrides the SSLKEYLOGFILE environment variable.
// Pass empty string to disable key logging.
func SetKeyLogFile(path string) error {
	globalMu.Lock()
	defer globalMu.Unlock()

	// Close existing writer if it's a file we opened
	if closer, ok := globalWriter.(io.Closer); ok {
		closer.Close()
	}
	globalWriter = nil

	if path == "" {
		return nil
	}

	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0600)
	if err != nil {
		return err
	}
	globalWriter = f
	return nil
}

// SetKeyLogWriter sets a custom key log writer.
// This allows writing to any io.Writer (e.g., a buffer for testing).
// Pass nil to disable key logging.
func SetKeyLogWriter(w io.Writer) {
	globalMu.Lock()
	defer globalMu.Unlock()

	// Close existing writer if it's a file we opened
	if closer, ok := globalWriter.(io.Closer); ok {
		closer.Close()
	}
	globalWriter = w
}

// NewFileWriter creates a new key log writer for a specific file.
// This is useful for session-level key logging that doesn't affect the global writer.
// The caller is responsible for closing the returned writer.
func NewFileWriter(path string) (io.WriteCloser, error) {
	return os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0600)
}

// Close closes the global key log writer if it was opened by this package.
// This should be called on application shutdown for clean resource release.
func Close() error {
	globalMu.Lock()
	defer globalMu.Unlock()

	if closer, ok := globalWriter.(io.Closer); ok {
		err := closer.Close()
		globalWriter = nil
		return err
	}
	globalWriter = nil
	return nil
}
