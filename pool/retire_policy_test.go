package pool

import (
	"os"
	"regexp"
	"testing"
	"time"
)

// Regression locks for two defects introduced while porting the #83
// connection-lifetime fix into this pool.

// Defect 1: a connection that is only MOMENTARILY unable to take a new request
// was being retired permanently.
//
// isConnUsable ends with h2Conn.CanTakeNewRequest(). That signal goes false
// whenever the connection is at the server's SETTINGS_MAX_CONCURRENT_STREAMS,
// and true again as soon as a stream finishes. Both sweeps retired on
// !isConnUsable, and requestClose sets closeRequested, which nothing ever
// clears. So a single burst of concurrent requests permanently discarded a
// healthy warm connection and forced a fresh TLS handshake for the next one -
// on a fingerprinting library, extra handshakes are also extra exposure.
//
// The invariant: requestClose is only ever reached through isConnRetirable,
// and isConnRetirable never consults a transient signal.
//
// This is a source scan because the transient signal lives on a real
// *http2.ClientConn, which cannot be fabricated in a unit test without a live
// server. The structural property is the thing that must not drift.
func TestRetirementNeverKeysOffTransientSignal(t *testing.T) {
	src, err := os.ReadFile("pool.go")
	if err != nil {
		t.Fatalf("read source: %v", err)
	}

	// Every requestClose call must be guarded by isConnRetirable, never by a
	// negated isConnUsable.
	badGuard := regexp.MustCompile(`if\s+!p\.isConnUsable\([^)]*\)\s*{\s*\n\s*go\s+conn\.requestClose\(\)`)
	if loc := badGuard.FindIndex(src); loc != nil {
		line := 1
		for _, b := range src[:loc[0]] {
			if b == '\n' {
				line++
			}
		}
		t.Errorf("pool.go:%d retires a connection on !isConnUsable", line)
		t.Error("isConnUsable includes CanTakeNewRequest(), which is transient; retiring on it " +
			"permanently discards a connection that is merely at its stream-concurrency limit")
	}

	// And isConnRetirable itself must not consult that signal.
	fn := regexp.MustCompile(`(?s)func \(p \*HostPool\) isConnRetirable\(.*?\n}`).Find(src)
	if fn == nil {
		t.Fatal("isConnRetirable not found; retirement policy must stay explicit")
	}
	if regexp.MustCompile(`CanTakeNewRequest`).Match(fn) {
		t.Error("isConnRetirable consults CanTakeNewRequest(), a transient signal; " +
			"only unrecoverable conditions belong in a one-way retirement decision")
	}
}

// The recoverable/unrecoverable split itself, on the parts reachable without a
// live connection.
func TestIsConnRetirableOnlyOnUnrecoverableState(t *testing.T) {
	p := &HostPool{maxIdleTime: 90 * time.Second, maxConnAge: 5 * time.Minute}

	cases := []struct {
		name string
		conn *Conn
		want bool
	}{
		{
			name: "no underlying h2 conn is unrecoverable",
			conn: &Conn{CreatedAt: time.Now(), LastUsedAt: time.Now(), inFlight: 4},
			want: true,
		},
		{
			name: "past maxConnAge is unrecoverable",
			conn: &Conn{CreatedAt: time.Now().Add(-10 * time.Minute), LastUsedAt: time.Now()},
			want: true,
		},
		{
			name: "already retired needs no second request",
			conn: func() *Conn {
				c := &Conn{CreatedAt: time.Now(), LastUsedAt: time.Now()}
				c.closeRequested = true
				return c
			}(),
			want: false,
		},
		{
			name: "already closed needs no request",
			conn: func() *Conn {
				c := &Conn{CreatedAt: time.Now(), LastUsedAt: time.Now()}
				c.closed = true
				return c
			}(),
			want: false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := p.isConnRetirable(tc.conn); got != tc.want {
				t.Errorf("isConnRetirable = %v, want %v", got, tc.want)
			}
		})
	}
}

// Defect 2: the maxConns cap became unreachable.
//
// The sweep counted a slot only when isConnUsable was true, but control only
// reaches the sweep when the loop above it already proved NO connection was
// usable. `serving` was therefore structurally zero, `serving >= maxConns` was
// dead for every maxConns >= 1, and SetMaxConnsPerHost silently stopped
// bounding anything.
func TestMaxConnsAccountingCountsBusyButLiveConns(t *testing.T) {
	src, err := os.ReadFile("pool.go")
	if err != nil {
		t.Fatalf("read source: %v", err)
	}

	// The slot count must not be gated on "usable right now".
	deadCount := regexp.MustCompile(`if\s+p\.isConnUsable\(conn\)\s*{\s*\n\s*serving\+\+`)
	if deadCount.Match(src) {
		t.Error("the cap counts only connections usable at this instant, but the sweep is only " +
			"reached when none were usable, so the count is structurally zero and maxConns is dead")
	}

	// A retired connection must not hold a slot it can never serve.
	retired := &Conn{CreatedAt: time.Now(), LastUsedAt: time.Now(), inFlight: 1}
	retired.closeRequested = true
	if !retired.isRetired() {
		t.Fatal("isRetired should report true once closeRequested is set")
	}

	// A live connection with work on it must never be destroyable while it is
	// making progress - that is the #83 property this port exists for.
	// abandonedBodyTimeout must be set, exactly as NewHostPoolWithConfig does:
	// left at zero, every in-flight connection is instantly "abandoned" and the
	// whole #83 guarantee evaporates.
	p := &HostPool{maxIdleTime: 90 * time.Second, maxConnAge: 5 * time.Minute, abandonedBodyTimeout: 10 * time.Minute}
	alive := &Conn{CreatedAt: time.Now(), LastUsedAt: time.Now(), inFlight: 1}
	alive.lastProgress.Store(time.Now().UnixNano())
	if p.isConnDestroyable(alive) {
		t.Error("a connection with in-flight work making progress must never be destroyable")
	}
}
