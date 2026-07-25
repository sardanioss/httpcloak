package pool

import (
	"context"
	"net"
	"time"
)

// armProxyHandshakeDeadline bounds all reads and writes performed while negotiating
// a proxy tunnel. Cancelling the context interrupts an in-flight socket operation.
func armProxyHandshakeDeadline(
	ctx context.Context,
	connection net.Conn,
	fallback time.Duration,
) (func(), error) {
	deadline := time.Now().Add(fallback)
	if contextDeadline, ok := ctx.Deadline(); ok && contextDeadline.Before(deadline) {
		deadline = contextDeadline
	}
	if err := connection.SetDeadline(deadline); err != nil {
		return nil, err
	}

	cancellationApplied := make(chan struct{})
	stopCancellation := context.AfterFunc(ctx, func() {
		_ = connection.SetDeadline(time.Now())
		close(cancellationApplied)
	})

	return func() {
		if !stopCancellation() {
			<-cancellationApplied
		}
		_ = connection.SetDeadline(time.Time{})
	}, nil
}
