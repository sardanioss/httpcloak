package transport

// IdempotentMethod reports whether method is idempotent by RFC 9110 section
// 9.2.2: GET, HEAD, OPTIONS, TRACE, PUT and DELETE. The empty method is GET.
// Methods are case-sensitive (RFC 9110 section 9.1), so "put" is not PUT.
func IdempotentMethod(method string) bool {
	switch method {
	case "", "GET", "HEAD", "OPTIONS", "TRACE", "PUT", "DELETE":
		return true
	}
	return false
}

// CanResend reports whether a request whose attempt failed with err may be
// sent again with no risk of the server acting on it twice: err proves that
// nothing of it was sent (RequestNotSent), or its method is idempotent and
// bodyReplayable says its body can be sent again whole.
//
// It is the rule the library holds itself to. A request that may have reached
// the server may have been acted on, and sending it again can have it acted
// on twice: a second order, a second payment. So the library sends a request
// again by itself (on a new connection, on another protocol, after a stalled
// HTTP/3 path, or as a session's or client's retry) only when one of these
// holds:
//
//  1. Nothing of it was written to any connection: no connection could be had
//     for it, or an HTTP/1.1 write to a pooled connection failed before its
//     first byte.
//  2. The server said it did not process it: an HTTP/2 RST_STREAM with
//     REFUSED_STREAM, a GOAWAY whose last stream ID is below the request's
//     stream, or HTTP/3's H3_REQUEST_REJECTED. The HTTP/2 and HTTP/3
//     transports resend these themselves, as Chrome does.
//  3. Its method is idempotent and its body can be sent again (it has none,
//     or holds it in memory), so that sending it twice has the effect of
//     sending it once.
//
// Never otherwise: a POST or PATCH that may have been written is not sent
// again, whatever became of it, and its failure comes back with RequestNotSent
// false, for the caller to settle (by asking the server what became of it,
// say). Nor does HTTP/1.1 send a request again once the wait for its answer
// timed out: a slow answer is a server at work, perhaps on this very request.
//
// That is stricter than Chrome, which on HTTP/1.1 resends any method whose
// reused connection was reset or closed before the answer began
// (HttpNetworkTransaction::ShouldResendRequest): a browser can ask its user
// before a form is submitted again, but a program placing an order cannot,
// and an order placed twice costs more than one that failed visibly. It is Go
// net/http's rule (Transport's shouldRetryRequest, nothingWrittenError), with
// two differences: net/http resends a PUT or DELETE only when nothing of it
// was written, where RFC 9110 makes both idempotent; and it takes an
// Idempotency-Key header as making any method idempotent, which this does not,
// because whether the server honours the key is not something the library
// can know. A caller who knows may send such a request again itself.
func CanResend(method string, bodyReplayable bool, err error) bool {
	return RequestNotSent(err) || (IdempotentMethod(method) && bodyReplayable)
}

// canResendOnAnotherProtocol is CanResend for a request whose attempt on one
// protocol failed with err, to be sent on another on a fresh connection. Its
// body can be sent again only when it is held in memory: a body read from a
// stream was consumed by the first attempt, and resending it would send it
// empty.
func canResendOnAnotherProtocol(req *Request, err error) bool {
	return CanResend(req.Method, req.BodyReader == nil, err)
}
