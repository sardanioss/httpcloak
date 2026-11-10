//go:build hctest

package main

// Test-only cgo helpers for upload_test.go and request_timeout_test.go, which
// cannot use cgo themselves. Behind the hctest build tag, like
// callback_thread_hctest.go, so they never reach a shipped library.

/*
#include <stdint.h>
#include <stdlib.h>
*/
import "C"

import "unsafe"

func hcTestUploadStart(session int64, url, options string) int64 {
	u, o := C.CString(url), C.CString(options)
	defer C.free(unsafe.Pointer(u))
	defer C.free(unsafe.Pointer(o))
	return int64(httpcloak_upload_start(C.int64_t(session), u, o))
}

func hcTestUploadWrite(upload int64, data []byte) int {
	p := C.CBytes(data)
	defer C.free(p)
	return int(httpcloak_upload_write_raw(C.int64_t(upload), p, C.int(len(data))))
}

func hcTestUploadFinish(upload int64) string {
	return takeCString(httpcloak_upload_finish(C.int64_t(upload)))
}

func hcTestUploadCancel(upload int64) { httpcloak_upload_cancel(C.int64_t(upload)) }

// hcTestRequestRaw runs a request through httpcloak_request_raw and returns
// the response metadata, or the last error when it failed.
func hcTestRequestRaw(session int64, reqJSON string) (metadata string, errMsg string) {
	c := C.CString(reqJSON)
	defer C.free(unsafe.Pointer(c))
	h := httpcloak_request_raw(C.int64_t(session), c, nil, 0)
	if h < 0 {
		return "", takeCString(httpcloak_last_error(C.int64_t(session)))
	}
	defer httpcloak_response_free(h)
	return takeCString(httpcloak_response_get_metadata(h)), ""
}

// hcTestRequest runs a request through the JSON entry point.
func hcTestRequest(session int64, reqJSON string) string {
	c := C.CString(reqJSON)
	defer C.free(unsafe.Pointer(c))
	return takeCString(httpcloak_request(C.int64_t(session), c))
}

func takeCString(s *C.char) string {
	if s == nil {
		return ""
	}
	defer C.free(unsafe.Pointer(s))
	return C.GoString(s)
}

// hcTestStreamRequest opens a stream through httpcloak_stream_request and
// returns its handle, or the last error.
func hcTestStreamRequest(session int64, reqJSON string) (int64, string) {
	c := C.CString(reqJSON)
	defer C.free(unsafe.Pointer(c))
	h := httpcloak_stream_request(C.int64_t(session), c)
	if h < 0 {
		return -1, takeCString(httpcloak_last_error(C.int64_t(session)))
	}
	return int64(h), ""
}

// hcTestStreamRead reads once into a fresh buffer, returning the count.
func hcTestStreamRead(stream int64, size int) int {
	buf := C.malloc(C.size_t(size))
	defer C.free(buf)
	return int(httpcloak_stream_read_raw(C.int64_t(stream), buf, C.int(size)))
}

func hcTestStreamCancel(stream int64) { httpcloak_stream_cancel(C.int64_t(stream)) }
func hcTestStreamClose(stream int64)  { httpcloak_stream_close(C.int64_t(stream)) }
