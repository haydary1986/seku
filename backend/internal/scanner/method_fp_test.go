package scanner

import "testing"

func TestHttpMethodProcessed(t *testing.T) {
	// soft response: PUT returns 200 with ~same body as GET → NOT processed
	if httpMethodProcessed("PUT", 200, 100000, 100001, "<html>...</html>") {
		t.Error("PUT returning the homepage (same size as GET) must NOT be flagged")
	}
	// real processing: 201 Created
	if !httpMethodProcessed("PUT", 201, 20, 100000, "created") {
		t.Error("201 Created must be flagged as processed")
	}
	// real processing: 2xx with very different body
	if !httpMethodProcessed("DELETE", 200, 30, 100000, "deleted ok") {
		t.Error("2xx with a body far smaller than GET should be flagged")
	}
	// TRACE echo (XST)
	if !httpMethodProcessed("TRACE", 200, 200, 100000, "TRACE / HTTP/1.1\nHost: x") {
		t.Error("TRACE echoing the request (XST) must be flagged")
	}
	// TRACE not echoing → safe
	if httpMethodProcessed("TRACE", 200, 100000, 100000, "<html>homepage</html>") {
		t.Error("TRACE that returns the homepage must NOT be flagged")
	}
	// blocked
	if httpMethodProcessed("PUT", 403, 100, 100000, "forbidden") {
		t.Error("403 must NOT be flagged")
	}
}
