package scanner

import (
	"bufio"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"time"

	utls "github.com/refraction-networking/utls"
	"golang.org/x/net/http2"
)

// utlsTransport performs HTTPS requests with a Chrome-like TLS ClientHello (via
// uTLS) so that WAF/CDN TLS-fingerprint checks (Cloudflare Bot Fight — JA3/JA4)
// classify the scanner as a real browser and return the TRUE response, including
// edge-added security headers (CSP, X-Frame-Options, ...) that bot-classified
// clients otherwise don't receive.
//
// It supports both HTTP/1.1 and HTTP/2 (whichever the server negotiates via
// ALPN) and falls back to the standard transport on any failure, so TLS mimicry
// can never break a scan.
type utlsTransport struct {
	fallback http.RoundTripper
	h2       http2.Transport
}

func newUTLSTransport() *utlsTransport {
	return &utlsTransport{
		fallback: &http.Transport{
			TLSClientConfig:   &tls.Config{InsecureSkipVerify: true},
			MaxIdleConns:      50,
			IdleConnTimeout:   30 * time.Second,
			ForceAttemptHTTP2: true,
			DialContext:       (&net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
		},
	}
}

// connCloser ties a response body to the connection it was read over, so closing
// the body (which every scanner does) releases the underlying connection.
type connCloser struct {
	io.ReadCloser
	closer io.Closer
}

func (b *connCloser) Close() error {
	err := b.ReadCloser.Close()
	if b.closer != nil {
		b.closer.Close()
	}
	return err
}

func (t *utlsTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.URL.Scheme != "https" {
		return t.fallback.RoundTrip(req)
	}
	resp, err := t.roundTripUTLS(req)
	if err != nil {
		return t.fallback.RoundTrip(req) // never break a scan over TLS mimicry
	}
	return resp, nil
}

func (t *utlsTransport) roundTripUTLS(req *http.Request) (*http.Response, error) {
	host := req.URL.Hostname()
	port := req.URL.Port()
	if port == "" {
		port = "443"
	}

	tcp, err := (&net.Dialer{Timeout: 10 * time.Second}).DialContext(req.Context(), "tcp", net.JoinHostPort(host, port))
	if err != nil {
		return nil, err
	}
	uconn := utls.UClient(tcp, &utls.Config{ServerName: host, InsecureSkipVerify: true}, utls.HelloChrome_Auto)
	if err := uconn.Handshake(); err != nil {
		tcp.Close()
		return nil, err
	}

	if uconn.ConnectionState().NegotiatedProtocol == "h2" {
		cc, err := t.h2.NewClientConn(uconn)
		if err != nil {
			uconn.Close()
			return nil, err
		}
		resp, err := cc.RoundTrip(req)
		if err != nil {
			cc.Close()
			return nil, err
		}
		resp.Body = &connCloser{ReadCloser: resp.Body, closer: cc}
		return resp, nil
	}

	// HTTP/1.1
	if err := req.Write(uconn); err != nil {
		uconn.Close()
		return nil, err
	}
	resp, err := http.ReadResponse(bufio.NewReader(uconn), req)
	if err != nil {
		uconn.Close()
		return nil, err
	}
	resp.Body = &connCloser{ReadCloser: resp.Body, closer: uconn}
	return resp, nil
}
