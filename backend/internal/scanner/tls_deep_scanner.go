package scanner

// Deep TLS scanner — wraps ProjectDiscovery's `tlsx` to inspect the target's TLS
// handshake and certificate in depth: negotiated protocol version, cipher
// strength, certificate expiry, self-signed / hostname-mismatch. This is a
// passive connection (no attack payloads), safe to run in the normal pipeline.
// Degrades gracefully if the tlsx binary is absent.

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"
	"time"

	"seku/internal/models"
)

type TLSDeepScanner struct{}

func NewTLSDeepScanner() *TLSDeepScanner { return &TLSDeepScanner{} }

func (s *TLSDeepScanner) Name() string     { return "Deep TLS Scanner (tlsx)" }
func (s *TLSDeepScanner) Category() string { return "tls_deep" }
func (s *TLSDeepScanner) Weight() float64  { return 8.0 }

type tlsxResult struct {
	Host        string   `json:"host"`
	Port        string   `json:"port"`
	TLSVersion  string   `json:"tls_version"`
	Cipher      string   `json:"cipher"`
	NotAfter    string   `json:"not_after"`
	SubjectCN   string   `json:"subject_cn"`
	SubjectAN   []string `json:"subject_an"`
	SelfSigned  bool     `json:"self_signed"`
	Expired     bool     `json:"expired"`
	Mismatched  bool     `json:"mismatched"`
	Untrusted   bool     `json:"untrusted"`
}

func (s *TLSDeepScanner) Scan(rawURL string) []models.CheckResult {
	bin := envStr("SEKU_TLSX_BIN", "tlsx")
	if _, err := exec.LookPath(bin); err != nil {
		return []models.CheckResult{s.info("Deep TLS Inspection",
			"tlsx binary not found in the image — deep TLS inspection skipped.")}
	}
	host := extractHost(ensureHTTPS(rawURL))
	if host == "" {
		return []models.CheckResult{s.info("Deep TLS Inspection", "could not resolve a host to inspect.")}
	}

	res, err := s.run(bin, host)
	if err != nil || res == nil {
		msg := "no TLS service was reachable on port 443."
		if err != nil {
			msg = "tlsx returned no usable result (" + err.Error() + ")."
		}
		return []models.CheckResult{s.info("Deep TLS Inspection", msg)}
	}
	return s.assemble(res)
}

func (s *TLSDeepScanner) run(bin, host string) (*tlsxResult, error) {
	timeout := time.Duration(envInt("SEKU_TLSX_TIMEOUT", 30)) * time.Second
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	args := []string{
		"-u", host + ":443",
		"-json", "-silent", "-no-color",
		"-tls-version", "-cipher", "-expired", "-self-signed", "-mismatched", "-untrusted", "-so",
	}
	cmd := exec.CommandContext(ctx, bin, args...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil && len(out) == 0 {
		return nil, err
	}
	sc := bufio.NewScanner(bytes.NewReader(out))
	sc.Buffer(make([]byte, 512*1024), 2*1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || line[0] != '{' {
			continue
		}
		var r tlsxResult
		if json.Unmarshal([]byte(line), &r) == nil && r.Host != "" {
			return &r, nil
		}
	}
	return nil, nil
}

func (s *TLSDeepScanner) assemble(r *tlsxResult) []models.CheckResult {
	var out []models.CheckResult

	// 1) Protocol version
	ver := strings.ToLower(r.TLSVersion)
	switch {
	case ver == "tls13" || ver == "tls12":
		out = append(out, s.check("TLS Protocol Version", "pass", 1000, "low",
			fmt.Sprintf("Negotiated %s — modern and secure.", strings.ToUpper(ver))))
	case ver == "tls11" || ver == "tls10" || strings.HasPrefix(ver, "ssl"):
		out = append(out, s.check("TLS Protocol Version", "fail", 150, "high",
			fmt.Sprintf("Negotiated %s — this protocol is deprecated and insecure. Disable it and require TLS 1.2+.", strings.ToUpper(ver))))
	case ver != "":
		out = append(out, s.check("TLS Protocol Version", "warn", 500, "medium",
			"Negotiated "+strings.ToUpper(ver)+" — verify TLS 1.2+ is enforced."))
	}

	// 2) Cipher strength
	if r.Cipher != "" {
		if isWeakCipher(r.Cipher) {
			out = append(out, s.check("TLS Cipher Strength", "warn", 450, "medium",
				"Weak/legacy cipher negotiated ("+r.Cipher+"). Prefer AEAD suites (GCM/CHACHA20) and drop RC4/3DES/CBC/SHA1."))
		} else {
			out = append(out, s.check("TLS Cipher Strength", "pass", 1000, "low",
				"Strong cipher negotiated ("+r.Cipher+")."))
		}
	}

	// 3) Certificate validity
	switch {
	case r.Expired:
		out = append(out, s.check("Certificate Expiry", "fail", 0, "high",
			"The TLS certificate is EXPIRED — browsers will block the site. Renew immediately."))
	case r.NotAfter != "":
		if t, err := parseTLSTime(r.NotAfter); err == nil {
			d := time.Until(t)
			if d < 0 {
				out = append(out, s.check("Certificate Expiry", "fail", 0, "high", "The TLS certificate is expired. Renew immediately."))
			} else if d < 21*24*time.Hour {
				out = append(out, s.check("Certificate Expiry", "warn", 500, "medium",
					fmt.Sprintf("The TLS certificate expires in %d day(s) (%s). Renew soon to avoid an outage.", int(d.Hours()/24), r.NotAfter)))
			} else {
				out = append(out, s.check("Certificate Expiry", "pass", 1000, "low",
					fmt.Sprintf("Certificate valid until %s.", r.NotAfter)))
			}
		}
	}

	// 4) Trust chain / self-signed
	if r.SelfSigned {
		out = append(out, s.check("Certificate Trust", "fail", 150, "high",
			"The certificate is SELF-SIGNED — clients cannot verify authenticity and will warn users. Use a CA-issued certificate."))
	} else if r.Untrusted {
		out = append(out, s.check("Certificate Trust", "warn", 400, "medium",
			"The certificate chain is untrusted (missing intermediates or unknown CA). Serve the full chain."))
	}

	// 5) Hostname match
	if r.Mismatched {
		out = append(out, s.check("Certificate Hostname Match", "fail", 150, "high",
			"The certificate does not match the hostname (CN/SAN mismatch) — clients will reject it. Reissue for the correct name."))
	}

	// Summary
	summary := s.check("Deep TLS Inspection", "pass", 1000, "info",
		fmt.Sprintf("Inspected %s:%s — %s, cipher %s.", r.Host, def(r.Port, "443"), strings.ToUpper(def(r.TLSVersion, "unknown")), def(r.Cipher, "n/a")))
	return append([]models.CheckResult{summary}, out...)
}

func (s *TLSDeepScanner) check(name, status string, score float64, sev, msg string) models.CheckResult {
	return models.CheckResult{
		Category:   s.Category(),
		CheckName:  name,
		Weight:     3.0,
		Status:     status,
		Score:      score,
		Severity:   sev,
		Confidence: 90,
		Details:    toJSON(map[string]string{"message": msg}),
	}
}

func (s *TLSDeepScanner) info(name, msg string) models.CheckResult {
	return models.CheckResult{
		Category: s.Category(), CheckName: name, Weight: 3.0,
		Status: "info", Score: 1000, Severity: "info",
		Details: toJSON(map[string]string{"message": msg, "state": "skipped"}),
	}
}

func isWeakCipher(c string) bool {
	u := strings.ToUpper(c)
	for _, w := range []string{"RC4", "3DES", "DES", "NULL", "EXPORT", "MD5", "_CBC_", "-CBC-", "ANON"} {
		if strings.Contains(u, w) {
			return true
		}
	}
	return false
}

func parseTLSTime(s string) (time.Time, error) {
	for _, layout := range []string{time.RFC3339, "2006-01-02T15:04:05Z07:00", "2006-01-02 15:04:05 -0700 MST", "2006-01-02T15:04:05Z"} {
		if t, err := time.Parse(layout, s); err == nil {
			return t, nil
		}
	}
	return time.Time{}, fmt.Errorf("unparseable time %q", s)
}

func def(v, d string) string {
	if strings.TrimSpace(v) == "" {
		return d
	}
	return v
}
