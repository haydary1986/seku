package scanner

// JWT Weakness Scanner
// -----------------------------------------------------------------------------
// Harvests JWTs from response cookies/headers/body and checks for the two most
// dangerous, easily-detected flaws: the "alg:none" bypass and HMAC signatures
// signed with a weak/guessable secret. Both let an attacker forge arbitrary
// tokens (full authentication bypass / privilege escalation).

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"

	"seku/internal/models"
)

type JWTScanner struct{}

func NewJWTScanner() *JWTScanner { return &JWTScanner{} }

func (s *JWTScanner) Name() string     { return "JWT Weakness Scanner" }
func (s *JWTScanner) Category() string { return "jwt_security" }
func (s *JWTScanner) Weight() float64  { return 9.0 }

var jwtRe = regexp.MustCompile(`eyJ[A-Za-z0-9_-]{5,}\.eyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]*`)

// weakJWTSecrets is a small, high-signal list of secrets that must never sign a
// production token. A hit is an immediate critical finding.
var weakJWTSecrets = []string{
	"secret", "password", "changeme", "admin", "123456", "jwt", "jwtsecret",
	"secretkey", "key", "test", "your-256-bit-secret", "supersecret",
	"seku-secret-change-in-production", "your_jwt_secret", "mysecret",
}

func (s *JWTScanner) Scan(rawURL string) []models.CheckResult {
	base := ensureHTTPS(rawURL)
	client := &http.Client{Timeout: 10 * time.Second, Transport: ScanTransport}

	tokens := map[string]bool{}
	if resp, err := client.Get(base); err == nil {
		for _, ck := range resp.Cookies() {
			for _, t := range jwtRe.FindAllString(ck.Value, -1) {
				tokens[t] = true
			}
		}
		for _, hv := range resp.Header.Values("Authorization") {
			for _, t := range jwtRe.FindAllString(hv, -1) {
				tokens[t] = true
			}
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 300*1024))
		resp.Body.Close()
		for _, t := range jwtRe.FindAllString(string(body), -1) {
			tokens[t] = true
		}
	}

	if len(tokens) == 0 {
		return []models.CheckResult{{
			Category:  s.Category(),
			CheckName: "JWT Security",
			Weight:    2.0,
			Status:    "pass",
			Score:     1000,
			Severity:  "info",
			Details:   toJSON(map[string]string{"message": "No JWT tokens observed in responses or cookies."}),
		}}
	}

	noExp := false
	for tok := range tokens {
		parts := strings.Split(tok, ".")
		if len(parts) < 2 {
			continue
		}
		alg, _ := jwtHeaderAlg(parts[0])

		// 1) alg:none — OBSERVED only. We saw a token declaring 'alg:none' but did
		// NOT actively confirm the server accepts a forged unsigned token, so this
		// is a high-severity red flag (unconfirmed), not a confirmed critical bypass.
		if strings.EqualFold(alg, "none") {
			return []models.CheckResult{{
				Category:   s.Category(),
				CheckName:  "JWT 'alg:none' Observed",
				Weight:     9.0,
				Status:     "warn",
				Score:      250,
				Severity:   "high",
				Confidence: 55,
				OWASP:      "A02:2021 - Cryptographic Failures",
				Details:    toJSON(map[string]string{"message": "A JWT declaring the unsigned 'alg:none' algorithm was observed. This is a strong red flag but was NOT actively confirmed to be accepted by the server. Verify the server rejects forged unsigned tokens and pins the expected algorithm — if it accepts them, this becomes a critical authentication bypass."}),
			}}
		}

		// 2) weak HMAC secret — forge tokens by re-signing.
		if len(parts) == 3 && strings.HasPrefix(strings.ToUpper(alg), "HS") {
			if secret := crackHMAC(parts[0]+"."+parts[1], parts[2], alg); secret != "" {
				return []models.CheckResult{s.critical("JWT Signed With Weak Secret",
					"A JWT is signed with a trivially guessable secret ('"+secret+"'). An attacker can forge valid tokens for any user. Rotate to a long, random secret (>=32 bytes) immediately.")}
			}
		}

		if !jwtHasExp(parts[1]) {
			noExp = true
		}
	}

	if noExp {
		return []models.CheckResult{{
			Category:   s.Category(),
			CheckName:  "JWT Missing Expiry",
			Weight:     5.0,
			Status:     "warn",
			Score:      600,
			Severity:   "low",
			Confidence: 70,
			OWASP:      "A07:2021 - Identification and Authentication Failures",
			Details:    toJSON(map[string]string{"message": "A JWT without an 'exp' (expiration) claim was observed. Tokens without expiry stay valid forever if leaked. Add a short expiry."}),
		}}
	}

	return []models.CheckResult{{
		Category:   s.Category(),
		CheckName:  "JWT Security",
		Weight:     3.0,
		Status:     "pass",
		Score:      1000,
		Severity:   "info",
		Confidence: 70,
		Details:    toJSON(map[string]string{"message": "JWT(s) detected with a signed algorithm and expiry — no obvious weakness found."}),
	}}
}

func (s *JWTScanner) critical(name, msg string) models.CheckResult {
	return models.CheckResult{
		Category:   s.Category(),
		CheckName:  name,
		Weight:     9.0,
		Status:     "fail",
		Score:      0,
		Severity:   "critical",
		Confidence: 90,
		OWASP:      "A02:2021 - Cryptographic Failures",
		Details:    toJSON(map[string]string{"message": msg}),
	}
}

func jwtHeaderAlg(part string) (string, bool) {
	raw, err := base64.RawURLEncoding.DecodeString(part)
	if err != nil {
		return "", false
	}
	var h struct {
		Alg string `json:"alg"`
	}
	if err := json.Unmarshal(raw, &h); err != nil {
		return "", false
	}
	return h.Alg, true
}

func jwtHasExp(part string) bool {
	raw, err := base64.RawURLEncoding.DecodeString(part)
	if err != nil {
		return true // undecodable → don't false-flag
	}
	var p map[string]interface{}
	if err := json.Unmarshal(raw, &p); err != nil {
		return true
	}
	_, ok := p["exp"]
	return ok
}

// crackHMAC returns the weak secret if signingInput verifies against sig with one
// of the known-weak secrets, else "".
func crackHMAC(signingInput, sig, alg string) string {
	want, err := base64.RawURLEncoding.DecodeString(sig)
	if err != nil || len(want) == 0 {
		return ""
	}
	for _, secret := range weakJWTSecrets {
		mac := hmac.New(sha256.New, []byte(secret))
		mac.Write([]byte(signingInput))
		if hmac.Equal(mac.Sum(nil), want) {
			return secret
		}
	}
	return ""
}
