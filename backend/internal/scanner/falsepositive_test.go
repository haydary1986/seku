package scanner

import (
	"strings"
	"testing"
)

// bigJSONLD returns a legitimate, >5KB inline JSON-LD block like the one
// University of Turath serves (schema.org structured data). It must NOT be
// classified as obfuscated.
func bigJSONLD() string {
	var b strings.Builder
	b.WriteString(`{"@context":"https://schema.org","@graph":[`)
	for i := 0; i < 120; i++ {
		b.WriteString(`{"@type":"Place","@id":"https://uoturath.edu.iq/#place",`)
		b.WriteString(`"name":"University of Turath","geo":{"@type":"GeoCoordinates",`)
		b.WriteString(`"latitude":"33.3152","longitude":"44.3661"},"address":"Baghdad, Iraq"},`)
	}
	b.WriteString(`]}`)
	return b.String()
}

// bigMinifiedJS returns a legitimate, >5KB minified script with normal
// identifiers (no obfuscation). It must NOT be classified as obfuscated.
func bigMinifiedJS() string {
	var b strings.Builder
	for i := 0; i < 200; i++ {
		b.WriteString(`function handleClick(event){var target=event.currentTarget;target.classList.toggle("active");return false;}`)
	}
	return b.String()
}

func TestIsObfuscatedScript_LegitimateNotFlagged(t *testing.T) {
	cases := map[string]string{
		"json-ld structured data": bigJSONLD(),
		"minified library code":   bigMinifiedJS(),
	}
	for name, script := range cases {
		if len(script) <= 5000 {
			t.Fatalf("%s: test fixture must be >5000 chars, got %d", name, len(script))
		}
		if isObfuscatedScript(script) {
			t.Errorf("%s (%d chars): flagged as obfuscated but is legitimate (false positive)", name, len(script))
		}
	}
}

func TestIsObfuscatedScript_RealThreatsStillCaught(t *testing.T) {
	packed := `eval(function(p,a,c,k,e,d){while(c--){if(k[c]){p=p.replace(new RegExp('\\b'+c+'\\b','g'),k[c])}}return p}('malicious',10,10,'x'.split(',')))`
	evalAtob := `var x=eval(atob("dmFyIGE9MTsgYWxlcnQoYSk7"));` + strings.Repeat("padding;", 700)
	hexHeavy := strings.Repeat(`\x61\x6c\x65\x72\x74`, 60)
	obfVars := strings.Repeat(`_0x3a2f1b;_0x4c8d;_0xff01;_0xab12;_0x9d3e;`, 10)

	cases := map[string]string{
		"packed p,a,c,k,e,d": packed,
		"eval(atob(...))":    evalAtob,
		"dense hex escapes":  hexHeavy,
		"_0x hashed vars":    obfVars,
	}
	for name, script := range cases {
		if !isObfuscatedScript(script) {
			t.Errorf("%s: genuine obfuscation NOT detected (regression — real malware would be missed)", name)
		}
	}
}

func TestIsTrustedHost_CloudflareInsightsTrusted(t *testing.T) {
	trusted := []string{
		"static.cloudflareinsights.com", // the exact host that produced the false positive
		"cloudflareinsights.com",
		"secure.gravatar.com",
		"s0.wp.com",
		"kit.fontawesome.com",
	}
	for _, h := range trusted {
		if !isTrustedHost(h) {
			t.Errorf("%q should be trusted but is not", h)
		}
	}

	// Genuinely untrusted hosts must still be rejected (no over-broadening).
	untrusted := []string{"evil-tracker.tk", "sketchy-cdn.xyz", "random-host.top"}
	for _, h := range untrusted {
		if isTrustedHost(h) {
			t.Errorf("%q should NOT be trusted", h)
		}
	}
}
