package scanner

// OSINT (passive reconnaissance) module.
// ---------------------------------------------------------------------------
// Gathers open-source intelligence about a domain WITHOUT actively scanning the
// target's application: DNS records, RDAP/WHOIS, certificate-transparency
// subdomains + certificates, resolved IPs with ASN/hosting, e-mail security
// posture (SPF/DMARC), and public breach exposure. All outbound calls go through
// the SSRF-guarded client. This is reconnaissance, not exploitation.

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"sort"
	"strings"
	"time"

	"seku/internal/safehttp"
)

func newOSINTRequest(url string) (*http.Request, error) {
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; SekuOSINT/1.0; +https://sec.erticaz.com)")
	req.Header.Set("Accept", "application/json")
	return req, nil
}

type OSINTReport struct {
	Domain        string            `json:"domain"`
	GeneratedAt   string            `json:"generated_at"`
	DNS           OSINTDns          `json:"dns"`
	Whois         OSINTWhois        `json:"whois"`
	IPs           []OSINTIP         `json:"ips"`
	Subdomains    []string          `json:"subdomains"`
	Certificates  []OSINTCert       `json:"certificates"`
	EmailSecurity OSINTEmail        `json:"email_security"`
	Breaches      []OSINTBreach     `json:"breaches"`
	Highlights    []OSINTHighlight  `json:"highlights"` // notable, human-facing signals
	Errors        map[string]string `json:"errors,omitempty"`
}

type OSINTDns struct {
	A     []string `json:"a"`
	AAAA  []string `json:"aaaa"`
	MX    []string `json:"mx"`
	NS    []string `json:"ns"`
	TXT   []string `json:"txt"`
	CNAME string   `json:"cname,omitempty"`
}

type OSINTWhois struct {
	Registrar   string   `json:"registrar"`
	CreatedAt   string   `json:"created_at"`
	ExpiresAt   string   `json:"expires_at"`
	UpdatedAt   string   `json:"updated_at"`
	Nameservers []string `json:"nameservers"`
	Statuses    []string `json:"statuses"`
}

type OSINTIP struct {
	IP      string `json:"ip"`
	ASN     string `json:"asn"`
	Org     string `json:"org"`
	Country string `json:"country"`
	ISP     string `json:"isp"`
}

type OSINTCert struct {
	Issuer    string `json:"issuer"`
	CommonName string `json:"common_name"`
	NotBefore string `json:"not_before"`
	NotAfter  string `json:"not_after"`
}

type OSINTEmail struct {
	SPF        string `json:"spf"`
	DMARC      string `json:"dmarc"`
	HasSPF     bool   `json:"has_spf"`
	HasDMARC   bool   `json:"has_dmarc"`
	DMARCPolicy string `json:"dmarc_policy"`
}

type OSINTBreach struct {
	Name       string `json:"name"`
	Domain     string `json:"domain"`
	BreachDate string `json:"breach_date"`
	PwnCount   int    `json:"pwn_count"`
}

type OSINTHighlight struct {
	Level string `json:"level"` // info, low, medium, high
	Text  string `json:"text"`
}

// RunOSINT performs passive reconnaissance on a bare domain (no scheme).
func RunOSINT(rawDomain string) OSINTReport {
	domain := normalizeOSINTDomain(rawDomain)
	rep := OSINTReport{
		Domain:      domain,
		GeneratedAt: time.Now().UTC().Format(time.RFC3339),
		Errors:      map[string]string{},
	}
	if domain == "" {
		rep.Errors["domain"] = "invalid domain"
		return rep
	}

	rep.DNS = osintDNS(domain, rep.Errors)
	rep.EmailSecurity = osintEmail(domain, rep.DNS.TXT)
	rep.Whois = osintWhois(domain, rep.Errors)
	rep.IPs = osintIPs(rep.DNS.A, rep.Errors)
	rep.Subdomains, rep.Certificates = osintCrtSh(domain, rep.Errors)
	rep.Breaches = osintBreaches(domain, rep.Errors)
	rep.Highlights = osintHighlights(&rep)
	if len(rep.Errors) == 0 {
		rep.Errors = nil
	}
	return rep
}

func normalizeOSINTDomain(s string) string {
	s = strings.TrimSpace(strings.ToLower(s))
	s = strings.TrimPrefix(s, "https://")
	s = strings.TrimPrefix(s, "http://")
	s = strings.TrimPrefix(s, "www.")
	if i := strings.IndexAny(s, "/:?"); i >= 0 {
		s = s[:i]
	}
	// crude validity check: must contain a dot and only host chars
	if !strings.Contains(s, ".") {
		return ""
	}
	for _, r := range s {
		if !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '.' || r == '-') {
			return ""
		}
	}
	return s
}

func osintDNS(domain string, errs map[string]string) OSINTDns {
	var d OSINTDns
	res := net.Resolver{}
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()

	if ips, err := res.LookupIPAddr(ctx, domain); err == nil {
		for _, ip := range ips {
			if ip.IP.To4() != nil {
				d.A = append(d.A, ip.IP.String())
			} else {
				d.AAAA = append(d.AAAA, ip.IP.String())
			}
		}
	}
	if mx, err := res.LookupMX(ctx, domain); err == nil {
		for _, m := range mx {
			d.MX = append(d.MX, strings.TrimSuffix(m.Host, "."))
		}
	}
	if ns, err := res.LookupNS(ctx, domain); err == nil {
		for _, n := range ns {
			d.NS = append(d.NS, strings.TrimSuffix(n.Host, "."))
		}
	}
	if txt, err := res.LookupTXT(ctx, domain); err == nil {
		d.TXT = txt
	}
	if cn, err := res.LookupCNAME(ctx, domain); err == nil {
		cn = strings.TrimSuffix(cn, ".")
		if cn != domain {
			d.CNAME = cn
		}
	}
	d.A = dedupeStrings(d.A)
	d.AAAA = dedupeStrings(d.AAAA)
	return d
}

func osintEmail(domain string, txt []string) OSINTEmail {
	var e OSINTEmail
	for _, t := range txt {
		if strings.HasPrefix(strings.ToLower(t), "v=spf1") {
			e.SPF = t
			e.HasSPF = true
		}
	}
	// DMARC lives at _dmarc.<domain>
	res := net.Resolver{}
	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Second)
	defer cancel()
	if dmarc, err := res.LookupTXT(ctx, "_dmarc."+domain); err == nil {
		for _, t := range dmarc {
			if strings.HasPrefix(strings.ToLower(t), "v=dmarc1") {
				e.DMARC = t
				e.HasDMARC = true
				for _, part := range strings.Split(t, ";") {
					part = strings.TrimSpace(strings.ToLower(part))
					if strings.HasPrefix(part, "p=") {
						e.DMARCPolicy = strings.TrimPrefix(part, "p=")
					}
				}
			}
		}
	}
	return e
}

// osintWhois queries RDAP (the modern WHOIS) over HTTPS.
func osintWhois(domain string, errs map[string]string) OSINTWhois {
	var w OSINTWhois
	body, err := osintGet("https://rdap.org/domain/" + domain)
	if err != nil {
		errs["whois"] = err.Error()
		return w
	}
	var r struct {
		Events []struct {
			Action string `json:"eventAction"`
			Date   string `json:"eventDate"`
		} `json:"events"`
		Status      []string `json:"status"`
		Nameservers []struct {
			LDHName string `json:"ldhName"`
		} `json:"nameservers"`
		Entities []struct {
			Roles      []string `json:"roles"`
			VCardArray []interface{} `json:"vcardArray"`
		} `json:"entities"`
	}
	if json.Unmarshal(body, &r) != nil {
		return w
	}
	for _, ev := range r.Events {
		switch strings.ToLower(ev.Action) {
		case "registration":
			w.CreatedAt = ev.Date
		case "expiration":
			w.ExpiresAt = ev.Date
		case "last changed", "last update of rdap database":
			w.UpdatedAt = ev.Date
		}
	}
	for _, ns := range r.Nameservers {
		w.Nameservers = append(w.Nameservers, strings.ToLower(ns.LDHName))
	}
	w.Statuses = r.Status
	for _, ent := range r.Entities {
		for _, role := range ent.Roles {
			if role == "registrar" {
				w.Registrar = vcardName(ent.VCardArray)
			}
		}
	}
	return w
}

// vcardName pulls the "fn" (full name) out of a jCard vcardArray.
func vcardName(v []interface{}) string {
	if len(v) < 2 {
		return ""
	}
	props, ok := v[1].([]interface{})
	if !ok {
		return ""
	}
	for _, p := range props {
		field, ok := p.([]interface{})
		if !ok || len(field) < 4 {
			continue
		}
		if name, _ := field[0].(string); name == "fn" {
			if val, ok := field[3].(string); ok {
				return val
			}
		}
	}
	return ""
}

func osintIPs(a []string, errs map[string]string) []OSINTIP {
	var out []OSINTIP
	seen := map[string]bool{}
	for _, ip := range a {
		if seen[ip] || len(out) >= 8 {
			continue
		}
		seen[ip] = true
		info := OSINTIP{IP: ip}
		if body, err := osintGet("https://ipapi.co/" + ip + "/json/"); err == nil {
			var r struct {
				ASN     string `json:"asn"`
				Org     string `json:"org"`
				Country string `json:"country_name"`
			}
			if json.Unmarshal(body, &r) == nil {
				info.ASN = r.ASN
				info.Org = r.Org
				info.ISP = r.Org
				info.Country = r.Country
			}
		}
		out = append(out, info)
	}
	return out
}

// osintCrtSh pulls subdomains + certificates from crt.sh certificate transparency.
func osintCrtSh(domain string, errs map[string]string) ([]string, []OSINTCert) {
	body, err := osintGet("https://crt.sh/?q=%25." + domain + "&output=json")
	if err != nil {
		errs["crtsh"] = err.Error()
		return nil, nil
	}
	var entries []struct {
		NameValue  string `json:"name_value"`
		IssuerName string `json:"issuer_name"`
		CommonName string `json:"common_name"`
		NotBefore  string `json:"not_before"`
		NotAfter   string `json:"not_after"`
	}
	if json.Unmarshal(body, &entries) != nil {
		return nil, nil
	}
	subSet := map[string]bool{}
	var certs []OSINTCert
	for _, e := range entries {
		for _, name := range strings.Split(e.NameValue, "\n") {
			name = strings.TrimSpace(strings.ToLower(name))
			name = strings.TrimPrefix(name, "*.")
			if name != "" && strings.HasSuffix(name, domain) {
				subSet[name] = true
			}
		}
		if len(certs) < 25 {
			certs = append(certs, OSINTCert{
				Issuer:     osintIssuerOrg(e.IssuerName),
				CommonName: e.CommonName,
				NotBefore:  e.NotBefore,
				NotAfter:   e.NotAfter,
			})
		}
	}
	subs := make([]string, 0, len(subSet))
	for s := range subSet {
		subs = append(subs, s)
	}
	sort.Strings(subs)
	if len(subs) > 500 {
		subs = subs[:500]
	}
	return subs, certs
}

func osintIssuerOrg(issuer string) string {
	for _, part := range strings.Split(issuer, ",") {
		part = strings.TrimSpace(part)
		if strings.HasPrefix(part, "O=") {
			return strings.TrimPrefix(part, "O=")
		}
	}
	return issuer
}

// osintBreaches lists public breaches affecting a domain (HIBP public endpoint).
func osintBreaches(domain string, errs map[string]string) []OSINTBreach {
	body, err := osintGet("https://haveibeenpwned.com/api/v3/breaches?domain=" + domain)
	if err != nil {
		return nil
	}
	var entries []struct {
		Name       string `json:"Name"`
		Domain     string `json:"Domain"`
		BreachDate string `json:"BreachDate"`
		PwnCount   int    `json:"PwnCount"`
	}
	if json.Unmarshal(body, &entries) != nil {
		return nil
	}
	var out []OSINTBreach
	for _, e := range entries {
		out = append(out, OSINTBreach{Name: e.Name, Domain: e.Domain, BreachDate: e.BreachDate, PwnCount: e.PwnCount})
	}
	return out
}

func osintHighlights(r *OSINTReport) []OSINTHighlight {
	var h []OSINTHighlight
	if !r.EmailSecurity.HasSPF {
		h = append(h, OSINTHighlight{"medium", "No SPF record — the domain is more spoofable in phishing."})
	}
	if !r.EmailSecurity.HasDMARC {
		h = append(h, OSINTHighlight{"medium", "No DMARC record — no policy against e-mail spoofing."})
	} else if p := r.EmailSecurity.DMARCPolicy; p == "none" || p == "" {
		h = append(h, OSINTHighlight{"low", "DMARC policy is 'none' (monitor only) — not enforcing."})
	}
	if n := len(r.Subdomains); n > 0 {
		lvl := "info"
		if n > 50 {
			lvl = "low"
		}
		h = append(h, OSINTHighlight{lvl, fmt.Sprintf("%d subdomains surfaced from certificate transparency — review the exposed attack surface.", n)})
	}
	if len(r.Breaches) > 0 {
		h = append(h, OSINTHighlight{"high", fmt.Sprintf("%d public breach(es) reference this domain — credential-stuffing risk.", len(r.Breaches))})
	}
	if r.Whois.ExpiresAt != "" {
		if t, err := time.Parse(time.RFC3339, r.Whois.ExpiresAt); err == nil && time.Until(t) < 30*24*time.Hour {
			h = append(h, OSINTHighlight{"high", "Domain registration expires within 30 days — renewal/hijack risk."})
		}
	}
	return h
}

// osintGet performs an SSRF-guarded GET and returns the body (bounded).
func osintGet(url string) ([]byte, error) {
	if !safehttp.IsSafeHost(url) {
		return nil, fmt.Errorf("blocked host")
	}
	client := safehttp.Client(12 * time.Second)
	req, err := newOSINTRequest(url)
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("http %d", resp.StatusCode)
	}
	return io.ReadAll(io.LimitReader(resp.Body, 4*1024*1024))
}

func dedupeStrings(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range in {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}
