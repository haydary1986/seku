package scanner

// GraphQL Scanner
// -----------------------------------------------------------------------------
// Detects exposed GraphQL endpoints and, critically, whether schema
// INTROSPECTION is enabled in production. Open introspection hands an attacker
// the complete API map (types, queries, mutations) and is a common, high-value
// finding on Frappe/ERPNext-style and modern SPA backends.

import (
	"io"
	"net/http"
	"strings"
	"time"

	"seku/internal/models"
)

type GraphQLScanner struct{}

func NewGraphQLScanner() *GraphQLScanner { return &GraphQLScanner{} }

func (s *GraphQLScanner) Name() string     { return "GraphQL Security Scanner" }
func (s *GraphQLScanner) Category() string { return "graphql" }
func (s *GraphQLScanner) Weight() float64  { return 8.0 }

func (s *GraphQLScanner) Scan(rawURL string) []models.CheckResult {
	base := strings.TrimRight(ensureHTTPS(rawURL), "/")
	client := &http.Client{Timeout: 12 * time.Second, Transport: ScanTransport}
	introspection := `{"query":"query{__schema{queryType{name}}}"}`

	paths := []string{"/graphql", "/api/graphql", "/v1/graphql", "/graphql/v1", "/query", "/graphiql", "/graphql/console", "/api/method/graphql"}

	for _, p := range paths {
		u := base + p
		req, err := http.NewRequest("POST", u, strings.NewReader(introspection))
		if err != nil {
			continue
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("User-Agent", "Seku-GraphQL/1.0")
		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 16*1024))
		resp.Body.Close()
		bs := string(body)

		// Require a real GraphQL JSON response shape (data.__schema.queryType), not
		// a raw substring — a soft-404/error handler that reflects our POSTed query
		// back contains "__schema"/"queryType" without ever executing it.
		ct := strings.ToLower(resp.Header.Get("Content-Type"))
		introspected := strings.Contains(bs, "\"__schema\"") && strings.Contains(bs, "\"queryType\"") &&
			strings.Contains(bs, "\"data\"") && strings.Contains(ct, "json")
		if resp.StatusCode == 200 && introspected {
			return []models.CheckResult{{
				Category:   s.Category(),
				CheckName:  "GraphQL Introspection Enabled",
				Weight:     8.0,
				Status:     "fail",
				Score:      350,
				Severity:   "medium",
				Confidence: 90,
				OWASP:      "A05:2021 - Security Misconfiguration",
				Details: toJSON(map[string]string{
					"message":  "GraphQL introspection is enabled at " + p + ", exposing the full API schema (all types, queries, and mutations) to attackers. Disable introspection in production.",
					"endpoint": u,
					"fix":      "Disable schema introspection in your GraphQL server configuration for production environments.",
				}),
			}}
		}
		// Endpoint responds like GraphQL but introspection is blocked → good.
		if resp.StatusCode < 500 && (strings.Contains(bs, "\"data\"") || strings.Contains(bs, "\"errors\"")) {
			return []models.CheckResult{{
				Category:   s.Category(),
				CheckName:  "GraphQL Endpoint",
				Weight:     4.0,
				Status:     "pass",
				Score:      1000,
				Severity:   "info",
				Confidence: 75,
				Details: toJSON(map[string]string{
					"message":  "GraphQL endpoint found at " + p + " with introspection disabled (good).",
					"endpoint": u,
				}),
			}}
		}
	}

	return []models.CheckResult{{
		Category:  s.Category(),
		CheckName: "GraphQL Endpoint",
		Weight:    2.0,
		Status:    "pass",
		Score:     1000,
		Severity:  "info",
		Details:   toJSON(map[string]string{"message": "No public GraphQL endpoint detected."}),
	}}
}
