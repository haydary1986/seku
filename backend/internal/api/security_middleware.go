package api

import (
	"net/url"
	"strings"

	"github.com/gofiber/fiber/v2"

	"seku/internal/config"
	"seku/internal/models"
)

// csrfProtection validates Origin/Referer headers on state-changing requests (POST/PUT/DELETE).
// This prevents cross-site request forgery by ensuring requests originate from allowed origins.
func csrfProtection() fiber.Handler {
	return func(c *fiber.Ctx) error {
		method := c.Method()
		// Only check state-changing methods
		if method == "GET" || method == "HEAD" || method == "OPTIONS" {
			return c.Next()
		}

		// Skip CSRF check for API key authenticated requests
		if c.Get("X-API-Key") != "" {
			return c.Next()
		}

		// Skip for login/register (no session yet)
		path := c.Path()
		if strings.HasPrefix(path, "/api/auth/login") || strings.HasPrefix(path, "/api/auth/register") {
			return c.Next()
		}

		origin := c.Get("Origin")
		referer := c.Get("Referer")

		// If neither header is present, allow (non-browser clients like curl/Postman)
		if origin == "" && referer == "" {
			return c.Next()
		}

		// Validate origin against the request host
		host := c.Hostname()
		if origin != "" {
			parsed, err := url.Parse(origin)
			if err == nil && parsed.Hostname() == host {
				return c.Next()
			}
		}

		if referer != "" {
			parsed, err := url.Parse(referer)
			if err == nil && parsed.Hostname() == host {
				return c.Next()
			}
		}

		// In development (localhost), allow any origin
		if strings.Contains(host, "localhost") || strings.Contains(host, "127.0.0.1") {
			return c.Next()
		}

		return c.Status(403).JSON(fiber.Map{"error": "CSRF validation failed: origin mismatch"})
	}
}

// auditMiddleware logs state-changing operations (POST/PUT/DELETE) to the audit_logs table.
func auditMiddleware() fiber.Handler {
	return func(c *fiber.Ctx) error {
		method := c.Method()

		// Only audit state-changing methods
		if method == "GET" || method == "HEAD" || method == "OPTIONS" {
			return c.Next()
		}

		// Execute the handler first
		err := c.Next()

		// Log the action after successful completion (2xx status)
		status := c.Response().StatusCode()
		if status >= 200 && status < 300 {
			userID, _ := c.Locals("user_id").(uint)
			if userID > 0 {
				action := mapMethodToAction(method)
				path := c.Path()
				resourceType := extractResourceType(path)

				audit := models.AuditLog{
					OrganizationID: GetUserOrgID(c),
					UserID:         userID,
					Action:         action + "." + resourceType,
					ResourceType:   resourceType,
					Details:        method + " " + path,
					IPAddress:      c.IP(),
					UserAgent:      c.Get("User-Agent"),
				}
				config.DB.Create(&audit)
			}
		}

		return err
	}
}

func mapMethodToAction(method string) string {
	switch method {
	case "POST":
		return "create"
	case "PUT":
		return "update"
	case "DELETE":
		return "delete"
	default:
		return "action"
	}
}

func extractResourceType(path string) string {
	// /api/targets/123 -> "target"
	// /api/scans/start -> "scan"
	parts := strings.Split(strings.TrimPrefix(path, "/api/"), "/")
	if len(parts) > 0 {
		name := parts[0]
		// Singularize common resource names
		name = strings.TrimSuffix(name, "s")
		return name
	}
	return "unknown"
}
