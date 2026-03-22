package api

import (
	"os"
	"strings"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"

	"vscan-mohesr/internal/config"
	"vscan-mohesr/internal/models"
)

var jwtSecret []byte

func init() {
	secret := os.Getenv("JWT_SECRET")
	if secret == "" {
		secret = "vscan-mohesr-secret-change-in-production"
	}
	jwtSecret = []byte(secret)
}

type RegisterRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
	FullName string `json:"full_name"`
	Email    string `json:"email"`
	Phone    string `json:"phone"`
	OrgName  string `json:"org_name"`
	OrgType  string `json:"org_type"` // university, government, company, other
	Country  string `json:"country"`
}

type RegisterResponse struct {
	Token        string              `json:"token"`
	User         models.User         `json:"user"`
	Organization models.Organization `json:"organization"`
}

type LoginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type LoginResponse struct {
	Token string      `json:"token"`
	User  models.User `json:"user"`
}

func Login(c *fiber.Ctx) error {
	var req LoginRequest
	if err := c.BodyParser(&req); err != nil {
		return c.Status(400).JSON(fiber.Map{"error": "Invalid request"})
	}

	var user models.User
	if err := config.DB.Where("username = ?", req.Username).First(&user).Error; err != nil {
		return c.Status(401).JSON(fiber.Map{"error": "Invalid username or password"})
	}

	if !user.IsActive {
		return c.Status(403).JSON(fiber.Map{"error": "Account is disabled"})
	}

	if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(req.Password)); err != nil {
		return c.Status(401).JSON(fiber.Map{"error": "Invalid username or password"})
	}

	// Generate JWT
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"user_id":  user.ID,
		"username": user.Username,
		"role":     user.Role,
		"exp":      time.Now().Add(72 * time.Hour).Unix(),
	})

	tokenString, err := token.SignedString(jwtSecret)
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "Failed to generate token"})
	}

	return c.JSON(LoginResponse{
		Token: tokenString,
		User:  user,
	})
}

func Register(c *fiber.Ctx) error {
	var req RegisterRequest
	if err := c.BodyParser(&req); err != nil {
		return c.Status(400).JSON(fiber.Map{"error": "Invalid request"})
	}

	// Validate required fields
	if req.Username == "" || req.Password == "" || req.Email == "" || req.OrgName == "" {
		return c.Status(400).JSON(fiber.Map{"error": "Username, password, email, and organization name are required"})
	}

	if len(req.Password) < 6 {
		return c.Status(400).JSON(fiber.Map{"error": "Password must be at least 6 characters"})
	}

	// Check username not taken
	var existing models.User
	if config.DB.Where("username = ?", req.Username).First(&existing).Error == nil {
		return c.Status(409).JSON(fiber.Map{"error": "Username already exists"})
	}

	// Check email not taken
	var existingEmail models.User
	if config.DB.Where("email = ?", req.Email).First(&existingEmail).Error == nil {
		return c.Status(409).JSON(fiber.Map{"error": "Email already registered"})
	}

	// Hash password
	hashed, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "Failed to hash password"})
	}

	// Generate slug from org name
	slug := strings.ToLower(strings.ReplaceAll(req.OrgName, " ", "-"))
	// Ensure slug is unique
	var slugCount int64
	config.DB.Model(&models.Organization{}).Where("slug = ?", slug).Count(&slugCount)
	if slugCount > 0 {
		slug = slug + "-" + time.Now().Format("20060102150405")
	}

	// Create Organization with free plan
	org := models.Organization{
		Name:       req.OrgName,
		Slug:       slug,
		Plan:       "free",
		MaxTargets: 5,
		MaxScans:   10,
		IsActive:   true,
	}
	if err := config.DB.Create(&org).Error; err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "Failed to create organization"})
	}

	// Create User with role="admin" (admin of their org, not system admin)
	user := models.User{
		Username: req.Username,
		Password: string(hashed),
		FullName: req.FullName,
		Email:    req.Email,
		Role:     "user",
		IsActive: true,
	}
	if err := config.DB.Create(&user).Error; err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "Failed to create user"})
	}

	// Create OrgMembership with role="owner"
	membership := models.OrgMembership{
		UserID:         user.ID,
		OrganizationID: org.ID,
		Role:           "owner",
	}
	config.DB.Create(&membership)

	// Generate JWT token
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"user_id":  user.ID,
		"username": user.Username,
		"role":     user.Role,
		"exp":      time.Now().Add(72 * time.Hour).Unix(),
	})

	tokenString, err := token.SignedString(jwtSecret)
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "Failed to generate token"})
	}

	return c.Status(201).JSON(RegisterResponse{
		Token:        tokenString,
		User:         user,
		Organization: org,
	})
}

func GetMyOrganization(c *fiber.Ctx) error {
	userID := c.Locals("user_id").(uint)
	var membership models.OrgMembership
	if err := config.DB.Where("user_id = ?", userID).First(&membership).Error; err != nil {
		return c.Status(404).JSON(fiber.Map{"error": "No organization found"})
	}
	var org models.Organization
	if err := config.DB.First(&org, membership.OrganizationID).Error; err != nil {
		return c.Status(404).JSON(fiber.Map{"error": "Organization not found"})
	}
	return c.JSON(org)
}

func GetProfile(c *fiber.Ctx) error {
	userID := c.Locals("user_id").(uint)
	var user models.User
	if err := config.DB.First(&user, userID).Error; err != nil {
		return c.Status(404).JSON(fiber.Map{"error": "User not found"})
	}
	return c.JSON(user)
}

func ChangePassword(c *fiber.Ctx) error {
	userID := c.Locals("user_id").(uint)

	var req struct {
		OldPassword string `json:"old_password"`
		NewPassword string `json:"new_password"`
	}
	if err := c.BodyParser(&req); err != nil {
		return c.Status(400).JSON(fiber.Map{"error": "Invalid request"})
	}

	var user models.User
	if err := config.DB.First(&user, userID).Error; err != nil {
		return c.Status(404).JSON(fiber.Map{"error": "User not found"})
	}

	if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(req.OldPassword)); err != nil {
		return c.Status(401).JSON(fiber.Map{"error": "Old password is incorrect"})
	}

	hashed, err := bcrypt.GenerateFromPassword([]byte(req.NewPassword), bcrypt.DefaultCost)
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "Failed to hash password"})
	}

	config.DB.Model(&user).Update("password", string(hashed))
	return c.JSON(fiber.Map{"message": "Password changed successfully"})
}

// --- Admin: User Management ---

func GetUsers(c *fiber.Ctx) error {
	var users []models.User
	config.DB.Order("created_at desc").Find(&users)
	return c.JSON(users)
}

func CreateUser(c *fiber.Ctx) error {
	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
		FullName string `json:"full_name"`
		Email    string `json:"email"`
		Role     string `json:"role"`
	}
	if err := c.BodyParser(&req); err != nil {
		return c.Status(400).JSON(fiber.Map{"error": "Invalid request"})
	}

	if req.Username == "" || req.Password == "" {
		return c.Status(400).JSON(fiber.Map{"error": "Username and password are required"})
	}

	if req.Role == "" {
		req.Role = "user"
	}

	// Check if username exists
	var existing models.User
	if config.DB.Where("username = ?", req.Username).First(&existing).Error == nil {
		return c.Status(409).JSON(fiber.Map{"error": "Username already exists"})
	}

	hashed, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "Failed to hash password"})
	}

	user := models.User{
		Username: req.Username,
		Password: string(hashed),
		FullName: req.FullName,
		Email:    req.Email,
		Role:     req.Role,
		IsActive: true,
	}
	config.DB.Create(&user)
	return c.Status(201).JSON(user)
}

func UpdateUser(c *fiber.Ctx) error {
	id := c.Params("id")
	var user models.User
	if err := config.DB.First(&user, id).Error; err != nil {
		return c.Status(404).JSON(fiber.Map{"error": "User not found"})
	}

	var req struct {
		FullName string `json:"full_name"`
		Email    string `json:"email"`
		Role     string `json:"role"`
		IsActive *bool  `json:"is_active"`
		Password string `json:"password"`
	}
	if err := c.BodyParser(&req); err != nil {
		return c.Status(400).JSON(fiber.Map{"error": "Invalid request"})
	}

	if req.FullName != "" {
		user.FullName = req.FullName
	}
	if req.Email != "" {
		user.Email = req.Email
	}
	if req.Role != "" {
		user.Role = req.Role
	}
	if req.IsActive != nil {
		user.IsActive = *req.IsActive
	}
	if req.Password != "" {
		hashed, _ := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
		user.Password = string(hashed)
	}

	config.DB.Save(&user)
	return c.JSON(user)
}

func DeleteUser(c *fiber.Ctx) error {
	id := c.Params("id")
	var user models.User
	if err := config.DB.First(&user, id).Error; err != nil {
		return c.Status(404).JSON(fiber.Map{"error": "User not found"})
	}
	config.DB.Delete(&user)
	return c.JSON(fiber.Map{"message": "User deleted"})
}

// --- JWT Middleware ---

func AuthRequired() fiber.Handler {
	return func(c *fiber.Ctx) error {
		authHeader := c.Get("Authorization")
		if authHeader == "" {
			return c.Status(401).JSON(fiber.Map{"error": "Authorization header required"})
		}

		tokenString := strings.TrimPrefix(authHeader, "Bearer ")

		token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
			return jwtSecret, nil
		})
		if err != nil || !token.Valid {
			return c.Status(401).JSON(fiber.Map{"error": "Invalid or expired token"})
		}

		claims, ok := token.Claims.(jwt.MapClaims)
		if !ok {
			return c.Status(401).JSON(fiber.Map{"error": "Invalid token claims"})
		}

		c.Locals("user_id", uint(claims["user_id"].(float64)))
		c.Locals("username", claims["username"].(string))
		c.Locals("role", claims["role"].(string))

		return c.Next()
	}
}

func AdminRequired() fiber.Handler {
	return func(c *fiber.Ctx) error {
		role, ok := c.Locals("role").(string)
		if !ok || role != "admin" {
			return c.Status(403).JSON(fiber.Map{"error": "Admin access required"})
		}
		return c.Next()
	}
}
