package handlers

import (
	"net/http"
	"os"

	"github.com/gin-gonic/gin"
	"github.com/vulncore/api/middleware"
)

type AuthHandler struct{}

func NewAuthHandler() *AuthHandler { return &AuthHandler{} }

type LoginRequest struct {
	Username string `json:"username" binding:"required"`
	Password string `json:"password" binding:"required"`
}

// Login valida credenciales y devuelve el token de acceso.
func (h *AuthHandler) Login(c *gin.Context) {
	var req LoginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	expectedUser := os.Getenv("VULNCORE_USERNAME")
	if expectedUser == "" {
		expectedUser = "admin"
	}
	expectedPass := os.Getenv("VULNCORE_PASSWORD")
	if expectedPass == "" {
		c.JSON(http.StatusServiceUnavailable, gin.H{
			"error": "VULNCORE_PASSWORD not configured — set it in env or docker-compose",
		})
		return
	}

	if req.Username != expectedUser || req.Password != expectedPass {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid credentials"})
		return
	}

	token := middleware.TokenFromCredentials(req.Username)
	c.JSON(http.StatusOK, gin.H{
		"token":    token,
		"username": req.Username,
	})
}

// Me devuelve el usuario actual (para validar token desde el frontend).
func (h *AuthHandler) Me(c *gin.Context) {
	username := os.Getenv("VULNCORE_USERNAME")
	if username == "" {
		username = "admin"
	}
	c.JSON(http.StatusOK, gin.H{"username": username, "authenticated": true})
}