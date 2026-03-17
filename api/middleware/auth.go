package middleware

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"os"
	"strings"

	"github.com/gin-gonic/gin"
)

// tokenFromCredentials genera un token determinista a partir
// de usuario + secreto. Sin base de datos, sin expiración compleja:
// para una herramienta de trabajo de un solo usuario es suficiente.
func TokenFromCredentials(username string) string {
	secret := os.Getenv("VULNCORE_SECRET")
	if secret == "" {
		secret = "vulncore-default-secret"
	}
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(username))
	return hex.EncodeToString(mac.Sum(nil))
}

// RequireAuth es el middleware que protege todas las rutas /api/*.
func RequireAuth() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Excluir rutas públicas
		path := c.Request.URL.Path
		if path == "/api/auth/login" || path == "/api/health" {
			c.Next()
			return
		}

		auth := c.GetHeader("Authorization")
		if !strings.HasPrefix(auth, "Bearer ") {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"error": "Missing or invalid Authorization header",
			})
			return
		}

		token := strings.TrimPrefix(auth, "Bearer ")
		username := os.Getenv("VULNCORE_USERNAME")
		if username == "" {
			username = "admin"
		}

		expected := TokenFromCredentials(username)
		if !hmac.Equal([]byte(token), []byte(expected)) {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"error": "Invalid token",
			})
			return
		}

		c.Next()
	}
}