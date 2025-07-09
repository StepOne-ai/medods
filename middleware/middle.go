package middleware

import (
	"context"
	"fmt"
	"net/http"
	"os"

	"github.com/StepOne-ai/medods/database"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v4"
)

func AuthMiddleware() gin.HandlerFunc {
	var jwtSecret = []byte(os.Getenv("JWT_SECRET"))
	if len(jwtSecret) == 0 {
		jwtSecret = []byte("somedefaultkey")
	}

	return func(c *gin.Context) {
		authHeader := c.Request.Header.Get("Authorization")
		if authHeader == "" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Отсутствует заголовок авторизации"})
		}

		tokenStr := authHeader[len("Bearer "):] // Все после Bearer
		token, err := jwt.Parse(tokenStr, func(token *jwt.Token) (any, error) {
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("ошибочный метод входа: %v", token.Header["alg"])
			}
			return jwtSecret, nil
		})

		if err != nil || !token.Valid {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid token"})
            c.Abort()
            return
		}

		claims, ok := token.Claims.(jwt.MapClaims)
        if !ok {
            c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid token claims"})
            c.Abort()
            return
        }

		accessToken := claims["access_token"].(string)
		if accessToken == "" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid access token"})
			c.Abort()
			return
		}

		var parsedClaims jwt.MapClaims
		token, err = jwt.ParseWithClaims(accessToken, &parsedClaims, func(token *jwt.Token) (any, error) {
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("invalid signing method: %v", token.Header["alg"])
			}
			return jwtSecret, nil
		})
		if err != nil || !token.Valid {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid access token"})
			c.Abort()
			return
		}
				
		userGUID, ok := parsedClaims["guid"].(string)
		if !ok || userGUID == "" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid user GUID type"})
			c.Abort()
			return
		}

		user, err := database.GetUserByGUID(context.Background(), userGUID)
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid user GUID"})
			c.Abort()
			return
		}

		if user.HashedRefreshToken != "" {
			c.Set("user_guid", userGUID)
		}
        c.Next()
	}
}