package handler

import (
	"bytes"
	"context"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/StepOne-ai/medods/database"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v4"
)

type User struct {
	GUID string `json:"guid"`
}

type TokenPair struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
}

func generateJWT(user database.User) (string, error) {
	var jwtSecret = []byte(os.Getenv("JWT_SECRET"))
	if len(jwtSecret) == 0 {
		jwtSecret = []byte("somedefaultkey")
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS512, jwt.MapClaims{
        "guid":    user.GUID,
        "exp":     time.Now().Add(15 * time.Minute).Unix(),
        "issuedAt": time.Now().Unix(),
    })
    return token.SignedString(jwtSecret)
}

func hashRefreshToken(refreshToken string) string {
    hash := sha512.Sum512([]byte(refreshToken))
    return base64.StdEncoding.EncodeToString(hash[:])
}

func LoginHandler(c *gin.Context) {
	var user User
	if err := c.ShouldBindJSON(&user); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request body"})
		return
	}

	found_user, err := database.GetUserByGUID(context.Background(), user.GUID)
	fmt.Println("found_user", found_user)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		return
	}

	accessToken, err := generateJWT(*found_user)
    if err != nil {
        c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
        return
    }
	
	refreshToken := base64.StdEncoding.EncodeToString([]byte(user.GUID + "-refresh"))
    hashedRefreshToken := hashRefreshToken(refreshToken)

	_, err = database.UpdateRefreshToken(user.GUID, hashedRefreshToken)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update refresh token"})
		return
	}

	userAgent := c.Request.UserAgent()
	currentIP := c.ClientIP()

	err = database.UpdateOrInsertUserAgent(user.GUID, userAgent, currentIP)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, TokenPair{
        AccessToken:  accessToken,
        RefreshToken: refreshToken,
    })
}

func RefreshHandler(c *gin.Context) {
	userAgent := c.Request.UserAgent()
	currentIP := c.ClientIP()

	guid, ok := c.Get("user_guid")
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "No user guid set"})
		return
	}

	receivedUserAgent, err := database.GetUserAgentAndLastIP(guid.(string))
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	if receivedUserAgent.UserAgent != userAgent || receivedUserAgent.LastIP != currentIP {
		sendWebhook(currentIP, guid.(string))
	}
	
    refreshToken := c.GetHeader("Refresh")
	if refreshToken == "" {
        c.JSON(http.StatusUnauthorized, gin.H{"error": "Missing refresh token"})
        return
    }

    user, err := database.GetUserByGUID(context.Background(), guid.(string))
    if err != nil {
        c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid guid set"})
        return
    }

	if user.HashedRefreshToken != hashRefreshToken(refreshToken) {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid refresh token"})
		return
	}

    newAccessToken, err := generateJWT(*user)
    if err != nil {
        c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
        return
    }

    newRefreshToken := base64.StdEncoding.EncodeToString([]byte(user.HashedRefreshToken + "-refresh"))
    hashedNewRefreshToken := hashRefreshToken(newRefreshToken)

    database.UpdateRefreshToken(user.GUID, hashedNewRefreshToken)

    c.JSON(http.StatusOK, TokenPair{
        AccessToken:  newAccessToken,
        RefreshToken: newRefreshToken,
    })
}

func MeHandler(c *gin.Context) {
    user_guid, ok := c.Get("user_guid")
	if !ok  || user_guid == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "User not found"})
		return
	}

	c.JSON(http.StatusOK, User{GUID: user_guid.(string)})
}

func LogoutHandler(c *gin.Context) {
	user_guid, ok := c.Get("user_guid")
    if !ok {
        c.JSON(http.StatusUnauthorized, gin.H{"error": "User not found"})
        return
    }

	c.Set("user_guid", nil)
	
	_, err := database.UpdateRefreshToken(user_guid.(string), "")
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to revoke refresh token"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Logout successful"})
}

func sendWebhook(ip, guid string) {
    webhookURL := os.Getenv("WEBHOOK_URL")
    payload := map[string]string{
        "guid": guid,
        "ip":   ip,
    }

    jsonPayload, _ := json.Marshal(payload)
    resp, err := http.Post(webhookURL, "application/json", bytes.NewBuffer(jsonPayload))
    if err != nil {
        log.Printf("Webhook failed: %v", err)
    }
    defer resp.Body.Close()
}