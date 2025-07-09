package database

import (
	"context"
	"crypto/rand"
	"fmt"

	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
)

type User struct {
    ID                 int    `json:"id"`
    GUID               string `json:"guid"`
    HashedRefreshToken string `json:"hashed_refresh_token"`
}

type UserAgent struct {
	ID         int    `json:"id"`
	UserGUID   string `json:"user_guid"`
	UserAgent  string `json:"user_agent"`
	LastIP     string `json:"last_ip"`
}

func generateGUID() (string, error) {
	return uuid.New().String(), nil
}

func GenerateRefreshToken() (string, error) {
    token := make([]byte, 32)
    _, err := rand.Read(token)
    return string(token), err
}

func HashRefreshToken(token string) (string, error) {
    hashedToken, err := bcrypt.GenerateFromPassword([]byte(token), bcrypt.DefaultCost)
    if err != nil {
        return "", err
    }
    return string(hashedToken), nil
}

func CreateUser() (*User, string, error) {
    var user User
    var refreshToken string
    var err error

    user.GUID, err = generateGUID()
	if err != nil {
		return nil, "", err
	}

    refreshToken, err = GenerateRefreshToken()
    if err != nil {
        return nil, "", err
    }
    hashedToken, err := HashRefreshToken(refreshToken)
    if err != nil {
        return nil, "", err
    }

    query := "INSERT INTO users (guid, hashed_refresh_token) VALUES ($1, $2) RETURNING id"
    err = DB.QueryRow(context.Background(), query, user.GUID, hashedToken).Scan(&user.ID)
    if err != nil {
        return nil, "", err
    }

    return &user, refreshToken, nil
}

func VerifyRefreshToken(guid, token string, ctx context.Context) bool {
    user, err := GetUserByGUID(ctx, guid)
    if err != nil {
        return false
    }

    err = bcrypt.CompareHashAndPassword([]byte(user.HashedRefreshToken), []byte(token))
    return err == nil
}

// GetUserByGUID получает пользователя по GUID
func GetUserByGUID(ctx context.Context, guid string) (*User, error) {
    query := "SELECT id, guid, hashed_refresh_token FROM users WHERE guid = $1 limit 1"
    var user User
    err := DB.QueryRow(ctx, query, guid).Scan(&user.ID, &user.GUID, &user.HashedRefreshToken)
    if err != nil {
        return nil, fmt.Errorf("failed to get user by GUID: %w", err)
    }
    return &user, nil
}

// UpdateRefreshToken обновляет хэш refresh токена для пользователя
func UpdateRefreshToken(guid string, newHashed string) (string, error) {
	query := "UPDATE users SET hashed_refresh_token = $1 WHERE guid = $2 RETURNING guid"
	var GUID string
	err := DB.QueryRow(context.Background(), query, newHashed, guid).Scan(&GUID)
	return GUID, err
}

func CheckUserGUID(guid string) (bool, error) {
    query := "SELECT EXISTS(SELECT 1 FROM users WHERE guid = $1)"
    var exists bool
    err := DB.QueryRow(context.Background(), query, guid).Scan(&exists)
    return exists, err
}

func GetUserByRefreshToken(hashedRefreshToken string) (*User, error) {
    query := "SELECT id, guid, hashed_refresh_token FROM users WHERE hashed_refresh_token = $1"
    var user User
    err := DB.QueryRow(context.Background(), query, hashedRefreshToken).Scan(&user.ID, &user.GUID, &user.HashedRefreshToken)
    if err != nil {
        return nil, err
    }
    return &user, nil
}

func UpdateOrInsertUserAgent(userGUID, userAgent, lastIP string) error {
    query := `
        INSERT INTO user_agents (user_guid, user_agent, last_ip)
        VALUES ($1, $2, $3)
        ON CONFLICT (user_guid)
        DO UPDATE SET user_agent = EXCLUDED.user_agent, last_ip = EXCLUDED.last_ip
    `
    _, err := DB.Exec(context.Background(), query, userGUID, userAgent, lastIP)
    if err != nil {
        return fmt.Errorf("failed to update or insert user agent: %w", err)
    }
    return nil
}

func GetUserAgentAndLastIP(userGUID string) (*UserAgent, error) {
	query := "SELECT id, user_guid, user_agent, last_ip FROM user_agents WHERE user_guid = $1"
	var userAgent UserAgent
	err := DB.QueryRow(context.Background(), query, userGUID).Scan(&userAgent.ID, &userAgent.UserGUID, &userAgent.UserAgent, &userAgent.LastIP)
	return &userAgent, err
}