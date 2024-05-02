package jwt

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/evgeniiburdin/gin_postgres_jwt_practice_1/pkg/models/postgres"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/joho/godotenv"
)

type JWTAuthMiddleware struct{}

type AuthMiddleware interface {
	GetJWTs(int, postgres.Storage) (string, string, error)
	ValidateRefreshToken(string, postgres.Storage) (int, error)
	InvalidateJWTs(int, string, postgres.Storage) error
	WithJWTAuth(postgres.Storage) gin.HandlerFunc
}

// FUNC FOR CREATING JWTs
func (am *JWTAuthMiddleware) GetJWTs(id int, s postgres.Storage) (string, string, error) {

	// Creating access JWT
	accessPayload := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"exp": (time.Now().Local().Add(time.Minute * 15)).Unix(),
		"sub": id,
		"typ": "access",
	})

	// Creating refresh JWT
	refreshPayload := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"exp": (time.Now().Local().Add(time.Hour)).Unix(),
		"sub": id,
		"typ": "refresh",
	})

	// Loading the keyword to sign tokens
	err := godotenv.Load()
	if err != nil {
		log.Fatalf("godotenv error: %v", err)
	}
	var key string = os.Getenv("jwt_key")
	if key == "" {
		log.Fatal("key not found")
	}

	// Signing access JWT
	accessToken, err := accessPayload.SignedString([]byte(key))
	if err != nil {
		return "", "", err
	}

	// Signing refresh JWT
	refreshToken, err := refreshPayload.SignedString([]byte(key))
	if err != nil {
		return "", "", err
	}

	// Writing refresh token to storage
	err = s.StorageUpdateJWT(id, refreshToken)
	if err != nil {
		return "", "", err
	}

	// Returning both access and refresh tokens
	return accessToken, refreshToken, nil
}

// FUNC FOR VALIDATING REFRESH TOKEN
func (am *JWTAuthMiddleware) ValidateRefreshToken(refreshToken string, s postgres.Storage) (int, error) {
	userID, err := s.StorageFindRT(refreshToken)
	if err != nil {
		return -1, err
	}
	return userID, nil
}

// FUNC FOR INVALIDATING JWTs
func (am *JWTAuthMiddleware) InvalidateJWTs(user_id int, accessToken string, s postgres.Storage) error {
	err := s.StorageBlacklistJWTs(user_id, accessToken)
	if err != nil {
		return err
	}
	return nil
}

// FUNC FOR VALIDATING ACCESS TOKEN
func (am *JWTAuthMiddleware) WithJWTAuth(s postgres.Storage) gin.HandlerFunc {
	return func(c *gin.Context) {

		// Loading the keyword to compare signatures
		err := godotenv.Load()
		if err != nil {
			log.Fatalf("godotenv error: %v", err)
		}

		// Getting access token from HTTP request header
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Missing authorization header"})
			c.Abort()
			return
		}
		parts := strings.Split(authHeader, " ")
		if len(parts) != 2 || parts[0] != "Bearer" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid authorization header format"})
			c.Abort()
			return
		}

		// Parsing into JWT structure
		token, err := jwt.Parse(parts[1], func(token *jwt.Token) (interface{}, error) {
			jwtKey := []byte(os.Getenv("jwt_key"))
			if jwtKey == nil {
				return nil, fmt.Errorf("JWT secret key not configured")
			}
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
			}
			return jwtKey, nil
		})
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Failed to parse JWT token: " + err.Error()})
			c.Abort()
			return
		}

		// Checking if the token valid
		if !token.Valid {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid JWT token"})
			c.Abort()
			return
		}

		// Retrieving token claims
		claims, ok := token.Claims.(jwt.MapClaims)
		if !ok {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Failed to extract claims from JWT token"})
			c.Abort()
			return
		}

		// Checking if the token is an access token
		if claims["typ"] != "access" {
			c.JSON(http.StatusNotAcceptable, gin.H{"error": "Not an access token"})
			c.Abort()
			return
		}

		// Checking if the token is in the blacklist
		blacklisted, err := s.StorageJWTCheckBlacklisted(parts[1])
		if err != nil {
			c.JSON(http.StatusNotAcceptable, gin.H{"error": err})
			c.Abort()
			return
		}
		if blacklisted {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "jwt blacklisted"})
			c.Abort()
			return
		}

		// Going to the next handler, providing with userID from claims and the token itself
		userID := int(claims["sub"].(float64))
		c.Set("user", userID)
		c.Set("accessToken", parts[1])

		c.Next()
	}
}
