package middleware

// github.com/pilinux/gorestlib
// The MIT License (MIT)
// Copyright (c) 2022 piLinux

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt"
	"github.com/google/uuid"
)

// variables for issuing or validating tokens
var (
	AccessKey     []byte
	AccessKeyTTL  int
	RefreshKey    []byte
	RefreshKeyTTL int

	Audience  string
	Issuer    string
	NotBefore int
	Subject   string
)

// MyCustomClaims ...
type MyCustomClaims struct {
	AuthID uint64 `json:"AuthID"`
	Email  string `json:"Email"`
	Role   string `json:"Role"`
	Scope  string `json:"Scope"`
	Custom string `json:"Custom"`
	jwt.StandardClaims
}

// user-related info for JWT
var (
	AuthID uint64
	Email  string
	Role   string
	Scope  string
	Custom string
)

// JWTPayload ...
type JWTPayload struct {
	AccessJWT  string `json:"AccessJWT"`
	RefreshJWT string `json:"RefreshJWT"`
}

// JWT - validate access token
func JWT() gin.HandlerFunc {
	return func(c *gin.Context) {
		val := c.Request.Header.Get("Authorization")
		if len(val) == 0 || !strings.Contains(val, "Bearer ") {
			// no vals or no bearer found
			c.AbortWithStatus(http.StatusUnauthorized)
			return
		}
		vals := strings.Split(val, " ")
		if len(vals) != 2 {
			c.AbortWithStatus(http.StatusUnauthorized)
			return
		}

		token, err := jwt.ParseWithClaims(vals[1], &MyCustomClaims{}, validateAccessJWT)

		if err != nil {
			// error parsing JWT
			c.AbortWithStatus(http.StatusUnauthorized)
			return
		}

		if claims, ok := token.Claims.(*MyCustomClaims); ok && token.Valid {
			AuthID = claims.AuthID
			Email = claims.Email
			Role = claims.Role
			Scope = claims.Scope
			Custom = claims.Custom
		}
	}
}

// RefreshJWT - validate refresh token
func RefreshJWT() gin.HandlerFunc {
	return func(c *gin.Context) {
		var jwtPayload JWTPayload
		if err := c.ShouldBindJSON(&jwtPayload); err != nil {
			c.AbortWithStatus(http.StatusBadRequest)
			return
		}

		token, err := jwt.ParseWithClaims(jwtPayload.RefreshJWT, &MyCustomClaims{}, validateRefreshJWT)
		if err != nil {
			c.AbortWithStatus(http.StatusUnauthorized)
			return
		}

		if claims, ok := token.Claims.(*MyCustomClaims); ok && token.Valid {
			AuthID = claims.AuthID
			Email = claims.Email
			Role = claims.Role
			Scope = claims.Scope
			Custom = claims.Custom
		}
	}
}

// validateAccessJWT ...
func validateAccessJWT(token *jwt.Token) (interface{}, error) {
	if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
		return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
	}
	return AccessKey, nil
}

// validateRefreshJWT ...
func validateRefreshJWT(token *jwt.Token) (interface{}, error) {
	if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
		return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
	}
	return RefreshKey, nil
}

// GetJWT - issue new tokens
func GetJWT(id uint64, email, role, scope, customClaim, tokenType string) (string, error) {
	var (
		key []byte
		ttl int
	)

	if tokenType == "access" {
		key = AccessKey
		ttl = AccessKeyTTL
	}
	if tokenType == "refresh" {
		key = RefreshKey
		ttl = RefreshKeyTTL
	}
	// Create the Claims
	claims := MyCustomClaims{
		id,
		email,
		role,
		scope,
		customClaim,
		jwt.StandardClaims{
			Audience:  Audience,
			ExpiresAt: time.Now().Add(time.Minute * time.Duration(ttl)).Unix(),
			Id:        uuid.NewString(),
			IssuedAt:  time.Now().Unix(),
			Issuer:    Issuer,
			NotBefore: time.Now().Add(time.Minute * time.Duration(NotBefore)).Unix(),
			Subject:   Subject,
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	jwtValue, err := token.SignedString(key)
	if err != nil {
		return "", err
	}
	return jwtValue, nil
}
