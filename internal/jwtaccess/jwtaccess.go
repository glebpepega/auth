package jwtaccess

import (
	"fmt"
	"os"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func Generate(guid string) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodHS512, jwt.MapClaims{
		"guid": guid,
		"exp":  time.Now().Add(time.Minute).Unix(),
	})

	return token.SignedString([]byte(os.Getenv("SECRET")))
}

func Parse(accessToken string) (jwt.MapClaims, error) {
	token, err := jwt.Parse(accessToken, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(os.Getenv("SECRET")), nil
	})
	if err != nil {
		return nil, fmt.Errorf("invalid access token")
	}
	return token.Claims.(jwt.MapClaims), nil
}
