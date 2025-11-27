package jwt

import (
	"errors"
	"fmt"
	"sso/internal/domain/models"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func NewToken(user models.User, app models.App, duration time.Duration) (string, error) {
	token := jwt.New(jwt.SigningMethodHS256)

	// запись данных которые будут передаваться
	claims := jwt.MapClaims{
		"uid":    user.ID,
		"email":  user.Email,
		"exp":    time.Now().Add(duration).Unix(),
		"app_id": app.ID,
	}

	token.Claims = claims

	//подписываем токен
	tokenString, err := token.SignedString([]byte(app.Secret))
	if err != nil {
		return "", err
	}

	return tokenString, nil
}

func ParseToken(tokenString string, app models.App) (int64, error) {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(app.Secret), nil
	})

	if err != nil {
		return 0, err
	}

	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		userIDFloat, ok := claims["uid"].(float64)
		if !ok {
			return 0, errors.New("invalid user ID in token")
		}
		return int64(userIDFloat), nil
	}

	return 0, errors.New("invalid token")
}
