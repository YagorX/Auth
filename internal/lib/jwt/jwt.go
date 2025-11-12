package jwt

import (
	"sso/internal/domain/models"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func NewToken(user models.User, app models.App, duration time.Duration) (string, error) {
	token := jwt.New(jwt.SigningMethodHS256)

	// claims := token.Claims.(jwt.MapClaims)
	// claims["uid"] = user.ID
	// claims["email"] = user.Email
	// claims["exp"] = time.Now().Add(duration).Unix()
	// claims["app_id"] = app.ID

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
