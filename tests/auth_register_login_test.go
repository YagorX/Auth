package tests

import (
	"testing"
	"time"

	"sso/tests/suite"

	ssov1 "github.com/YagorX/protos/gen/go/sso"
	"github.com/brianvoe/gofakeit/v6"
	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/status"
)

const passDefaultLen = 10

func TestRegisterLogin_Login_HappyPath(t *testing.T) {
	ctx, st := suite.New(t)

	email := gofakeit.Email()
	pass := randomFakePassword()

	respReg, err := st.AuthClient.Register(ctx, &ssov1.RegisterRequest{
		Email:    email,
		Password: pass,
	})
	require.NoError(t, err)
	require.NotEmpty(t, respReg.GetUserUuid())

	loginTime := time.Now()

	respLogin, err := st.AuthClient.Login(ctx, &ssov1.LoginRequest{
		Email:    email,
		Password: pass,
		AppId:    int32(st.AppID),
	})
	if err != nil {
		if s, ok := status.FromError(err); ok {
			t.Fatalf("login rpc failed: code=%s msg=%q err=%v", s.Code(), s.Message(), err)
		}
		t.Fatalf("login rpc failed: err=%v", err)
	}

	token := respLogin.GetAccessToken()
	require.NotEmpty(t, token)

	parsed, err := jwt.Parse(token, func(tk *jwt.Token) (interface{}, error) {
		// Если у тебя HMAC — проверяем метод подписи
		if _, ok := tk.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, jwt.ErrSignatureInvalid
		}
		return []byte(st.AppSecret), nil
	})
	require.NoError(t, err)
	require.True(t, parsed.Valid)

	claims, ok := parsed.Claims.(jwt.MapClaims)
	require.True(t, ok)

	// uid у тебя почти наверняка строка uuid
	uid, ok := claims["uid"].(string)
	require.True(t, ok, "uid claim should be string uuid")
	assert.Equal(t, respReg.GetUserUuid(), uid)

	assert.Equal(t, email, claims["email"].(string))
	assert.Equal(t, int(st.AppID), int(claims["app_id"].(float64)))

	const deltaSeconds = 1
	assert.InDelta(t,
		loginTime.Add(st.Cfg.TokenTTL).Unix(),
		claims["exp"].(float64),
		deltaSeconds,
	)
}

func randomFakePassword() string {
	return gofakeit.Password(true, true, true, true, false, passDefaultLen)
}
