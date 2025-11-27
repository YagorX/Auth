package auth

import (
	"context"
	"sso/internal/domain/models"
	"sso/internal/lib/jwt"
	"sso/internal/storage/sqlite"
	"sync"
	"time"
)

type JWTAdapter struct {
	storage  *sqlite.Storage
	appCache map[int64]models.App
	cacheMux sync.RWMutex
}

func NewJWTAdapter(storage *sqlite.Storage) *JWTAdapter {
	return &JWTAdapter{storage: storage,
		appCache: make(map[int64]models.App)}
}

func (j *JWTAdapter) CreateToken(userID int64, appID int64, ttl time.Duration) (string, error) {
	// Получаем app из базы чтобы взять secret
	app, err := j.getApp(context.Background(), appID)
	if err != nil {
		return "", err
	}

	user := models.User{ID: userID}

	tokenString, err := jwt.NewToken(user, app, ttl)
	if err != nil {
		return "", err
	}

	return tokenString, nil
}

func (j *JWTAdapter) ParseToken(tokenString string, appID int64) (int64, error) {
	// Получаем app из базы чтобы взять secret
	app, err := j.getApp(context.Background(), appID)
	if err != nil {
		return 0, err
	}

	return jwt.ParseToken(tokenString, app)
}

func (j *JWTAdapter) getApp(ctx context.Context, appID int64) (models.App, error) {
	// Сначала проверяем кэш
	j.cacheMux.RLock()
	if app, exists := j.appCache[appID]; exists {
		j.cacheMux.RUnlock()
		return app, nil
	}
	j.cacheMux.RUnlock()

	// Если нет в кэше - идем в базу
	app, err := j.storage.App(ctx, appID)
	if err != nil {
		return models.App{}, err
	}

	// Сохраняем в кэш
	j.cacheMux.Lock()
	j.appCache[appID] = app
	j.cacheMux.Unlock()

	return app, nil
}
