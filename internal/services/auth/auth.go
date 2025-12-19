package auth

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"

	"sso/internal/domain/models"
	"sso/internal/lib/jwt"
	"sso/internal/lib/logger/sl"
	"sso/internal/storage"
)

type Auth struct {
	userSaver       UserSaver
	userProvider    UserProvider
	appProvider     AppProvider
	tokenManager    TokenManager
	refreshSaver    RefreshSessionSaver
	refreshProvider RefreshSessionProvider
	refreshRotator  RefreshSessionRotator
	refreshRevoker  RefreshSessionRevoker
	log             *slog.Logger
	tokenTTL        time.Duration
	refreshTTL      time.Duration
}

type UserSaver interface {
	SaveUser(ctx context.Context, username, email string, passHash []byte) (uuid.UUID, error)
}

type UserProvider interface {
	User(ctx context.Context, email string) (models.User, error)
	UserByUUID(ctx context.Context, userUUID uuid.UUID) (models.User, error)
	IsAdminByUUID(ctx context.Context, userUUID uuid.UUID) (bool, error)
}

type TokenManager interface {
	CreateToken(userUUID uuid.UUID, appID int64, ttl time.Duration) (string, error)
	ParseToken(token string, appID int64) (uuid.UUID, error)
}

type AppProvider interface {
	App(ctx context.Context, appID int64) (models.App, error)
}

type RefreshSessionSaver interface {
	SaveRefreshSession(ctx context.Context, userUUID uuid.UUID, refreshHash string, expiresAt time.Time) error
}

type RefreshSessionProvider interface {
	RefreshSessionByHash(ctx context.Context, hash string) (models.RefreshSession, error)
}

type RefreshSessionRotator interface {
	RotateRefreshSession(ctx context.Context, oldHash, newHash string, newExpiresAt time.Time) error
}

type RefreshSessionRevoker interface {
	RevokeRefreshSession(ctx context.Context, hash string) error
}

func New(
	log *slog.Logger,
	userSaver UserSaver,
	userProvider UserProvider,
	appProvider AppProvider,
	tokenManager TokenManager,
	tokenTTL time.Duration,
	refreshTTL time.Duration,
	refreshSaver RefreshSessionSaver,
	refreshProvider RefreshSessionProvider,
	refreshRotator RefreshSessionRotator,
	refreshRevoker RefreshSessionRevoker,
) *Auth {
	return &Auth{
		userSaver:       userSaver,
		userProvider:    userProvider,
		appProvider:     appProvider,
		tokenManager:    tokenManager,
		refreshSaver:    refreshSaver,
		refreshProvider: refreshProvider,
		refreshRotator:  refreshRotator,
		refreshRevoker:  refreshRevoker,
		log:             log,
		tokenTTL:        tokenTTL,
		refreshTTL:      refreshTTL,
	}
}

/*
====================
Auth methods
====================
*/

func (a *Auth) Login(ctx context.Context, email, password string, appID int) (refreshToken, accessToken string, err error) {
	const op = "auth.Login"

	user, err := a.userProvider.User(ctx, email)
	if err != nil {
		if errors.Is(err, storage.ErrUserNotFound) {
			return "", "", fmt.Errorf("%s: %w", op, storage.ErrInvalidCredentials)
		}
		return "", "", fmt.Errorf("%s: %w", op, err)
	}

	if err := bcrypt.CompareHashAndPassword(user.PasswordHash, []byte(password)); err != nil {
		return "", "", fmt.Errorf("%s: %w", op, storage.ErrInvalidCredentials)
	}

	app, err := a.appProvider.App(ctx, int64(appID))
	if err != nil {
		return "", "", fmt.Errorf("%s: %w", op, err)
	}

	access, err := jwt.NewToken(user, app, a.tokenTTL)
	if err != nil {
		return "", "", fmt.Errorf("%s: %w", op, err)
	}

	refreshRaw, err := newRefreshToken(64)
	if err != nil {
		return "", "", fmt.Errorf("%s: %w", op, err)
	}

	refreshHash := sha256Hex(refreshRaw)
	refreshExp := time.Now().Add(a.refreshTTL)

	if err := a.refreshSaver.SaveRefreshSession(ctx, user.UUID, refreshHash, refreshExp); err != nil {
		a.log.Error("save refresh failed", sl.Err(err))
		return "", "", fmt.Errorf("%s: %w", op, err)
	}

	return refreshRaw, access, nil
}

func (a *Auth) IsAdminByUUID(
	ctx context.Context,
	userUUID uuid.UUID,
) (bool, error) {
	const op = "auth.IsAdminByUUID"

	if userUUID == uuid.Nil {
		return false, storage.ErrUserNotFound
	}

	isAdmin, err := a.userProvider.IsAdminByUUID(ctx, userUUID)
	if err != nil {
		return false, fmt.Errorf("%s: %w", op, err)
	}

	return isAdmin, nil
}

func (a *Auth) RegisterNewUser(ctx context.Context, email, password string) (uuid.UUID, error) {
	const op = "auth.RegisterNewUser"

	passHash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return uuid.Nil, fmt.Errorf("%s: %w", op, err)
	}

	userUUID, err := a.userSaver.SaveUser(ctx, email, email, passHash)
	if err != nil {
		if errors.Is(err, storage.ErrUserExist) {
			return uuid.Nil, fmt.Errorf("%s: %w", op, storage.ErrUserExist)
		}
		return uuid.Nil, fmt.Errorf("%s: %w", op, err)
	}

	return userUUID, nil
}

func (a *Auth) ValidateToken(ctx context.Context, token string, appID int64) (uuid.UUID, error) {
	userUUID, err := a.tokenManager.ParseToken(token, appID)
	if err != nil {
		return uuid.Nil, storage.ErrInvalidToken
	}

	user, err := a.userProvider.UserByUUID(ctx, userUUID)
	if err != nil || !user.IsActive {
		return uuid.Nil, storage.ErrUserNotFound
	}

	return userUUID, nil
}

func (a *Auth) Refresh(ctx context.Context, refreshToken string, appID int) (accessToken, RefreshToken string, err error) {
	const op = "auth.Refresh"

	if refreshToken == "" {
		return "", "", storage.ErrInvalidToken
	}

	oldHash := sha256Hex(refreshToken)

	sess, err := a.refreshProvider.RefreshSessionByHash(ctx, oldHash)
	if err != nil || sess.RevokedAt != nil || time.Now().After(sess.ExpiresAt) {
		return "", "", storage.ErrInvalidToken
	}

	app, err := a.appProvider.App(ctx, int64(appID))
	if err != nil {
		return "", "", fmt.Errorf("%s: %w", op, err)
	}

	user, err := a.userProvider.UserByUUID(ctx, sess.UserUUID)
	if err != nil {
		return "", "", storage.ErrUserNotFound
	}

	access, err := jwt.NewToken(user, app, a.tokenTTL)
	if err != nil {
		return "", "", fmt.Errorf("%s: %w", op, err)
	}

	refreshRaw, err := newRefreshToken(64)
	if err != nil {
		return "", "", fmt.Errorf("%s: %w", op, err)
	}

	newHash := sha256Hex(refreshRaw)
	newExp := time.Now().Add(a.refreshTTL)

	if err := a.refreshRotator.RotateRefreshSession(ctx, oldHash, newHash, newExp); err != nil {
		return "", "", fmt.Errorf("%s: %w", op, err)
	}

	return access, refreshRaw, nil
}

func (a *Auth) Logout(ctx context.Context, refreshToken string) error {
	if refreshToken == "" {
		return storage.ErrInvalidToken
	}

	hash := sha256Hex(refreshToken)
	_ = a.refreshRevoker.RevokeRefreshSession(ctx, hash)

	return nil
}
