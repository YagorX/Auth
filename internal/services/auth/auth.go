package auth

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sso/internal/domain/models"
	"sso/internal/lib/jwt"
	"sso/internal/lib/logger/sl"
	"sso/internal/storage"
	"time"

	"golang.org/x/crypto/bcrypt"
)

// сервисный слой будет отвечать за бизнес логику, то есть выполнять действия и бьудет взаиможейстоввать с базой данных
// для того чтобы передавать данные между сервисным слоем и слоем работы с данными заведем моедльки (в пакете domain)
// всё это сделано для того чтобы наши heandlers не работали напрямую с бд

type Auth struct {
	userSaver       UserSaver
	refreshSaver    RefreshSessionSaver
	userProvider    UserProvider
	appProvider     AppProvider
	tokenManager    TokenManager
	refreshProvider RefreshSessionProvider
	refreshRotator  RefreshSessionRotator
	refreshRevoker  RefreshSessionRevoker
	log             *slog.Logger
	tokenTTL        time.Duration
	refreshTTL      time.Duration
}

// type Storage interface{} разделим на конкретные

type UserSaver interface {
	SaveUser(
		ctx context.Context,
		email string,
		passHash []byte,
	) (uid int64, err error)
}

type UserProvider interface {
	User(ctx context.Context, email string) (models.User, error)
	IsAdmin(ctx context.Context, userID int64) (bool, error)
	UserByID(ctx context.Context, userID int64) (models.User, error)
}

type TokenManager interface {
	CreateToken(userID int64, appID int64, ttl time.Duration) (string, error)
	ParseToken(token string, appID int64) (int64, error)
}

type AppProvider interface {
	App(ctx context.Context, appID int64) (models.App, error)
}

type RefreshSessionProvider interface {
	RefreshSessionByHash(ctx context.Context, hash string) (models.RefreshSession, error)
}

type RefreshSessionSaver interface {
	SaveRefreshSession(ctx context.Context, userID int64, refreshHash string, expiresAt time.Time) error
}

type RefreshSessionRotator interface {
	RotateRefreshSession(ctx context.Context, oldHash, newHash string, newExpiresAt time.Time) error
}

type RefreshSessionRevoker interface {
	RevokeRefreshSession(ctx context.Context, hash string) error
}

var (
	ErrInvalidCredentials = errors.New("invalid credentials")
	ErrInvalidateAppID    = errors.New("invalidate appID")
	ErrUserExist          = errors.New("user already exists")
	ErrUserNotFound       = errors.New("user not found")
	ErrInvalidToken       = errors.New("invalid token")
)

// New returns s new instance of the Auth service.
func New(
	log *slog.Logger,
	userSaver UserSaver,
	userProvider UserProvider,
	appProvider AppProvider,
	tokenManager TokenManager,
	tokenTTL time.Duration,
	refreshTTL time.Duration,
) *Auth {
	return &Auth{
		userSaver:    userSaver,
		userProvider: userProvider,
		appProvider:  appProvider,
		tokenManager: tokenManager,
		log:          log,
		tokenTTL:     tokenTTL,
		refreshTTL:   refreshTTL,
	}
}

// login check if user with given credentials exists in the system
// If user exists, but password is incorrect, return error
// if user doesnot exist, return error
func (a *Auth) Login(
	ctx context.Context,
	email string,
	password string,
	appID int,
) (refreshToken, accessToken string, err error) {
	const op = "auth.Login"

	log := a.log.With(
		slog.String("op", op),
		slog.String("email", email), // так себе практика
	)
	log.Info("login user")

	user, err := a.userProvider.User(ctx, email)
	if err != nil {
		if errors.Is(err, storage.ErrUserNotFound) {
			// если человек ввел логин неверный или пароль
			a.log.Warn("user not found", sl.Err(err))
			return "", "", fmt.Errorf("%s %w", op, ErrInvalidCredentials)
		}

		a.log.Error("failed to get user", sl.Err(err))
		return "", "", fmt.Errorf("%s %w", op, err)
	}

	if err := bcrypt.CompareHashAndPassword(user.PassHash, []byte(password)); err != nil {
		//если не верный пароль
		a.log.Info("invalid credentials", sl.Err(err))
		return "", "", fmt.Errorf("%s %w", op, ErrInvalidCredentials)
	}

	// открываем приложение в котором секретный ключь
	app, err := a.appProvider.App(ctx, int64(appID))
	if err != nil {
		return "", "", fmt.Errorf("%s %w", op, err)
	}

	a.log.Info("user logger is succesful")
	//создание токенов refresh + access(это уже есть снизу)
	tokenAccess, err := jwt.NewToken(user, app, a.tokenTTL)
	// token, err := a.tokenManager.CreateToken(user.ID, int64(app.ID), a.tokenTTL)
	if err != nil {
		a.log.Error("error with generate token", sl.Err(err))
		return "", "", fmt.Errorf("%s %w", op, err)
	}

	refreshRaw, err := newRefreshToken(64) // 64 bytes -> длинная строка
	if err != nil {
		a.log.Error("error with generate refresh token", sl.Err(err))
		return "", "", fmt.Errorf("%s %w", op, err)
	}

	refreshHash := sha256Hex(refreshRaw)
	refreshExp := time.Now().Add(a.refreshTTL)

	if err := a.refreshSaver.SaveRefreshSession(ctx, user.ID, refreshHash, refreshExp); err != nil {
		a.log.Error("failed to save refresh session", sl.Err(err))
		return "", "", fmt.Errorf("%s %w", op, err)
	}

	return tokenAccess, refreshRaw, nil
}

// RegisterNewUser registers new user in the system and return ID.
// if user with given username already exists, return error
func (a *Auth) RegisterNewUser(
	ctx context.Context,
	email string,
	password string,
) (int64, error) {
	const op = "auth.RegisterNewUser"

	log := a.log.With(
		slog.String("op", op),
		slog.String("email", email), // так себе практика
	)
	log.Info("register user")

	passHash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)

	if err != nil {
		log.Error("failed to generate password hash", sl.Err(err))

		return 0, fmt.Errorf("%s %w", op, err)
	}

	id, err := a.userSaver.SaveUser(ctx, email, passHash)
	if err != nil {
		if errors.Is(err, storage.ErrUserExist) {
			// если пользователь уже существует
			a.log.Warn("user already exists", sl.Err(err))
			return 0, fmt.Errorf("%s %w", op, ErrUserExist)
		}
		log.Error("failed to save user", sl.Err(err))
		return 0, fmt.Errorf("%s %w", op, err)
	}

	log.Info("user registered")
	return id, nil
}

// is admin checks if user is admin
func (a *Auth) IsAdmin(ctx context.Context, userID int64) (bool, error) {
	const op = "Auth.IsAdmin"

	log := a.log.With(
		slog.String("op", op),
		slog.Int64("user_id", userID),
	)

	log.Info("checking if user is admin")
	isAsdmin, err := a.userProvider.IsAdmin(ctx, userID)
	if err != nil {
		if errors.Is(err, storage.ErrUserNotFound) {
			// если человек ввел логин неверный или пароль
			a.log.Warn("user not found", sl.Err(err))
			return false, fmt.Errorf("%s %w", op, ErrUserNotFound)
		}
		return false, fmt.Errorf("%s %w", op, err)
	}

	log.Info("checking if user is admin", slog.Bool("isAdmin", isAsdmin))

	return isAsdmin, nil
}

func (a *Auth) ValidateToken(ctx context.Context, token string, appID int64) (int64, error) {
	userID, err := a.tokenManager.ParseToken(token, appID)
	if err != nil {
		return 0, ErrInvalidToken
	}

	// Проверяем что пользователь существует
	_, err = a.userProvider.UserByID(ctx, userID)
	if err != nil {
		return 0, ErrUserNotFound
	}

	return userID, nil
}
