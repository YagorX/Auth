package app

import (
	"log/slog"
	"time"

	grpcapp "sso/internal/app/grpc"
	"sso/internal/services/auth"
	"sso/internal/storage/postgres"
)

type App struct {
	GRPCServer *grpcapp.App
}

func New(
	log *slog.Logger,
	grpcPort int,
	postgresDSN string,
	tokenTTL time.Duration,
	refreshTTL time.Duration,
) *App {
	storage, err := postgres.New(postgresDSN, log)
	if err != nil {
		panic(err)
	}

	jwtAdapter := auth.NewJWTAdapter(storage)

	authService := auth.New(
		log,
		storage,    // UserSaver
		storage,    // UserProvider
		storage,    // AppProvider
		jwtAdapter, // TokenManager
		tokenTTL,
		refreshTTL,
		storage, // RefreshSessionSaver
		storage, // RefreshSessionProvider
		storage, // RefreshSessionRotator
		storage, // RefreshSessionRevoker
	)

	grpcApp := grpcapp.New(log, authService, grpcPort)

	return &App{GRPCServer: grpcApp}
}
