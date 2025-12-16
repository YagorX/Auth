package app

import (
	"log/slog"
	grpcapp "sso/internal/app/grpc"
	"sso/internal/services/auth"
	"sso/internal/storage/sqlite"
	"time"
)

type App struct {
	GRPCServer *grpcapp.App
}

func New(
	log *slog.Logger,
	grpcPort int,
	storagePath string,
	tokenTTL time.Duration,
	refreshTTL time.Duration,
) *App {
	storage, err := sqlite.New(storagePath, log)
	if err != nil {
		panic(err)
	}

	jwtAdapter := auth.NewJWTAdapter(storage)

	authService := auth.New(log, storage, storage, storage, jwtAdapter, tokenTTL, refreshTTL, storage, storage, storage, storage)

	grpcApp := grpcapp.New(log, authService, grpcPort)

	return &App{
		GRPCServer: grpcApp,
	}
}
