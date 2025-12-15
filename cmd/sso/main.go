package main

import (
	"log/slog"
	"os"
	"os/signal"
	"sso/internal/app"
	"sso/internal/config"
	"sso/internal/lib/logger/handlers/slogpretty"
	"syscall"
)

const (
	envLocal = "local"
	envDev   = "dev"
	envProd  = "prod"
)

// access token нельзя передавать в cookies, лучше передавать через заголовки
// основной прикол jwt что не нужн обращаться в бд чтобы узнать роль и тд

func main() {
	// TODO: инициализировать объект конфига
	cfg := config.MustLoad()

	// TODO: инициализировать логгер

	log := setupLogger(cfg.Env)

	// TODO: инициализировать приложение (app)

	application := app.New(log, cfg.GRPC.Port, cfg.Storage_path, cfg.Token_ttl, cfg.RefreshTTL)

	log.Info("staritng application", slog.Any("config", cfg))

	go application.GRPCServer.MustRun()

	// TODO: сделать корректную обработку сигналов для остановки grpc serv
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGTERM, syscall.SIGINT) // приходят сигналы и запысиваются в канал stop

	sign := <-stop
	log.Info("stopping application", slog.String("signal", sign.String()))

	application.GRPCServer.Stop()
	log.Info("application stopped")

}

// создание логера обертки
func setupLogger(env string) *slog.Logger {
	var log *slog.Logger
	switch env {
	case envLocal:
		// log = slog.New(
		// 	slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}),
		// )
		log = setupPrettySlog()
	case envDev:
		log = slog.New(
			slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}),
		)
	case envProd:
		log = slog.New(
			slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}),
		)
	}

	return log
}

func setupPrettySlog() *slog.Logger {
	opts := slogpretty.PrettyHandlerOptions{
		SlogOpts: &slog.HandlerOptions{
			Level: slog.LevelDebug,
		},
	}

	handler := opts.NewPrettyHandler(os.Stdout)

	return slog.New(handler)
}
