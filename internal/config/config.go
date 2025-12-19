package config

import (
	"flag"
	"os"
	"time"

	"github.com/ilyakaznacheev/cleanenv"
)

type Config struct {
	Env         string        `yaml:"env" env-default:"local"`
	PostgresDSN string        `yaml:"storage_path" env:"POSTGRES_DSN" env-required:"true"`
	TokenTTL    time.Duration `yaml:"token_ttl" env-default:"1h"`
	RefreshTTL  time.Duration `yaml:"refreshTTL" env-default:"168h"`
	GRPC        GRPCConfig    `yaml:"grpc"`
}

type GRPCConfig struct {
	Port    int           `yaml:"port" env-default:"44044"`
	Timeout time.Duration `yaml:"timeout" env-default:"5s"`
}

// MustLoad загружает конфиг (panic — осознанно, это bootstrap)
func MustLoad() *Config {
	path := fetchConfigPath()
	if path == "" {
		panic("config path is empty")
	}

	return mustLoadByPath(path)
}

func mustLoadByPath(path string) *Config {
	if _, err := os.Stat(path); os.IsNotExist(err) {
		panic("config file does not exist: " + path)
	}

	var cfg Config
	if err := cleanenv.ReadConfig(path, &cfg); err != nil {
		panic("failed to read config: " + err.Error())
	}

	return &cfg
}

// fetchConfigPath:
// 1. флаг --config
// 2. ENV CONFIG_PATH
func fetchConfigPath() string {
	var path string

	flag.StringVar(&path, "config", "", "path to config file")
	flag.Parse()

	if path == "" {
		path = os.Getenv("CONFIG_PATH")
	}

	return path
}

// MustLoadByPath загружает конфиг по явному пути
func MustLoadByPath(path string) *Config {
	return mustLoadByPath(path)
}
