package suite

// import (
// 	"context"
// 	"database/sql"
// 	"net"
// 	"os"
// 	"strconv"
// 	"testing"

// 	ssov1 "github.com/YagorX/protos/gen/go/sso"
// 	_ "github.com/jackc/pgx/v5/stdlib"
// 	"google.golang.org/grpc"
// 	"google.golang.org/grpc/credentials/insecure"

// 	"sso/internal/config"
// )

// type Suite struct {
// 	T          *testing.T
// 	Cfg        *config.Config
// 	AuthClient ssov1.AuthClient
// 	DB         *sql.DB

// 	// то, чем подписываются JWT в jwt.NewToken (app.Secret)
// 	AppID     int64
// 	AppSecret string
// }

// const (
// 	grpcHost          = "localhost"
// 	defaultConfigPath = "../config/local_tests.yaml"
// )

// func New(t *testing.T) (context.Context, *Suite) {
// 	t.Helper()
// 	t.Parallel()

// 	cfgPath := os.Getenv("CONFIG_PATH")
// 	if cfgPath == "" {
// 		cfgPath = defaultConfigPath
// 	}

// 	cfg := config.MustLoadByPath(cfgPath)

// 	ctx, cancel := context.WithTimeout(context.Background(), cfg.GRPC.Timeout)
// 	t.Cleanup(cancel)

// 	// 1) Подключаемся к БД (DSN у тебя лежит в cfg.PostgresDSN)
// 	db, err := sql.Open("pgx", cfg.PostgresDSN)
// 	if err != nil {
// 		t.Fatalf("db open failed: %v", err)
// 	}
// 	t.Cleanup(func() { _ = db.Close() })

// 	if err := db.PingContext(ctx); err != nil {
// 		t.Fatalf("db ping failed: %v", err)
// 	}

// 	// 2) Seed app (иначе Login будет Internal из-за ErrAppNotFound)
// 	const (
// 		testAppID     int64 = 1
// 		testAppName         = "test-app"
// 		testAppSecret       = "test-secret"
// 	)

// 	ensureTestApp(t, ctx, db, testAppID, testAppName, testAppSecret)

// 	// 3) gRPC клиент
// 	cc, err := grpc.DialContext(
// 		ctx,
// 		grpcAddress(cfg),
// 		grpc.WithTransportCredentials(insecure.NewCredentials()),
// 	)
// 	if err != nil {
// 		t.Fatalf("grpc server connection failed: %v", err)
// 	}
// 	t.Cleanup(func() { _ = cc.Close() })

// 	return ctx, &Suite{
// 		T:          t,
// 		Cfg:        cfg,
// 		AuthClient: ssov1.NewAuthClient(cc),
// 		DB:         db,
// 		AppID:      testAppID,
// 		AppSecret:  testAppSecret,
// 	}
// }

// func grpcAddress(cfg *config.Config) string {
// 	return net.JoinHostPort(grpcHost, strconv.Itoa(cfg.GRPC.Port))
// }

// func ensureTestApp(t *testing.T, ctx context.Context, db *sql.DB, id int64, name, secret string) {
// 	t.Helper()

// 	// upsert по id
// 	_, err := db.ExecContext(ctx, `
// 		INSERT INTO apps (id, name, secret)
// 		VALUES ($1, $2, $3)
// 		ON CONFLICT (id) DO UPDATE
// 		SET name = EXCLUDED.name,
// 		    secret = EXCLUDED.secret
// 	`, id, name, secret)
// 	if err != nil {
// 		t.Fatalf("seed app failed: %v", err)
// 	}
// }
