package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strconv"

	"log/slog"
	"sso/internal/domain/models"
	"sso/internal/lib/logger/sl"
	"sso/internal/storage"

	"github.com/mattn/go-sqlite3"
)

type Storage struct {
	db  *sql.DB
	log *slog.Logger
}

// new creates a new instance of the sqlite storage
func New(storagePath string, log *slog.Logger) (*Storage, error) {
	const op = "storage.sqlite.New"
	println("storagePath: ", storagePath)
	// path to file
	db, err := sql.Open("sqlite3", storagePath)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", op, err)
	}

	return &Storage{
		db:  db,
		log: log,
	}, nil
}

func (s *Storage) SaveUser(ctx context.Context, email string, passHash []byte) (int64, error) {
	const op = "storage.sqlite.SaveUser"

	// example
	stmt, err := s.db.Prepare("INSERT INTO users(email, pass_hash) VALUES (?, ?)")
	if err != nil {
		return 0, fmt.Errorf("%s: %w", op, err)
	}

	res, err := stmt.ExecContext(ctx, email, passHash)
	if err != nil {
		// ПРАВИЛЬНАЯ проверка UNIQUE constraint
		var sqliteErr sqlite3.Error
		if errors.As(err, &sqliteErr) && sqliteErr.ExtendedCode == sqlite3.ErrConstraintUnique {
			return 0, fmt.Errorf("%s: %w", op, storage.ErrUserExist)
		}

		return 0, fmt.Errorf("%s: %w", op, err)
	}

	id, err := res.LastInsertId()
	if err != nil {
		return 0, fmt.Errorf("%s: %w", op, err)
	}

	return id, nil
}

// info aboout user
func (s *Storage) User(ctx context.Context, email string) (models.User, error) {
	const op = "storage.sqlite.User"

	stmt, err := s.db.Prepare("SELECT * FROM users WHERE email = ?")
	if err != nil {
		return models.User{}, fmt.Errorf("%s: %w", op, err)
	}

	row := stmt.QueryRowContext(ctx, email)

	var user models.User
	err = row.Scan(&user.ID, &user.Email, &user.PassHash, &user.IsAdmin)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return models.User{}, fmt.Errorf("%s: %w", op, storage.ErrUserNotFound)
		}

		return models.User{}, fmt.Errorf("%s: %w", op, err)
	}

	return user, nil
}

func (s *Storage) IsAdmin(ctx context.Context, userID int64) (bool, error) {
	const op = "storage.sqlite.IsAdmin"

	var test int
	err := s.db.QueryRow("SELECT 1").Scan(&test)
	if err != nil {
		s.log.Error("FAILED - Simple query:", sl.Err(err))
		return false, fmt.Errorf("database broken: %w", err)
	}
	s.log.Info("PASSED - Simple query works")

	// Проверяем какие колонки есть в таблице users
	rows, err := s.db.Query("PRAGMA table_info(users)")
	if err != nil {
		s.log.Error("FAILED - Cannot get table info:", sl.Err(err))
		return false, fmt.Errorf("cannot get table info: %w", err)
	}
	defer rows.Close()

	// Проверяем есть ли данные в таблице
	var rowCount int
	err = s.db.QueryRow("SELECT COUNT(*) FROM users").Scan(&rowCount)
	if err != nil {
		s.log.Error("FAILED - Cannot count rows:", sl.Err(err))
		return false, fmt.Errorf("cannot count rows: %w", err)
	}
	var tmp string = "Total rows in users table:" + strconv.Itoa(rowCount)
	s.log.Info(tmp)

	// Проверяем конкретного пользователя
	var isAdmin bool
	err = s.db.QueryRow("SELECT is_admin FROM users WHERE id = ?", userID).Scan(&isAdmin)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			println("FAILED - Cannot check user:", err.Error())
			return false, fmt.Errorf("%s: %w", op, storage.ErrUserNotFound)
		}
		return false, fmt.Errorf("%s: %w", op, err)
	}

	return isAdmin, nil
}

func (s *Storage) App(ctx context.Context, appID int64) (models.App, error) {
	const op = "storage.sqlite.App"

	stmt, err := s.db.Prepare("SELECT id, name, secret FROM apps WHERE id = ?")
	if err != nil {
		return models.App{}, fmt.Errorf("%s: %w", op, err)
	}

	row := stmt.QueryRowContext(ctx, appID)

	var app models.App
	err = row.Scan(&app.ID, &app.Name, &app.Secret)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return models.App{}, fmt.Errorf("%s: %w", op, storage.ErrAppNotFound)
		}

		return models.App{}, fmt.Errorf("%s: %w", op, err)
	}

	return app, nil
}

func (s *Storage) UserByID(ctx context.Context, userID int64) (models.User, error) {
	const op = "storage.sqlite.UserById"

	query := `SELECT id, email, pass_hash, is_admin FROM users WHERE id = ?`
	var user models.User
	err := s.db.QueryRowContext(ctx, query, userID).Scan(&user.ID, &user.Email, &user.PassHash, &user.IsAdmin)
	if err != nil {
		if err == sql.ErrNoRows {
			return models.User{}, storage.ErrUserNotFound
		}
		return models.User{}, err
	}

	return user, nil
}
