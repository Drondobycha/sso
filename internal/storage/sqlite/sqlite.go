package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"sso/internal/domain/models"
	perm "sso/internal/services/permissions"
	"sso/internal/storage"

	"github.com/mattn/go-sqlite3"
)

type Storage struct {
	db *sql.DB
}

func New(storagePath string) (*Storage, error) {
	const op = "storage.sqlite.New"
	db, err := sql.Open("sqlite3", storagePath)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", op, err)
	}
	return &Storage{db: db}, nil
}

func (s *Storage) SaveUser(ctx context.Context, email string, passHash []byte) (int64, error) {
	const op = "storage.sqlite.SaveUser"
	stmt, err := s.db.Prepare("INSERT INTO users(email, pass_hash) VALUES(?, ?);")
	if err != nil {
		return 0, fmt.Errorf("%s: %w", op, err)
	}
	res, err := stmt.ExecContext(ctx, email, passHash)
	if err != nil {
		var sqliteErr sqlite3.Error
		if errors.As(err, &sqliteErr) && sqliteErr.ExtendedCode == sqlite3.ErrConstraintUnique {
			return 0, fmt.Errorf("%s: %w", op, storage.ErrUserExists)
		}
		return 0, fmt.Errorf("%s: %w", op, err)
	}

	id, err := res.LastInsertId()
	if err != nil {
		return 0, fmt.Errorf("%s: %w", op, err)
	}

	return id, nil
}

// User returns user by email
func (s *Storage) User(ctx context.Context, email string) (models.User, error) {
	const op = "storage.sqlite.User"
	var user models.User
	stmt, err := s.db.Prepare("SELECT id, email, pass_hash FROM users WHERE email = ?;")
	if err != nil {
		return models.User{}, fmt.Errorf("%s: %w", op, err)
	}

	row := stmt.QueryRowContext(ctx, email)

	err = row.Scan(&user.ID, &user.Email, &user.PassHash)
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
	stmt, err := s.db.Prepare("SELECT is_admin FROM users WHERE id = ?;")
	if err != nil {
		return false, fmt.Errorf("%s: %w", op, err)
	}
	row := stmt.QueryRowContext(ctx, userID)
	var isAmin bool
	err = row.Scan(&isAmin)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return false, fmt.Errorf("%s: %w", op, storage.ErrAppNotFound)
		}
		return false, fmt.Errorf("%s: %w", op, err)
	}
	return isAmin, nil
}

func (s *Storage) App(ctx context.Context, appId int) (models.App, error) {
	const op = "storage.sqlite.App"

	stmt, err := s.db.Prepare("SELECT id, name, secret FROM apps WHERE id = ?")
	if err != nil {
		return models.App{}, fmt.Errorf("%s: %w", op, err)
	}
	row := stmt.QueryRowContext(ctx, appId)

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

func (s *Storage) AddPerm(ctx context.Context, usrID int64, permissions string) (bool, error) {
	const op = "storage.sqlite.AddPerm"
	stmt, err := s.db.Prepare("INSERT INTO permissions(user_id, permission) VALUES(?, ?);")
	if err != nil {
		return false, fmt.Errorf("%s: %w", op, err)
	}
	_, err = stmt.ExecContext(ctx, usrID, permissions)
	if err != nil {
		var sqliteErr sqlite3.Error
		if errors.As(err, &sqliteErr) && sqliteErr.ExtendedCode == sqlite3.ErrConstraintUnique {
			return false, fmt.Errorf("%s: %w", op, perm.ErrPermissionExists)
		}
		return false, fmt.Errorf("%s: %w", op, err)
	}
	return true, nil
}

func (s *Storage) CheckPerm(ctx context.Context, uid int64, CheckedPerm string) (res bool, err error) {
	return true, nil
}

func (s *Storage) ListPerm(ctx context.Context, uid int64) (list_permission []string, err error) {
	const op = "storage.sqlite.ListPerm"
	stmt, err := s.db.Prepare("SELECT permission FROM permissions WHERE user_id = ?;")
	if err != nil {
		return nil, fmt.Errorf("%s: %w", op, err)
	}
	rows, err := stmt.QueryContext(ctx, uid)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, fmt.Errorf("%s: %w", op, storage.ErrUserNotFound)
		}
		return nil, fmt.Errorf("%s: %w", op, err)
	}
	defer rows.Close()
	var permissions []string
	for rows.Next() {
		var permission string
		err = rows.Scan(&permission)
		if err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return nil, fmt.Errorf("%s: %w", op, perm.ErrPermissionNotFound)
			}
			return nil, fmt.Errorf("%s: %w", op, err)
		}
		permissions = append(permissions, permission)
	}
	return permissions, nil
}

func (s *Storage) RemovePerm(ctx context.Context, uid int64, RemovedPerm string) (res bool, err error) {
	return true, nil
}
