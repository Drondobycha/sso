package postgres

import (
	"context"
	"errors"
	"fmt"
	"sso/internal/domain/models"
	"sso/internal/storage"

	"github.com/jackc/pgx"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

type Storage struct {
	pool *pgxpool.Pool
}

const unique_violation = "23505"

func New(ctx context.Context, storagePath string) (*Storage, error) {
	const op = "storage.postgres.New"
	pool, err := pgxpool.New(ctx, storagePath)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", op, err)
	}
	if err := pool.Ping(ctx); err != nil {
		return nil, fmt.Errorf("%s: %w", op, err)
	}
	return &Storage{pool: pool}, nil
}

func (s *Storage) SaveUser(ctx context.Context, email string, passHash []byte) (int64, error) {
	const op = "storage.postgres.SaveUser"
	var id int64
	query_row := "INSERT INTO users(email, pass_hash) VALUES($1, $2) RETURNING id;"
	err := s.pool.QueryRow(ctx, query_row, email, passHash).Scan(&id)
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == unique_violation {
			return 0, fmt.Errorf("%s: %w", op, storage.ErrUserExists)
		}
		return 0, fmt.Errorf("%s: query row: %w", op, err)
	}
	return id, nil
}

func (s *Storage) User(ctx context.Context, email string) (models.User, error) {
	const op = "storage.postgres.User"
	var user models.User

	err := s.pool.QueryRow(ctx,
		"SELECT id, email, pass_hash FROM users WHERE email = $1;",
		email).Scan(&user.ID, &user.Email, &user.PassHash)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return models.User{}, fmt.Errorf("%s: %w", op, storage.ErrUserNotFound)
		}
		return models.User{}, fmt.Errorf("%s: %w", op, err)
	}
	return user, nil
}

func (s *Storage) IsAdmin(ctx context.Context, userID int64) (bool, error) {
	const op = "storage.postgres.IsAdmin"
	var isAdmin bool
	err := s.pool.QueryRow(ctx,
		"SELECT is_admin FROM users WHERE id = $1;",
		userID).Scan(&isAdmin)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return false, fmt.Errorf("%s: %w", op, storage.ErrUserNotFound)
		}
		return false, fmt.Errorf("%s: %w", op, err)
	}
	return isAdmin, nil
}

func (s *Storage) App(ctx context.Context, appID int) (models.App, error) {
	const op = "storage.postgres.App"
	var app models.App
	err := s.pool.QueryRow(ctx,
		"SELECT id, name, secret FROM apps WHERE id = $1;",
		appID).Scan(&app.ID, &app.Name, &app.Secret)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return models.App{}, fmt.Errorf("%s: %w", op, storage.ErrAppNotFound)
		}
		return models.App{}, fmt.Errorf("%s: %w", op, err)
	}
	return app, nil
}

func (s *Storage) AddPerm(ctx context.Context, uid int64, addedPerm string) (bool, error) {
	const op = "storage.postgres.AddPerm"
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return false, fmt.Errorf("%s: begin tx: %w", op, err)
	}
	defer func() {
		if err := tx.Rollback(ctx); err != nil && !errors.Is(err, pgx.ErrTxClosed) {
			println("Ошибка отката транзакции")
		}
	}()
	stmt, err := tx.Prepare(ctx, "insert_perm", "INSERT INTO permissions(user_id, permission) VALUES($1, $2);")
	if err != nil {
		return false, fmt.Errorf("%s: prepare stmt: %w", op, err)
	}
	if _, err := tx.Exec(ctx, stmt.Name, uid, addedPerm); err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == unique_violation {
			return false, fmt.Errorf("%s: %w", op, storage.ErrPermissionExists)
		}
		return false, fmt.Errorf("%s: query row: %w", op, err)
	}
	if err := tx.Commit(ctx); err != nil {
		return false, fmt.Errorf("%s: %w", op, err)
	}
	return true, nil
}

func (s *Storage) RemovePerm(ctx context.Context, uid int64, removedPerm string) (bool, error) {
	const op = "storage.postgres.RemovePerm"
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return false, fmt.Errorf("%s: begin tx: %w", op, err)
	}
	defer func() {
		if err := tx.Rollback(ctx); err != nil && !errors.Is(err, pgx.ErrTxClosed) {
			println("Ошибка отката транзакции")
		}
	}()
	stmt, err := tx.Prepare(ctx, "delete_perm", "DELETE FROM permissions WHERE user_id = $1 AND permission = $2;")
	if err != nil {
		return false, fmt.Errorf("%s: prepare stmt: %w", op, err)
	}
	if _, err := tx.Exec(ctx, stmt.Name, uid, removedPerm); err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == unique_violation {
			return false, fmt.Errorf("%s: %w", op, storage.ErrPermissionNotFound)
		}
		return false, fmt.Errorf("%s: query row: %w", op, err)
	}
	if err := tx.Commit(ctx); err != nil {
		return false, fmt.Errorf("%s: %w", op, err)
	}
	return true, nil
}

func (s *Storage) CheckPerm(ctx context.Context, uid int64, checkedPerm string) (bool, error) {
	const op = "storage.postgres.CheckPerm"
	var hasPerm bool
	err := s.pool.QueryRow(ctx,
		"SELECT EXISTS(SELECT 1 FROM permissions WHERE user_id = $1 AND permission = $2);",
		uid, checkedPerm).Scan(&hasPerm)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return false, fmt.Errorf("%s: %w", op, storage.ErrUserNotFound)
		}
		return false, fmt.Errorf("%s: %w", op, err)
	}
	return hasPerm, nil
}

func (s *Storage) ListPerm(ctx context.Context, uid int64) ([]string, error) {
	const op = "storage.postgres.ListPerm"
	const query = "SELECT permission FROM permissions WHERE user_id = $1;"
	rows, err := s.pool.Query(ctx, query, uid)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
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
			if errors.Is(err, pgx.ErrNoRows) {
				return nil, fmt.Errorf("%s: %w", op, storage.ErrPermissionNotFound)
			}
			return nil, fmt.Errorf("%s: %w", op, err)
		}
		permissions = append(permissions, permission)
	}
	return permissions, nil
}
