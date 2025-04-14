package postgres

import (
	"context"
	"errors"
	"fmt"
	"sso/internal/storage"

	"github.com/jackc/pgx"
	"github.com/jackc/pgx/v5/pgconn"
)

func (s *Storage) AddPermTx(ctx context.Context, uid int64, addedPerm string) (bool, error) {
	const op = "storage.postgres.permissions.AddPerm"
	const query = "INSERT INTO permissions(user_id, permission) VALUES($1, $2);"
	if _, err := s.pool.Exec(ctx, query, uid, addedPerm); err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == unique_violation {
			return false, fmt.Errorf("%s: %w", op, storage.ErrPermissionExists)
		}
		return false, fmt.Errorf("%s: query row: %w", op, err)
	}
	return true, nil
}

func (s *Storage) AddPerm(ctx context.Context, uid int64, addedPerm string) (bool, error) {
	const op = "storage.postgres.permissions.AddPerm"
	const query = "INSERT INTO permissions(user_id, permission) VALUES($1, $2);"
	if _, err := s.pool.Exec(ctx, query, uid, addedPerm); err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == unique_violation {
			return false, fmt.Errorf("%s: %w", op, storage.ErrPermissionExists)
		}
		return false, fmt.Errorf("%s: query row: %w", op, err)
	}
	return true, nil
}

func (s *Storage) RemovePerm(ctx context.Context, uid int64, removedPerm string) (bool, error) {
	const op = "storage.postgres.permissions.RemovePerm"
	const query = "DELETE FROM permissions WHERE user_id = $1 AND permission = $2;"
	if _, err := s.pool.Exec(ctx, query, uid, removedPerm); err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == unique_violation {
			return false, fmt.Errorf("%s: %w", op, storage.ErrPermissionNotFound)
		}
		return false, fmt.Errorf("%s: query row: %w", op, err)
	}
	return true, nil
}

func (s *Storage) CheckPerm(ctx context.Context, uid int64, checkedPerm string) (bool, error) {
	const op = "storage.postgres.permissions.CheckPerm"
	const query = "SELECT EXISTS(SELECT 1 FROM permissions WHERE user_id = $1 AND permission = $2);"
	var hasPerm bool
	err := s.pool.QueryRow(ctx, query, uid, checkedPerm).Scan(&hasPerm)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return false, fmt.Errorf("%s: %w", op, storage.ErrUserNotFound)
		}
		return false, fmt.Errorf("%s: %w", op, err)
	}
	return hasPerm, nil
}

func (s *Storage) ListPerm(ctx context.Context, uid int64) ([]string, error) {
	const op = "storage.postgres.permissions.ListPerm"
	const query = "SELECT permission FROM permissions WHERE user_id = $1;"
	ValidateSQLQuery(query)
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
