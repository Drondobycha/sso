package postgres

import (
	"context"
	"errors"
	"fmt"
	"sso/internal/domain/models"
	"sso/internal/storage"

	"github.com/jackc/pgx"
)

const foreign_key_violation = "23503" // PostgreSQL error code for foreign key violation

func (s *Storage) GetUserInfo(ctx context.Context, userID int64) (models.User_info, error) {
	const op = "storage.postgres.user_info.UserInfo"
	var userInfo models.User_info
	const query = "SELECT user_id, email, name, email_verified, create_at FROM users WHERE id = $1;"
	err := s.pool.QueryRow(ctx, query, userID).Scan(&userInfo.User_id, &userInfo.Email, &userInfo.Name, &userInfo.Email_verified, &userInfo.Create_at)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return models.User_info{}, fmt.Errorf("%s: %w", op, storage.ErrUserNotFound)
		}
		return models.User_info{}, fmt.Errorf("%s: %w", op, err)
	}
	return userInfo, nil
}

func (s *Storage) DeleteUser(ctx context.Context, userID int64) (bool, error) {
	const op = "storage.postgres.user_info.DeleteUser"
	const query = "DELETE FROM users WHERE id = $1;"
	if _, err := s.pool.Exec(ctx, query, userID); err != nil {
		var pgErr *pgx.PgError
		if errors.As(err, &pgErr) && pgErr.Code == foreign_key_violation {
			return false, fmt.Errorf("%s: %w", op, storage.ErrUserHasPermissions)
		}
		return false, fmt.Errorf("%s: %w", op, err)
	}
	return true, nil
}

func (s *Storage) UpdateUserInfo(ctx context.Context, userID int64, email string, name string) (bool, error) {
	const op = "storage.postgres.user_info.UpdateUserInfo"
	const query = "UPDATE users SET email = $1, name = $2 WHERE id = $3;"
	if _, err := s.pool.Exec(ctx, query, email, name, userID); err != nil {
		var pgErr *pgx.PgError
		if errors.As(err, &pgErr) && pgErr.Code == unique_violation {
			return false, fmt.Errorf("%s: %w", op, storage.ErrUserExists)
		}
		return false, fmt.Errorf("%s: %w", op, err)
	}
	return true, nil
}
