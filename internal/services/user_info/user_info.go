package userinfo

import (
	"context"
	"errors"
	"log/slog"
	"sso/internal/domain/models"
	"sso/internal/storage"
)

type User_info struct {
	log          *slog.Logger
	infoProvider User_info_Provider
}

type User_info_Provider interface {
	DeleteUser(ctx context.Context, uid int64) (bool, error)
	GetUserInfo(ctx context.Context, uid int64) (user_info models.User_info, err error)
	UpdateUserInfo(ctx context.Context, uid int64, email string, name string) (bool, error)
}

func New(log *slog.Logger, infoProvider User_info_Provider) *User_info {
	return &User_info{
		log:          log,
		infoProvider: infoProvider,
	}
}

func (u *User_info) DeleteUser(ctx context.Context, uid int64) (bool, error) {
	const op = "user_info.DeleteUser"
	log := u.log.With(slog.String("op", op), slog.Int64("user_id", uid))
	log.Info("attempting to delete user")
	res, err := u.infoProvider.DeleteUser(ctx, uid)
	if err != nil {
		if errors.Is(err, storage.ErrUserNotFound) {
			log.Warn("user not found", slog.Int64("user_id", uid))
			return false, err
		}
		log.Error("failed to delete user", slog.Any("error", err))
		return false, err
	}
	log.Info("user deleted successfully")
	return res, nil
}

func (u *User_info) GetUserInfo(ctx context.Context, uid int64) (user_info models.User_info, err error) {
	const op = "user_info.GetUserInfo"
	log := u.log.With(slog.String("op", op), slog.Int64("user_id", uid))
	log.Info("attempting to get user info")

	user_info, err = u.infoProvider.GetUserInfo(ctx, uid)
	if err != nil {
		if errors.Is(err, storage.ErrUserNotFound) {
			log.Warn("user not found", slog.Int64("user_id", uid))
			return models.User_info{}, err
		}
		log.Error("failed to get user info", slog.Any("error", err))
		return models.User_info{}, err
	}
	log.Info("user info retrieved successfully")
	return user_info, nil
}

func (u *User_info) UpdateUserInfo(ctx context.Context, uid int64, email string, name string) (bool, error) {
	const op = "user_info.UpdateUserInfo"
	log := u.log.With(slog.String("op", op), slog.Int64("user_id", uid), slog.String("email", email), slog.String("name", name))
	log.Info("attempting to update user info")
	res, err := u.infoProvider.UpdateUserInfo(ctx, uid, email, name)
	if err != nil {
		if errors.Is(err, storage.ErrUserNotFound) {
			log.Warn("user not found", slog.Int64("user_id", uid))
			return false, err
		}
		log.Error("failed to update user info", slog.Any("error", err))
		return false, err
	}
	log.Info("user info updated successfully")
	return res, nil
}
