package permissions

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sso/internal/lib/logger/sl"
)

var (
	ErrInvalidPermissions = errors.New("invalid permissions")
	ErrUserNotFound       = errors.New("user not found")
	ErrPermissionExists   = errors.New("permission already exists")
	ErrPermissionNotFound = errors.New("permission not found")
)

type Permissions struct {
	log          *slog.Logger
	permProvider PermissionsProvider
}

type PermissionsProvider interface {
	AddPerm(ctx context.Context, uid int64, addedPerm string) (res bool, err error)
	RemovePerm(ctx context.Context, uid int64, RemovedPerm string) (res bool, err error)
	CheckPerm(ctx context.Context, uid int64, CheckedPerm string) (res bool, err error)
	ListPerm(ctx context.Context, uid int64) (list_permission []string, err error)
}

func New(log *slog.Logger, permProvider PermissionsProvider) *Permissions {
	return &Permissions{
		log:          log,
		permProvider: permProvider,
	}
}

func (p *Permissions) AddPerm(ctx context.Context, uid int64, addedPerm string) (res bool, err error) {
	const op = "permissions.AddPerm"
	log := p.log.With(slog.String("op", op), slog.Int64("user_id", uid), slog.String("permission", addedPerm))
	log.Info("attempting to add permission")
	res, err = p.permProvider.AddPerm(ctx, uid, addedPerm)
	if err != nil {
		if errors.Is(err, ErrUserNotFound) {
			log.Warn("user not found", sl.Err(err))
			return false, fmt.Errorf("%s: %w", op, ErrUserNotFound)
		}
		if errors.Is(err, ErrPermissionExists) {
			log.Warn("permission already exists", sl.Err(err))
			return false, fmt.Errorf("%s: %w", op, ErrPermissionExists)
		}
		log.Error("failed to add permission", sl.Err(err))
		return false, err
	}
	log.Info("permission added successfully")
	return res, nil
}

func (p *Permissions) RemovePerm(ctx context.Context, uid int64, RemovedPerm string) (res bool, err error) {
	const op = "permissions.RemovePerm"
	log := p.log.With(slog.String("op", op), slog.Int64("user_id", uid), slog.String("permission", RemovedPerm))
	log.Info("attempting to remove permission")
	res, err = p.permProvider.RemovePerm(ctx, uid, RemovedPerm)
	if err != nil {
		if errors.Is(err, ErrUserNotFound) {
			log.Warn("user not found", sl.Err(err))
			return false, fmt.Errorf("%s: %w", op, ErrUserNotFound)
		}
		if errors.Is(err, ErrPermissionNotFound) {
			log.Warn("permission not found", sl.Err(err))
			return false, fmt.Errorf("%s: %w", op, ErrPermissionNotFound)
		}
		log.Error("failed to remove permission", sl.Err(err))
		return false, err
	}
	log.Info("permission removed successfully")
	return res, nil
}

func (p *Permissions) CheckPerm(ctx context.Context, uid int64, CheckedPerm string) (res bool, err error) {
	const op = "permissions.CheckPerm"
	log := p.log.With(slog.String("op", op), slog.Int64("user_id", uid), slog.String("permission", CheckedPerm))
	log.Info("attempting to check permission")
	res, err = p.permProvider.CheckPerm(ctx, uid, CheckedPerm)
	if err != nil {
		if errors.Is(err, ErrUserNotFound) {
			log.Warn("user not found", sl.Err(err))
			return false, fmt.Errorf("%s: %w", op, ErrUserNotFound)
		}
		log.Error("failed to check permission", sl.Err(err))
		return false, err
	}
	log.Info("permission checked successfully")
	if res {
		log.Info("user has permission")
	} else {
		log.Info("user does not have permission")
	}
	return res, nil
}

func (p *Permissions) ListPerm(ctx context.Context, uid int64) (list_permission []string, err error) {
	return []string{"reed"}, nil
}
