package app

import (
	"context"
	"log/slog"
	grpcapp "sso/internal/app/grpc"
	"sso/internal/services/auth"
	"sso/internal/services/permissions"
	userinfo "sso/internal/services/user_info"
	"sso/internal/storage/postgres"
	"time"
)

type App struct {
	GRPCSrv *grpcapp.App
}

func New(log *slog.Logger, grpcPort int, storagePath string, tokenTTL time.Duration) *App {
	storage, err := postgres.New(context.Background(), storagePath)
	if err != nil {
		panic(err)
	}
	authService := auth.New(log, storage, storage, storage, tokenTTL)
	permissionsService := permissions.New(log, storage)
	user_info_Service := userinfo.New(log, storage)
	grpcApp := grpcapp.New(log, authService, permissionsService, user_info_Service, grpcPort)

	return &App{
		GRPCSrv: grpcApp,
	}
}
