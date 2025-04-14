package userinfo

import (
	"context"
	"sso/internal/domain/models"

	ssov1 "github.com/Drondobycha/proto/gen/go/sso"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const empty_value = 0

type User_info interface {
	DeleteUser(ctx context.Context, uid int64) (bool, error)
	GetUserInfo(ctx context.Context, uid int64) (user_info models.User_info, err error)
	UpdateUserInfo(ctx context.Context, uid int64, email string, name string) (bool, error)
}

type serverAPI struct {
	ssov1.UnimplementedUserInfoServer
	User_info User_info
}

func Register(gRPC *grpc.Server, user_info User_info) {
	ssov1.RegisterUserInfoServer(gRPC, &serverAPI{User_info: user_info})
}

func (s *serverAPI) DeleteUser(ctx context.Context, req *ssov1.DeleteUserRequest) (*ssov1.DeleteUserResponse, error) {
	if err := ValidateDeleteUser(req); err != nil {
		return nil, err
	}
	delete, err := s.User_info.DeleteUser(ctx, req.GetUserId())
	if err != nil {
		return nil, status.Error(codes.Internal, "internal error")
	}
	return &ssov1.DeleteUserResponse{
		Success: delete,
	}, nil
}

func (s *serverAPI) GetUserInfo(ctx context.Context, req *ssov1.GetUserInfoRequest) (*ssov1.GetUserInfoResponse, error) {
	if err := ValidateGetUserInfo(req); err != nil {
		return nil, err
	}
	user_info, err := s.User_info.GetUserInfo(ctx, req.GetUserId())
	if err != nil {
		return nil, status.Error(codes.Internal, "internal error")
	}
	return &ssov1.GetUserInfoResponse{
		UserId:        user_info.User_id,
		Email:         user_info.Email,
		Name:          user_info.Name,
		EmailVerified: user_info.Email_verified,
		CreatedAt:     user_info.Create_at,
	}, nil
}

func (s *serverAPI) UpdateUserInfo(ctx context.Context, req *ssov1.UpdateUserInfoRequest) (*ssov1.UpdateUserInfoResponse, error) {
	if err := ValidateUpdateUserInfo(req); err != nil {
		return nil, err
	}
	update, err := s.User_info.UpdateUserInfo(ctx, req.GetUserId(), req.GetEmail(), req.GetName())
	if err != nil {
		return nil, status.Error(codes.Internal, "internal error")
	}
	return &ssov1.UpdateUserInfoResponse{
		Success: update,
	}, nil
}

func ValidateDeleteUser(req *ssov1.DeleteUserRequest) error {
	if req.GetUserId() == empty_value {
		return status.Error(codes.InvalidArgument, "user_id is required")
	}
	return nil
}

func ValidateGetUserInfo(req *ssov1.GetUserInfoRequest) error {
	if req.GetUserId() == empty_value {
		return status.Error(codes.InvalidArgument, "user_id is required")
	}
	return nil
}

func ValidateUpdateUserInfo(req *ssov1.UpdateUserInfoRequest) error {
	if req.GetUserId() == empty_value {
		return status.Error(codes.InvalidArgument, "user_id is required")
	}
	// If the fields are optional, do not enforce validation for empty values.
	// Uncomment the following checks if these fields should be mandatory.
	/*
		if req.GetEmail() == "" {
			return status.Error(codes.InvalidArgument, "email is required")
		}
		if req.GetName() == "" {
			return status.Error(codes.InvalidArgument, "name is required")
		}
	*/
	return nil
}
