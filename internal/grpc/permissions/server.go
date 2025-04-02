package permissions

import (
	"context"
	"slices"
	"sso/internal/storage"

	ssov1 "github.com/Drondobycha/proto/gen/go/sso"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const empty_value = 0

type Permissions interface {
	AddPerm(ctx context.Context, uid int64, addedPerm string) (res bool, err error)
	RemovePerm(ctx context.Context, uid int64, RemovedPerm string) (res bool, err error)
	CheckPerm(ctx context.Context, uid int64, CheckedPerm string) (res bool, err error)
	ListPerm(ctx context.Context, uid int64) (list_permission []string, err error)
}

type serverAPI struct {
	ssov1.UnimplementedPermissionsServer
	permissions Permissions
}

func Register(gRPC *grpc.Server, permissions Permissions) {
	ssov1.RegisterPermissionsServer(gRPC, &serverAPI{permissions: permissions})
}

func (s *serverAPI) CheckPermission(ctx context.Context, req *ssov1.CheckPermissionRequest) (*ssov1.CheckPermissionResponse, error) {
	if err := ValidateCheckPermission(req); err != nil {
		return nil, err
	}
	check, err := s.permissions.CheckPerm(ctx, req.GetUserId(), req.GetPermission())
	if err != nil {
		return nil, status.Error(codes.Internal, "internal error")
	}
	return &ssov1.CheckPermissionResponse{
		HasPermission: check,
	}, nil
}

func (s *serverAPI) AddPermission(ctx context.Context, req *ssov1.AddPermissionRequest) (*ssov1.AddPermissionResponse, error) {
	if err := ValidateAddPermission(req); err != nil {
		return nil, err
	}
	add, err := s.permissions.AddPerm(ctx, req.GetUserId(), req.GetPermission())
	if err != nil {
		return nil, status.Error(codes.Internal, "internal error")
	}
	return &ssov1.AddPermissionResponse{
		Success: add,
	}, nil
}

func (s *serverAPI) ListPermissions(ctx context.Context, req *ssov1.ListPermissionsRequest) (*ssov1.ListPermissionsResponse, error) {
	if err := ValidateListPermissions(req); err != nil {
		return nil, err
	}
	list, err := s.permissions.ListPerm(ctx, req.GetUserId())
	if err != nil {
		return nil, status.Error(codes.Internal, "internal error")
	}
	return &ssov1.ListPermissionsResponse{
		Permissions: list,
	}, nil
}

func (s *serverAPI) RemovePermissionc(ctx context.Context, req *ssov1.RemovePermissionRequest) (*ssov1.RemovePermissionResponse, error) {
	if err := ValidateRemovePermissions(req); err != nil {
		return nil, err
	}
	remove, err := s.permissions.RemovePerm(ctx, req.GetUserId(), req.GetPermission())
	if err != nil {
		return nil, status.Error(codes.Internal, "internal error")
	}

	return &ssov1.RemovePermissionResponse{
		Success: remove,
	}, nil
}

func ValidateCheckPermission(req *ssov1.CheckPermissionRequest) error {
	if req.GetUserId() == empty_value {
		return status.Error(codes.InvalidArgument, "user_id is required")
	}

	if req.GetPermission() == "" {
		return status.Error(codes.InvalidArgument, "permission is required")
	}
	if !slices.Contains(storage.AllPermissions, req.GetPermission()) {
		return status.Error(codes.InvalidArgument, "invalid permission")
	}
	return nil
}

func ValidateAddPermission(req *ssov1.AddPermissionRequest) error {
	if req.GetUserId() == empty_value {
		return status.Error(codes.InvalidArgument, "user_id is required")
	}

	if req.GetPermission() == "" {
		return status.Error(codes.InvalidArgument, "permission is required")
	}
	if !slices.Contains(storage.AllPermissions, req.GetPermission()) {
		return status.Error(codes.InvalidArgument, "invalid permission")
	}
	return nil
}

func ValidateListPermissions(req *ssov1.ListPermissionsRequest) error {
	if req.GetUserId() == empty_value {
		return status.Error(codes.InvalidArgument, "user_id is required")
	}
	return nil
}

func ValidateRemovePermissions(req *ssov1.RemovePermissionRequest) error {
	if req.GetUserId() == empty_value {
		return status.Error(codes.InvalidArgument, "user_id is required")
	}

	if req.GetPermission() == "" {
		return status.Error(codes.InvalidArgument, "permission is required")
	}
	if !slices.Contains(storage.AllPermissions, req.GetPermission()) {
		return status.Error(codes.InvalidArgument, "invalid permission")
	}
	return nil
}
