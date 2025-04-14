package storage

import "errors"

var (
	ErrUserExists         = errors.New("user already exists")
	ErrUserNotFound       = errors.New("user not found")
	ErrAppNotFound        = errors.New("app not found")
	ErrPermissionExists   = errors.New("permission already exists")
	ErrPermissionNotFound = errors.New("permission not found")
	ErrUserHasPermissions = errors.New("user has permissions and cannot be deleted")
)

var AllPermissions = []string{
	"read",
	"write",
	"delete",
	"update",
}
