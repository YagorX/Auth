package auth

import (
	"context"
	"errors"

	ssov1 "github.com/YagorX/protos/gen/go/sso"
	"github.com/google/uuid"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	authsvc "sso/internal/storage"
)

type Auth interface {
	Login(ctx context.Context, email, password string, appID int) (refreshToken, accessToken string, err error)
	RegisterNewUser(ctx context.Context, email, password string) (uuid.UUID, error)
	IsAdminByUUID(ctx context.Context, userUUID uuid.UUID) (bool, error)
	ValidateToken(ctx context.Context, token string, appID int64) (uuid.UUID, error)
	Refresh(ctx context.Context, refreshToken string, appID int) (accessToken, newRefreshToken string, err error)
	Logout(ctx context.Context, refreshToken string) error
}

type serverAPI struct {
	ssov1.UnimplementedAuthServer
	auth Auth
}

const emptyValue = 0

func Register(gRPC *grpc.Server, auth Auth) {
	ssov1.RegisterAuthServer(gRPC, &serverAPI{auth: auth})
}

/*
====================
Handlers
====================
*/

func (s *serverAPI) Register(ctx context.Context, req *ssov1.RegisterRequest) (*ssov1.RegisterResponse, error) {
	if err := validateRegister(req); err != nil {
		return nil, err
	}

	userUUID, err := s.auth.RegisterNewUser(ctx, req.GetEmail(), req.GetPassword())
	if err != nil {
		if errors.Is(err, authsvc.ErrUserExist) {
			return nil, status.Error(codes.AlreadyExists, "user already exists")
		}
		return nil, status.Error(codes.Internal, "internal error")
	}

	return &ssov1.RegisterResponse{
		UserUuid: userUUID.String(),
	}, nil
}

func (s *serverAPI) Login(ctx context.Context, req *ssov1.LoginRequest) (*ssov1.LoginResponse, error) {
	if err := validateLogin(req); err != nil {
		return nil, err
	}

	refreshToken, accessToken, err := s.auth.Login(ctx, req.GetEmail(), req.GetPassword(), int(req.GetAppId()))
	if err != nil {
		if errors.Is(err, authsvc.ErrInvalidCredentials) {
			return nil, status.Error(codes.InvalidArgument, "invalid email or password")
		}
		return nil, status.Error(codes.Internal, "internal error")
	}

	return &ssov1.LoginResponse{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
	}, nil
}

func (s *serverAPI) IsAdmin(ctx context.Context, req *ssov1.IsAdminRequest) (*ssov1.IsAdminResponse, error) {
	if err := validateIsAdmin(req); err != nil {
		return nil, err
	}

	userUUID, err := uuid.Parse(req.GetUserUuid())
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, "invalid user_uuid")
	}

	isAdmin, err := s.auth.IsAdminByUUID(ctx, userUUID)
	if err != nil {
		if errors.Is(err, authsvc.ErrUserNotFound) {
			return nil, status.Error(codes.NotFound, "user not found")
		}
		return nil, status.Error(codes.Internal, "internal error")
	}

	return &ssov1.IsAdminResponse{IsAdmin: isAdmin}, nil
}

func (s *serverAPI) ValidateToken(ctx context.Context, req *ssov1.ValidateTokenRequest) (*ssov1.ValidateTokenResponse, error) {
	if err := validateValidateToken(req); err != nil {
		return nil, err
	}

	userUUID, err := s.auth.ValidateToken(ctx, req.GetToken(), req.GetAppId())
	if err != nil {
		if errors.Is(err, authsvc.ErrInvalidToken) {
			return nil, status.Error(codes.Unauthenticated, "invalid token")
		}
		if errors.Is(err, authsvc.ErrUserNotFound) {
			return nil, status.Error(codes.NotFound, "user not found")
		}
		return nil, status.Error(codes.Internal, "internal error")
	}

	return &ssov1.ValidateTokenResponse{
		UserUuid: userUUID.String(),
	}, nil
}

func (s *serverAPI) Refresh(ctx context.Context, req *ssov1.RefreshRequest) (*ssov1.RefreshResponse, error) {
	if err := validateRefresh(req); err != nil {
		return nil, err
	}

	access, refresh, err := s.auth.Refresh(ctx, req.GetRefreshToken(), int(req.GetAppId()))
	if err != nil {
		if errors.Is(err, authsvc.ErrInvalidToken) {
			return nil, status.Error(codes.Unauthenticated, "invalid refresh token")
		}
		return nil, status.Error(codes.Internal, "internal error")
	}

	return &ssov1.RefreshResponse{
		AccessToken:  access,
		RefreshToken: refresh,
	}, nil
}

func (s *serverAPI) Logout(ctx context.Context, req *ssov1.LogoutRequest) (*ssov1.LogoutResponse, error) {
	if err := validateLogout(req); err != nil {
		return nil, err
	}

	// Logout идемпотентный — даже если токен уже отозван, можно вернуть OK.
	_ = s.auth.Logout(ctx, req.GetRefreshToken())

	return &ssov1.LogoutResponse{}, nil
}

/*
====================
Validation
====================
*/

func validateRegister(req *ssov1.RegisterRequest) error {
	if req.GetEmail() == "" {
		return status.Error(codes.InvalidArgument, "email is required")
	}
	if req.GetPassword() == "" {
		return status.Error(codes.InvalidArgument, "password is required")
	}
	return nil
}

func validateLogin(req *ssov1.LoginRequest) error {
	if req.GetEmail() == "" {
		return status.Error(codes.InvalidArgument, "email is required")
	}
	if req.GetPassword() == "" {
		return status.Error(codes.InvalidArgument, "password is required")
	}
	if req.GetAppId() == emptyValue {
		return status.Error(codes.InvalidArgument, "app_id is required")
	}
	return nil
}

func validateIsAdmin(req *ssov1.IsAdminRequest) error {
	if req.GetUserUuid() == "" {
		return status.Error(codes.InvalidArgument, "user_uuid is required")
	}
	return nil
}

func validateValidateToken(req *ssov1.ValidateTokenRequest) error {
	if req.GetToken() == "" {
		return status.Error(codes.InvalidArgument, "token is required")
	}
	if req.GetAppId() == 0 {
		return status.Error(codes.InvalidArgument, "app_id is required")
	}
	return nil
}

func validateRefresh(req *ssov1.RefreshRequest) error {
	if req.GetRefreshToken() == "" {
		return status.Error(codes.InvalidArgument, "refresh_token is required")
	}
	if req.GetAppId() == 0 {
		return status.Error(codes.InvalidArgument, "app_id is required")
	}
	return nil
}

func validateLogout(req *ssov1.LogoutRequest) error {
	if req.GetRefreshToken() == "" {
		return status.Error(codes.InvalidArgument, "refresh_token is required")
	}
	return nil
}
