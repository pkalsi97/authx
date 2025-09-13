package handlers

import (
	"context"

	"github.com/pkalsi97/authx/internal/db"
	"github.com/pkalsi97/authx/internal/utils"
	pb "github.com/pkalsi97/authx/proto"
)

type AuthServer struct {
	pb.UnimplementedAuthServiceServer
}

func (s *AuthServer) IntrospectToken(ctx context.Context, req *pb.IntrospectRequest) (*pb.IntrospectResponse, error) {
	token := req.Token

	userId, userpool, err := utils.ExtractInfo(token)
	if err != nil {
		return &pb.IntrospectResponse{Active: false}, nil
	}

	permissions, roles, err := db.GetUserRolesAndPermissions(ctx, userId)
	if err != nil {
		return &pb.IntrospectResponse{Active: false}, nil
	}

	if err := utils.ValidateAccessToken(token, permissions, roles); err != nil {
		return &pb.IntrospectResponse{Active: false}, nil
	}

	return &pb.IntrospectResponse{
		Active:   true,
		Sub:      userId,
		Userpool: userpool,
		Scopes:   permissions,
		Roles:    roles,
	}, nil
}
