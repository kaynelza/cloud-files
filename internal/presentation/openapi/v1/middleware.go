package v1

import (
	"context"

	"github.com/go-faster/errors"
	"github.com/kaynelza/cloud-files/internal/infrastructure/entity"
	"github.com/ogen-go/ogen/middleware"
)

func (s *Server) AccessTokenMiddleware(req middleware.Request, next middleware.Next) (middleware.Response, error) {
	val, ok := req.Params.Header("Authorization")
	if !ok {
		return middleware.Response{}, errors.Wrap(entity.ErrUnauthorized, "JWT not provided")
	}
	token, ok := val.(string)
	if !ok {
		return middleware.Response{}, errors.Wrap(entity.ErrUnauthorized, "invalid JWT")
	}

	if err := s.tokenizer.CheckToken(req.Context, token); err != nil {
		return middleware.Response{}, errors.Wrap(entity.ErrUnauthorized, "invalid token")
	}

	req.SetContext(context.WithValue(req.Context, entity.AuthTokenKey, token))

	return next(req)
}
