package v1

import (
	"context"
	"net/http"

	"github.com/go-faster/errors"
	"github.com/kaynelza/cloud-files/internal/infrastructure/entity"
	api "github.com/kaynelza/cloud-files/pkg/openapi/v1"
	"go.uber.org/zap"
)

func (s *Server) NewError(ctx context.Context, err error) *api.ErrorResponseStatusCode {
	s.log.Debug("Error occurred", zap.Error(err))

	switch {

	case errors.Is(err, entity.ErrBadRequest):
		return &api.ErrorResponseStatusCode{
			StatusCode: http.StatusBadRequest,
			Response:   api.ErrorResponse{Message: err.Error()},
		}

	default:
		return &api.ErrorResponseStatusCode{
			StatusCode: http.StatusInternalServerError,
			Response:   api.ErrorResponse{Message: "internal server error"},
		}
	}
}
