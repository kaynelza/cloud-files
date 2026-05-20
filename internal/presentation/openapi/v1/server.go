package v1

import (
	"context"
	"regexp"

	"github.com/go-faster/errors"
	"github.com/google/uuid"
	"github.com/kaynelza/cloud-files/internal/infrastructure/entity"
	"github.com/kaynelza/cloud-files/pkg/openapi/v1"
	"go.uber.org/zap"
	"golang.org/x/crypto/bcrypt"
)

type (
	Server struct {
		emailRegexp    *regexp.Regexp
		passwordRegexp *regexp.Regexp

		repo      Storage
		tokenizer Tokenizer

		log *zap.Logger
	}

	Storage interface {
		CreateNewUser(ctx context.Context, credentials *entity.UserCredentials) (entity.User, error)
		GetHashedPassword(ctx context.Context, email string) ([]byte, error)
		GetUserByRefreshToken(ctx context.Context, token string) (entity.User, error)
		UpdateRefreshToken(ctx context.Context, refreshToken string, user entity.User) error
		GetUser(ctx context.Context, email string) (uuid.UUID, error)
	}

	Tokenizer interface {
		NewTokens(ctx context.Context, user entity.User) (entity.Tokens, error)
	}
)

func New() (*Server, error) {
	eReg, err := regexp.Compile("^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}$")
	if err != nil {
		return nil, errors.Wrap(err, "regexp e-mail")
	}

	pReg, err := regexp.Compile("^(?=.*[A-Za-z])(?=.*\\d)[A-Za-z\\d]{8,}$")
	if err != nil {
		return nil, errors.Wrap(err, "regexp password")
	}

	return &Server{emailRegexp: eReg,
		passwordRegexp: pReg}, nil
}

func (s *Server) APIV1AuthRefreshPost(ctx context.Context, params api.APIV1AuthRefreshPostParams) (*api.APIV1AuthRefreshPostOK, error) {
	user, err := s.repo.GetUserByRefreshToken(ctx, params.Token)
	if err != nil {
		return nil, errors.Wrap(err, "get refresh token")
	}

	token, err := s.tokenizer.NewTokens(ctx, user)
	if err != nil {
		return nil, errors.Wrap(err, "new tokens")
	}

	if err = s.repo.UpdateRefreshToken(ctx, token.Refresh, user); err != nil {
		return nil, errors.Wrap(err, "update refresh token")
	}

	return &api.APIV1AuthRefreshPostOK{
		AccessToken:  token.Access,
		RefreshToken: token.Refresh,
	}, nil
}

func (s *Server) APIV1AuthSignInPost(ctx context.Context, req *api.APIV1AuthSignInPostReq) (*api.APIV1AuthSignInPostOK, error) {
	if !s.emailRegexp.MatchString(req.Email) {
		return nil, errors.Wrap(entity.ErrBadRequest, "invalid email")
	}
	if !s.passwordRegexp.MatchString(req.Password) {
		return nil, errors.Wrap(entity.ErrBadRequest, "invalid password")
	}

	hash, err := s.repo.GetHashedPassword(ctx, req.Email)
	if err != nil {
		return nil, errors.Wrap(err, "get user credentials")
	}

	if err = bcrypt.CompareHashAndPassword(hash, []byte(req.Password)); err != nil {
		return nil, errors.Wrap(entity.ErrBadRequest, "invalid password")
	}

	ID, err := s.repo.GetUser(ctx, req.Email) // todo: dep
	if err != nil {
		return nil, errors.Wrap(err, "get user")
	}

	tokens, err := s.tokenizer.NewTokens(ctx, entity.User{
		ID:    ID,
		Email: req.Email,
	})
	if err != nil {
		return nil, errors.Wrap(err, "new tokens")
	}

	return &api.APIV1AuthSignInPostOK{
		AccessToken:  tokens.Access,
		RefreshToken: tokens.Refresh,
	}, nil

}

func (s *Server) APIV1AuthSignUpPost(ctx context.Context, req *api.APIV1AuthSignUpPostReq) (*api.APIV1AuthSignUpPostOK, error) {
	if !s.emailRegexp.MatchString(req.Email) {
		return nil, errors.Wrap(entity.ErrBadRequest, "invalid email")
	}

	if !s.passwordRegexp.MatchString(req.Password) {
		return nil, errors.Wrap(entity.ErrBadRequest, "invalid password")
	}

	user, err := s.repo.CreateNewUser(ctx, &entity.UserCredentials{
		Email:    req.Email,
		Password: req.Password,
	})
	if err != nil {
		return nil, errors.Wrap(err, "create new user")
	}

	tokens, err := s.tokenizer.NewTokens(ctx, user)
	if err != nil {
		return nil, errors.Wrap(err, "create tokens")
	}

	return &api.APIV1AuthSignUpPostOK{
		AccessToken:  tokens.Access,
		RefreshToken: tokens.Refresh,
	}, nil
}

func (s *Server) APIV1CloudStorageMyDownloadIDGet(ctx context.Context, params api.APIV1CloudStorageMyDownloadIDGetParams) (api.APIV1CloudStorageMyDownloadIDGetRes, error) {
	//TODO implement me
	panic("implement me")
}

func (s *Server) APIV1CloudStorageMyFileInfoGet(ctx context.Context, params api.APIV1CloudStorageMyFileInfoGetParams) (*api.APIV1CloudStorageMyFileInfoGetOK, error) {
	//TODO implement me
	panic("implement me")
}

func (s *Server) APIV1CloudStorageMyGet(ctx context.Context, params api.APIV1CloudStorageMyGetParams) (*api.APIV1CloudStorageMyGetOK, error) {
	//TODO implement me
	panic("implement me")
}

func (s *Server) APIV1CloudStorageMyUploadPost(ctx context.Context, req *api.APIV1CloudStorageMyUploadPostReq) (api.APIV1CloudStorageMyUploadPostRes, error) {
	//TODO implement me
	panic("implement me")
}

func (s *Server) APIV1CloudStorageMyUploadUploadIDCompletePost(ctx context.Context, params api.APIV1CloudStorageMyUploadUploadIDCompletePostParams) (api.APIV1CloudStorageMyUploadUploadIDCompletePostRes, error) {
	//TODO implement me
	panic("implement me")
}

func (s *Server) APIV1CloudStorageMyUploadUploadIDGet(ctx context.Context, params api.APIV1CloudStorageMyUploadUploadIDGetParams) (api.APIV1CloudStorageMyUploadUploadIDGetRes, error) {
	//TODO implement me
	panic("implement me")
}

func (s *Server) APIV1CloudStorageMyUploadUploadIDPut(ctx context.Context, req api.APIV1CloudStorageMyUploadUploadIDPutReq, params api.APIV1CloudStorageMyUploadUploadIDPutParams) (api.APIV1CloudStorageMyUploadUploadIDPutRes, error) {
	//TODO implement me
	panic("implement me")
}
