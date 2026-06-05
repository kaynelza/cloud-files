package v1

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"math"
	"path"
	"regexp"
	"strings"
	"time"

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
		GetUserFiles(ctx context.Context, user entity.User, limit, page int) ([]entity.File, int, float64, error)
		GetUserFile(ctx context.Context, user entity.User, path string) (entity.File, error)
		GetUserFileData(ctx context.Context, user entity.User, id string) ([]byte, error)
		CreateUploadSession(ctx context.Context, duration time.Duration, user entity.User, session entity.UploadSession) (string, string, error)
		GetInfoAboutCompletedFile(ctx context.Context, id string) (entity.File, error)
		MarkUploadCompleted(ctx context.Context, id string) error
		GetInfoAboutUploadSession(ctx context.Context, id string) (entity.UploadIDSession, error)
		AppendFileBytes(ctx context.Context, id string, data []byte) (int, error)
	}

	Tokenizer interface {
		NewTokens(ctx context.Context, user entity.User) (entity.Tokens, error)
		GetUser(ctx context.Context, token string) (entity.User, error)
		CheckToken(ctx context.Context, token string) error
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
	if err := s.ValidateCreds(req.Email, req.Password); err != nil {
		return nil, errors.New("invalid credentials")
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
	if err := s.ValidateFile(params.ID); err != nil {
		return nil, errors.Wrap(err, "invalid file")
	}

	user, err := s.userFromContext(ctx)
	if err != nil {
		return nil, errors.Wrap(err, "get user")
	}

	data, err := s.repo.GetUserFileData(ctx, user, params.ID)
	if err != nil {
		return nil, errors.Wrap(err, "get file data")
	}

	return &api.APIV1CloudStorageMyDownloadIDGetOK{Data: bytes.NewReader(data)}, nil
}

func (s *Server) APIV1CloudStorageMyFileInfoGet(ctx context.Context, params api.APIV1CloudStorageMyFileInfoGetParams) (*api.APIV1CloudStorageMyFileInfoGetOK, error) {
	if err := s.ValidateFile(params.File); err != nil {
		return nil, errors.Wrap(err, "invalid file")
	}

	user, err := s.userFromContext(ctx)
	if err != nil {
		return nil, errors.Wrap(err, "get user")
	}

	file, err := s.repo.GetUserFile(ctx, user, params.File)
	if err != nil {
		return nil, errors.Wrap(err, "get file")
	}

	return &api.APIV1CloudStorageMyFileInfoGetOK{
		ID:        file.Id,
		Name:      file.Name,
		Size:      file.Size,
		MimeType:  file.MimeType,
		FilePath:  file.FilePath,
		CreatedAt: file.CreatedAt.String(),
	}, nil
}

func (s *Server) APIV1CloudStorageMyGet(ctx context.Context, params api.APIV1CloudStorageMyGetParams) (*api.APIV1CloudStorageMyGetOK, error) {
	user, err := s.userFromContext(ctx)
	if err != nil {
		return nil, errors.Wrap(err, "get user")
	}

	files, total, usedGbs, err := s.repo.GetUserFiles(ctx, user, params.Limit, params.Page)
	if err != nil {
		return nil, errors.Wrap(err, "get user files")
	}

	return &api.APIV1CloudStorageMyGetOK{
		Files:   convertEntityToApiFiles(files),
		Total:   total,
		UsedGbs: usedGbs,
	}, nil

}

func (s *Server) APIV1CloudStorageMyUploadPost(ctx context.Context, req *api.APIV1CloudStorageMyUploadPostReq) (api.APIV1CloudStorageMyUploadPostRes, error) {
	if err := validateUploadRequest(req); err != nil {
		return nil, errors.Wrap(err, "invalid upload request")
	}

	user, err := s.userFromContext(ctx)
	if err != nil {
		return nil, errors.Wrap(err, "get user")
	}

	uploadID, expiresAt, err := s.repo.CreateUploadSession(ctx, entity.UploadSessionLifetime, user, entity.UploadSession{
		FileName: req.Name,
		Size:     req.Size,
		MimeType: req.MimeType,
		FilePath: req.FilePath,
	})
	if err != nil {
		return nil, errors.Wrap(err, "create upload session")
	}

	return &api.APIV1CloudStorageMyUploadPostCreated{
		UploadID:  uploadID,
		ChunkSize: entity.DefaultChunkSize,
		ExpiresAt: expiresAt,
	}, nil
}

func (s *Server) APIV1CloudStorageMyUploadUploadIDCompletePost(ctx context.Context, params api.APIV1CloudStorageMyUploadUploadIDCompletePostParams) (api.APIV1CloudStorageMyUploadUploadIDCompletePostRes, error) {
	if err := s.ValidateFile(params.UploadID); err != nil {
		return nil, errors.Wrap(err, "invalid file")
	}

	fileSession, err := s.repo.GetInfoAboutCompletedFile(ctx, params.UploadID)
	if err != nil {
		return nil, errors.Wrap(err, "get file info")
	}

	if err := s.repo.MarkUploadCompleted(ctx, params.UploadID); err != nil { // todo: mark completed
		return nil, errors.Wrap(err, "delete upload id")
	}

	return &api.APIV1CloudStorageMyUploadUploadIDCompletePostOK{
		ID:        fileSession.Id,
		Name:      fileSession.Name,
		Size:      fileSession.Size,
		MimeType:  fileSession.MimeType,
		FilePath:  fileSession.FilePath,
		CreatedAt: fileSession.CreatedAt.String(),
	}, nil
}

func (s *Server) APIV1CloudStorageMyUploadUploadIDGet(ctx context.Context, params api.APIV1CloudStorageMyUploadUploadIDGetParams) (api.APIV1CloudStorageMyUploadUploadIDGetRes, error) {
	if err := s.ValidateFile(params.UploadID); err != nil {
		return nil, errors.Wrap(err, "invalid file")
	}

	fileSession, err := s.repo.GetInfoAboutUploadSession(ctx, params.UploadID)
	if err != nil {
		return nil, errors.Wrap(err, "get upload session")
	}

	var recievedRanges []string
	for i := 0; i <= fileSession.ReceivedBytes; i += fileSession.ChunkSize {
		bytesRange := fmt.Sprintf("%f-%f", i, math.Min(float64(i+fileSession.ChunkSize), float64(fileSession.Size)))
		recievedRanges = append(recievedRanges, bytesRange)
	}

	return &api.APIV1CloudStorageMyUploadUploadIDGetOK{
		UploadID:       fileSession.UploadID,
		Name:           fileSession.Name,
		Size:           fileSession.Size,
		ReceivedBytes:  fileSession.ReceivedBytes,
		ReceivedRanges: recievedRanges,
		ChunkSize:      fileSession.ChunkSize,
		ExpiresAt:      fileSession.ExpiresAt,
	}, nil
}

func (s *Server) APIV1CloudStorageMyUploadUploadIDPut(ctx context.Context, req api.APIV1CloudStorageMyUploadUploadIDPutReq, params api.APIV1CloudStorageMyUploadUploadIDPutParams) (api.APIV1CloudStorageMyUploadUploadIDPutRes, error) {
	if err := s.ValidateFile(params.UploadID); err != nil {
		return nil, errors.Wrap(err, "invalid file")
	}

	r := bufio.NewReader(req.Data)

	if entity.DefaultChunkSize < r.Size() {
		return nil, errors.New("chunk size is too big")
	}

	data, err := io.ReadAll(r)
	if err != nil {
		return nil, errors.Wrap(err, "read data")
	}

	fileSize, err := s.repo.AppendFileBytes(ctx, params.UploadID, data)
	if err != nil {
		return nil, errors.Wrap(err, "update received bytes")
	}

	return &api.APIV1CloudStorageMyUploadUploadIDPutOK{
		UploadID:      params.UploadID,
		ReceivedBytes: r.Size(),
		TotalBytes:    fileSize,
	}, nil
}

func convertEntityToApiFile(f entity.File) api.APIV1CloudStorageMyGetOKFilesItem {
	return api.APIV1CloudStorageMyGetOKFilesItem{
		ID:        f.Id,
		Name:      f.Name,
		Size:      f.Size,
		MimeType:  f.MimeType,
		FilePath:  f.FilePath,
		CreatedAt: f.CreatedAt.String(),
	}
}

func convertEntityToApiFiles(f []entity.File) []api.APIV1CloudStorageMyGetOKFilesItem {
	result := make([]api.APIV1CloudStorageMyGetOKFilesItem, 0, len(f))
	for _, file := range f {
		result = append(result, convertEntityToApiFile(file))
	}
	return result
}

func (s *Server) ValidateCreds(email, password string) error {
	if !s.emailRegexp.MatchString(email) {
		return errors.Wrap(entity.ErrBadRequest, "invalid email")
	}

	if !s.passwordRegexp.MatchString(password) {
		return errors.Wrap(entity.ErrBadRequest, "invalid password")
	}
	return nil
}

func (s *Server) ValidateFile(f string) error {
	if strings.TrimSpace(f) == "" {
		return errors.Wrap(entity.ErrBadRequest, "invalid file")
	}
	_, err := uuid.Parse(f)
	if err != nil {
		return errors.Wrap(entity.ErrBadRequest, "invalid format")
	}

	Ok, err := path.Match("*.*", path.Clean(f))
	if err != nil {
		return errors.New("invalid format")
	}

	if !Ok {
		return errors.Wrap(entity.ErrBadRequest, "invalid file")
	}

	return nil
}

func validateMIMEType(mimeType string) error {
	if _, ok := entity.AllowedMIMETypes[mimeType]; !ok {
		return errors.Wrap(entity.ErrBadRequest, "MIME type is not allowed")
	}

	return nil
}

func validateUploadRequest(req *api.APIV1CloudStorageMyUploadPostReq) error {
	if req.Name == "" {
		return errors.Wrap(entity.ErrBadRequest, "invalid name")
	}

	if req.Size <= 0 {
		return errors.Wrap(entity.ErrBadRequest, "invalid size")
	}

	if err := validateMIMEType(req.MimeType); err != nil {
		return errors.Wrap(entity.ErrBadRequest, "invalid MIME type")
	}

	if req.FilePath == "" {
		return errors.Wrap(entity.ErrBadRequest, "invalid file path")
	}

	return nil
}

func (s *Server) userFromContext(ctx context.Context) (entity.User, error) {
	token, ok := ctx.Value(entity.AuthTokenKey).(string)
	if !ok {
		return entity.User{}, errors.New("token not found")
	}

	user, err := s.tokenizer.GetUser(ctx, token)
	if err != nil {
		return entity.User{}, errors.Wrap(err, "get user")
	}

	return user, nil
}
