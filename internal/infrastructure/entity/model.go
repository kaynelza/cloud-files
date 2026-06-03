package entity

import (
	"time"

	"github.com/google/uuid"
)

type (
	User struct {
		ID    uuid.UUID
		Email string
	}

	UserCredentials struct {
		Email    string
		Password string
	}

	Tokens struct {
		Access  string
		Refresh string
	}
	File struct {
		Id        string    `json:"id"`
		Name      string    `json:"name"`
		Size      int       `json:"size"`
		MimeType  string    `json:"mime_type"`
		FilePath  string    `json:"file_path"`
		CreatedAt time.Time `json:"created_at"`
	}
	UploadSession struct {
		FileName string `json:"file_name"`
		Size     int    `json:"size"`
		MimeType string `json:"mime_type"`
		FilePath string `json:"file_path"`
	}
)
