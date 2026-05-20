package entity

import "github.com/google/uuid"

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
)
