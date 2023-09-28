package models

import (
	"time"
)

type User struct {
	Guid    string  `bson:"guid"`
	Session Session `bson:"session"`
}

type Session struct {
	RefreshToken string    `bson:"refreshToken"`
	CreatedAt    time.Time `bson:"createdAt"`
}
