package oauth2

import (
	"github.com/satori/go.uuid"
	"time"
)

type SessionId string

type Session interface {
	Id() SessionId
	UserId() string
	ExpiresAt() time.Time
	SetExpiresAt(expireAt time.Time)
}

type session struct {
	id        SessionId
	userId    string
	expiresAt time.Time
}

func (s *session) Id() SessionId {
	return s.id
}

func (s *session) UserId() string {
	return s.userId
}

func (s *session) ExpiresAt() time.Time {
	return s.expiresAt
}

func (s *session) SetExpiresAt(expireAt time.Time) {
	s.expiresAt = expireAt
}

func NewSession(userId string) Session {
	return &session{
		id:     SessionId(uuid.NewV4().String()),
		userId: userId,
	}
}
