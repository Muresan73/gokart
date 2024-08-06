package datastore

import (
	"context"

	"github.com/go-webauthn/webauthn/webauthn"
)

type User struct {
	session     webauthn.SessionData
	uId         string
	uName       string
	credentials []webauthn.Credential
}

// WebAuthnCredentials implements webauthn.User.
func (u User) WebAuthnCredentials() []webauthn.Credential {
	return u.credentials
}

// WebAuthnDisplayName implements webauthn.User.
func (u User) WebAuthnDisplayName() string {
	return u.uName
}

// WebAuthnID implements webauthn.User.
func (u User) WebAuthnID() []byte {
	return u.session.UserID
}

// WebAuthnName implements webauthn.User.
func (u User) WebAuthnName() string {
	return u.uName
}

type DataStore interface {
	GetUser(context.Context) error
	GetSession(context.Context) error
}

var store = map[string]User{}

func GetUser(name string) User {
	return store[name]
}

func (u *User) UpdateCredential(c webauthn.Credential) {
	u.credentials = append(u.credentials, c)
}

func (u *User) AddCredential(c webauthn.Credential) {
	u.credentials = append(u.credentials, c)
}

func (u *User) SaveSession(s *webauthn.SessionData) {
	u.session = *s
}

func GetSession(name string) webauthn.SessionData {
	return store[name].session
}
