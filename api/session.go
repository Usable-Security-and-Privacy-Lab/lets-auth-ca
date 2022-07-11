package api

// Taken from the Duo Labs webauthn demo app. Thank you!
// https://github.com/duo-labs/webauthn.io

import (
	"crypto/rand"
	"encoding/json"
	"errors"
	"net/http"
	"fmt"

	"github.com/duo-labs/webauthn/webauthn"
	"github.com/gorilla/sessions"
)

// DefaultEncryptionKeyLength is the length of the generated encryption keys
// used for session management.
const DefaultEncryptionKeyLength = 32

// Two sessions, one for webauthn registration/login, one for persisting login after webauthn is done
const WebauthnSession = "webauthn-session"
const WebauthnSessionMaxAge = 30 // 30 seconds

const UserSession = "user-session"
const UserSessionMaxAge = 30  // 30 seconds

// ErrInsufficientBytesRead is returned in the rare case that an unexpected
// number of bytes are returned from the crypto/rand reader when creating
// session cookie encryption keys.
var ErrInsufficientBytesRead = errors.New("insufficient bytes read")

// ErrMarshal is returned if unexpected data is present in a webauthn session.
var ErrMarshal = errors.New("error unmarshaling data")

// GenerateSecureKey reads and returns n bytes from the crypto/rand reader
func GenerateSecureKey(n int) ([]byte, error) {
	buf := make([]byte, n)
	read, err := rand.Read(buf)
	if err != nil {
		return buf, err
	}
	if read != n {
		return buf, ErrInsufficientBytesRead
	}
	return buf, nil
}

// Store is a wrapper around sessions.CookieStore which provides some helper
// methods related to webauthn operations.
type Store struct {
	*sessions.CookieStore
}

// NewStore returns a new session store.
func NewStore(keyPairs ...[]byte) (*Store, error) {
	// Generate a default encryption key if one isn't provided
	if len(keyPairs) == 0 {
		key, err := GenerateSecureKey(DefaultEncryptionKeyLength)
		if err != nil {
			return nil, err
		}
		keyPairs = append(keyPairs, key)
	}
	store := &Store{
		sessions.NewCookieStore(keyPairs...),
	}
	return store, nil
}

// SaveWebauthnSession marhsals and saves the webauthn data to the provided
// key given the request and responsewriter
func (store *Store) SaveWebauthnSession(key string, data *webauthn.SessionData, r *http.Request, w http.ResponseWriter) error {
	marshaledData, err := json.Marshal(data)
	if err != nil {
		fmt.Println("failed saving webauthn session")
		return err
	}
	return store.Set(WebauthnSession, WebauthnSessionMaxAge, key, marshaledData, r, w)
}

// GetWebauthnSession unmarshals and returns the webauthn session information
// from the session cookie.
func (store *Store) GetWebauthnSession(key string, r *http.Request) (webauthn.SessionData, error) {
	sessionData := webauthn.SessionData{}
	session, err := store.Get(r, WebauthnSession)
	if err != nil {
		fmt.Println("error getting session data")
		return sessionData, err
	}
	assertion, ok := session.Values[key].([]byte)
	if !ok {
		fmt.Println("error getting assertion")
		return sessionData, ErrMarshal
	}

	err = json.Unmarshal(assertion, &sessionData)
	if err != nil {
		fmt.Println("error unmarshalling assertion")
		return sessionData, err
	}
	// Delete the value from the session now that it's been read
	delete(session.Values, key)
	return sessionData, nil
}

func (store *Store) setUserSession(w http.ResponseWriter, r *http.Request, username string) (err error) {
	return store.Set(UserSession, UserSessionMaxAge, "username", username, r, w)
}

func (store *Store) getUserSession(r *http.Request) (username string, err error) {
	session, err := sessionStore.Get(r, UserSession)
	if err != nil {
		err = errors.New("Error getting user session from store: " + err.Error())
		return "", nil
	}
	username, present := session.Values["username"].(string)
	if !present {
		return "", nil
	}

	return username, nil
}

func (store *Store) deleteUserSession(w http.ResponseWriter, r *http.Request) (err error) {
	session, err := sessionStore.Get(r, UserSession)
	if err != nil {
		fmt.Println("Error getting user session from store: " + err.Error())
	}

	// delete the username
	delete(session.Values, "username")
	// set the maxAge so it will be deleted
	(*session.Options).MaxAge = -1

	err = session.Save(r, w)
	if err != nil {
		err = errors.New("Error saving user session: " + err.Error())
		return
	}

	return
}

// Set stores a value to the session with the provided key.
func (store *Store) Set(sessionName string, age int, key string, value interface{}, r *http.Request, w http.ResponseWriter) error {
	session, _ := store.Get(r, sessionName)
	// We can safely ignore any error here. We may have old cookies from a
	// previous time the server ran. But we just clobber that here.
	// cookies are very short lived for us -- only for the duration of the
	// registration or login process (maybe a few minutes at most).
	(*session.Options).MaxAge = age
	session.Values[key] = value
	session.Save(r, w)
	return nil
}