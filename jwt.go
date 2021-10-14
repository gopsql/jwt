package jwt

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/golang-jwt/jwt/v4"
)

type (
	Session struct {
		Keys    *KeyPair
		Options *SessionOptions
	}

	SessionOptions struct {
		UserIdKeyName    string // defaults to "UserId"
		SessionIdKeyName string // defaults to "SessionId"
	}

	KeyPair struct {
		*rsa.PrivateKey
		*rsa.PublicKey
	}
)

func NewSession(options *SessionOptions) *Session {
	if options == nil {
		options = &SessionOptions{}
	}
	return &Session{
		Keys:    NewKeyPair(),
		Options: options,
	}
}

func (s *Session) SetString(input string) (err error) {
	if s.Keys == nil {
		s.Keys = NewKeyPair()
	}
	return s.Keys.SetString(input)
}

func (s Session) String() string {
	if s.Keys == nil {
		return ""
	}
	return s.Keys.String()
}

func (s Session) uidKey() string {
	if s.Options != nil && s.Options.UserIdKeyName != "" {
		return s.Options.UserIdKeyName
	}
	return "UserId"
}

func (s Session) sidKey() string {
	if s.Options != nil && s.Options.SessionIdKeyName != "" {
		return s.Options.SessionIdKeyName
	}
	return "SessionId"
}

func (s Session) GenerateAuthorization(userId int, sessionId string) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		s.uidKey(): userId,
		s.sidKey(): sessionId,
	})
	auth, err := token.SignedString(s.Keys.PrivateKey)
	if err != nil {
		return "", err
	}
	return "Bearer " + auth, nil
}

func (s Session) ParseAuthorization(auth string) (userId int, sessionId string, ok bool) {
	parts := strings.SplitN(auth, " ", 2)
	if parts[0] != "Bearer" {
		return
	}
	claims, e := parseToken(s.Keys.PublicKey, parts[1])
	if e != nil {
		return
	}
	var uid, sid interface{}
	uid, ok = claims[s.uidKey()]
	if !ok {
		return
	}
	sid, ok = claims[s.sidKey()]
	if !ok {
		return
	}
	userId, e = strconv.Atoi(fmt.Sprint(uid))
	if e != nil {
		ok = false
		return
	}
	sessionId = fmt.Sprint(sid)
	ok = true
	return
}

func NewKeyPair() *KeyPair {
	privatekey, _ := rsa.GenerateKey(rand.Reader, 2048)
	return &KeyPair{privatekey, &privatekey.PublicKey}
}

func (kp *KeyPair) SetString(input string) (err error) {
	if input == "" {
		return nil
	}
	privKey, err := jwt.ParseRSAPrivateKeyFromPEM([]byte(input))
	if err != nil {
		return err
	}
	pubKeyBytes, err := x509.MarshalPKIXPublicKey(&privKey.PublicKey)
	if err != nil {
		return err
	}
	publicKey, err := jwt.ParseRSAPublicKeyFromPEM(pem.EncodeToMemory(
		&pem.Block{
			Type:  "RSA PUBLIC KEY",
			Bytes: pubKeyBytes,
		},
	))
	kp.PrivateKey = privKey
	kp.PublicKey = publicKey
	return nil
}

func (kp KeyPair) String() string {
	var buffer bytes.Buffer
	err := pem.Encode(&buffer, &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(kp.PrivateKey),
	})
	if err != nil {
		return ""
	}
	return "\n" + buffer.String()
}

func parseToken(pubKey *rsa.PublicKey, input string) (jwt.MapClaims, error) {
	token, err := jwt.Parse(input, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return pubKey, nil
	})
	if err != nil {
		return nil, err
	}
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok || !token.Valid {
		return nil, errors.New("invalid token")
	}
	return claims, nil
}
