package services

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha1"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/ad3n/golang-jwt/models"
	"github.com/golang-jwt/jwt"
)

type Jwt struct {
}

func (j Jwt) CreateToken(user models.User) (models.Token, error) {
	var err error

	claims := jwt.MapClaims{}
	claims["type"] = "access_token"
	claims["user_id"] = user.Username
	claims["exp"] = time.Now().Add(time.Hour * 2).Unix()

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	jwt := models.Token{}

	jwt.AccessToken, err = token.SignedString([]byte(os.Getenv("SECRET_KEY")))
	if err != nil {
		return jwt, err
	}

	return j.createRefreshToken(jwt)
}

func (Jwt) ValidateToken(accessToken string) (models.User, error) {
	token, err := jwt.Parse(accessToken, func(token *jwt.Token) (interface{}, error) {
		_, ok := token.Method.(*jwt.SigningMethodHMAC)
		if !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}

		return []byte(os.Getenv("SECRET_KEY")), nil
	})

	user := models.User{}
	if err != nil {
		return user, err
	}

	payload, ok := token.Claims.(jwt.MapClaims)
	if ok && token.Valid {
		user.Username = payload["user_id"].(string)

		return user, nil
	}

	return user, errors.New("invalid token")
}

func (Jwt) ValidateRefreshToken(token models.Token) bool {
	sha1 := sha1.New()
	io.WriteString(sha1, os.Getenv("SECRET_KEY"))

	salt := string(sha1.Sum(nil))[0:16]
	block, err := aes.NewCipher([]byte(salt))
	if err != nil {
		return false
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return false
	}

	data, err := base64.URLEncoding.DecodeString(token.RefreshToken)
	if err != nil {
		return false
	}

	nonceSize := gcm.NonceSize()
	nonce, ciphertext := data[:nonceSize], data[nonceSize:]

	plain, err := gcm.Open(nil, nonce, ciphertext, nil)
	if token.AccessToken == string(plain) && err == nil {
		return true
	}

	return false
}

func (Jwt) createRefreshToken(token models.Token) (models.Token, error) {
	sha1 := sha1.New()
	io.WriteString(sha1, os.Getenv("SECRET_KEY"))

	salt := string(sha1.Sum(nil))[0:16]
	block, err := aes.NewCipher([]byte(salt))
	if err != nil {
		fmt.Println(err.Error())

		return token, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return token, err
	}

	nonce := make([]byte, gcm.NonceSize())
	_, err = io.ReadFull(rand.Reader, nonce)
	if err != nil {
		return token, err
	}

	token.RefreshToken = base64.URLEncoding.EncodeToString(gcm.Seal(nonce, nonce, []byte(token.AccessToken), nil))

	return token, nil
}
