package services

import (
	"os"
	"testing"

	"github.com/ad3n/golang-jwt/models"
	"github.com/go-playground/assert"
)

func TestCreateAndValidateAndRefreshTogether(t *testing.T) {
	os.Setenv("SECRET_KEY", "ThisIsSecret")

	user := models.User{}
	user.Username = "admin"

	jwt := Jwt{}
	token, err := jwt.CreateToken(user)

	assert.Equal(t, nil, err)
	assert.NotEqual(t, "", token.AccessToken)
	assert.NotEqual(t, "", token.RefreshToken)

	user, err = jwt.ValidateToken(token.AccessToken)
	assert.Equal(t, nil, err)
	assert.Equal(t, user.Username, "admin")

	assert.Equal(t, true, jwt.ValidateRefreshToken(token))
}
