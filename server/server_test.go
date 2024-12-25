package server

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	"github.com/stretchr/testify/assert"
	"golang.org/x/crypto/bcrypt"
)

const (
	TEST_USER = "testuser"
	TEST_PASS = "testpass"
)

var TEST_TIME = time.Date(2024, time.January, 12, 5, 55, 35, 150, time.UTC)

func TestAddExpiryDuration(t *testing.T) {
	assert.Equal(t, TEST_TIME.Add(24*time.Hour), addExpiryDuration(TEST_TIME))
}

func TestLoginUser_UserDidntExist(t *testing.T) {
	e := echo.New()
	s := New()
	s.now = func() time.Time { return TEST_TIME }
	loginGroup := e.Group("/login", middleware.BasicAuth(s.AuthenticateUser))
	loginGroup.POST("", s.LoginUser)

	req := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(""))
	rec := httptest.NewRecorder()
	req.SetBasicAuth(TEST_USER, TEST_PASS)

	e.ServeHTTP(rec, req)

	assert := assert.New(t)
	assert.Equal(http.StatusCreated, rec.Code)
	assert.Equal(
		"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."+
			"eyJleHAiOjE3MDUxMjUzMzUsInN1YiI6InRlc3R1c2VyIn0."+
			"W4s_64lN7Ob8NIj2Yf1sVfO5PiPyZbPI-UE0s6MLi2c",
		rec.Body.String())
}

func TestLoginUser_UserExisted(t *testing.T) {
	e := echo.New()
	s := New()
	s.now = func() time.Time { return time.Date(2024, time.January, 12, 5, 55, 35, 150, time.UTC) }
	hash, err := bcrypt.GenerateFromPassword([]byte(TEST_PASS), COST)
	assert.NoError(t, err)
	s.users[TEST_USER] = User{Name: TEST_USER, PassHash: hash}
	loginGroup := e.Group("/login", middleware.BasicAuth(s.AuthenticateUser))
	loginGroup.POST("", s.LoginUser)

	req := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(""))
	rec := httptest.NewRecorder()
	req.SetBasicAuth(TEST_USER, TEST_PASS)

	e.ServeHTTP(rec, req)

	assert := assert.New(t)
	assert.Equal(http.StatusOK, rec.Code)
	assert.Equal(
		"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."+
			"eyJleHAiOjE3MDUxMjUzMzUsInN1YiI6InRlc3R1c2VyIn0."+
			"W4s_64lN7Ob8NIj2Yf1sVfO5PiPyZbPI-UE0s6MLi2c",
		rec.Body.String())
}
