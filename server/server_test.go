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
)

func TestLoginUser_UserDidntExist(t *testing.T) {
	e := echo.New()
	s := New()
	s.now = func() time.Time { return time.Date(2024, time.January, 12, 5, 55, 35, 150, time.UTC) }
	loginGroup := e.Group("/login", middleware.BasicAuth(s.AuthenticateUser))
	loginGroup.POST("", s.LoginUser)

	req := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(""))
	rec := httptest.NewRecorder()
	req.SetBasicAuth("testuser", "testpass")

	e.ServeHTTP(rec, req)

	assert := assert.New(t)
	assert.Equal(http.StatusCreated, rec.Code)
	assert.Equal(
		"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."+
			"eyJleHAiOjE3MDUxMjUzMzUsInN1YiI6InRlc3R1c2VyIn0."+
			"W4s_64lN7Ob8NIj2Yf1sVfO5PiPyZbPI-UE0s6MLi2c",
		rec.Body.String())
}
