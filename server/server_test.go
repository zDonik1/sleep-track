package server

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/suite"
	"golang.org/x/crypto/bcrypt"
)

const (
	TEST_USER    = "testuser"
	TEST_PASS    = "testpass"
	ANOTHER_PASS = "otherpass"
	EXPECTED_JWT = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9." +
		"eyJleHAiOjE3MDUxMjUzMzUsInN1YiI6InRlc3R1c2VyIn0." +
		"W4s_64lN7Ob8NIj2Yf1sVfO5PiPyZbPI-UE0s6MLi2c"
)

var TEST_TIME = time.Date(2024, time.January, 12, 5, 55, 35, 150, time.UTC)

type ServerSuite struct {
	suite.Suite

	ech  *echo.Echo
	serv *Server
	rec  *httptest.ResponseRecorder
}

func (s *ServerSuite) SetupTest() {
	s.ech = echo.New()
	s.serv = New()
	s.serv.now = func() time.Time { return TEST_TIME }
	s.rec = httptest.NewRecorder()
}

// ------------------------------------------------
// LOGIN SUITE
// ------------------------------------------------

type LoginSuite struct {
	ServerSuite
}

func (s *LoginSuite) SetupTest() {
	s.ServerSuite.SetupTest()
	s.ech.POST("/login", s.serv.LoginUser, middleware.BasicAuth(s.serv.AuthenticateUser))
}

func (s *LoginSuite) setupDbWithUser() {
	hash, err := bcrypt.GenerateFromPassword([]byte(TEST_PASS), COST)
	s.NoError(err)
	s.serv.users[TEST_USER] = User{Name: TEST_USER, PassHash: hash}
}

func (s *LoginSuite) TestLoginUser_UserDidntExist() {
	req := httptest.NewRequest(http.MethodPost, "/login", nil)
	req.SetBasicAuth(TEST_USER, TEST_PASS)

	s.ech.ServeHTTP(s.rec, req)

	s.Equal(http.StatusCreated, s.rec.Code)
	s.Equal(EXPECTED_JWT, s.rec.Body.String())
}

func (s *LoginSuite) TestLoginUser_UserExisted() {
	s.setupDbWithUser()
	req := httptest.NewRequest(http.MethodPost, "/login", nil)
	req.SetBasicAuth(TEST_USER, TEST_PASS)

	s.ech.ServeHTTP(s.rec, req)

	s.Equal(http.StatusOK, s.rec.Code)
	s.Equal(EXPECTED_JWT, s.rec.Body.String())
}

func (s *LoginSuite) TestLoginUser_WrongPassword() {
	s.setupDbWithUser()
	req := httptest.NewRequest(http.MethodPost, "/login", nil)
	req.SetBasicAuth(TEST_USER, ANOTHER_PASS)

	s.ech.ServeHTTP(s.rec, req)

	s.Equal(http.StatusUnauthorized, s.rec.Code)
	s.Equal(
		jsonMes("crypto/bcrypt: hashedPassword is not the hash of the given password"),
		s.rec.Body.String())
}

func TestLoginSuite(t *testing.T) {
	suite.Run(t, new(LoginSuite))
}

// ------------------------------------------------
// OTHER TEST
// ------------------------------------------------

func TestAddExpiryDuration(t *testing.T) {
	assert.Equal(t, TEST_TIME.Add(24*time.Hour), addExpiryDuration(TEST_TIME))
}

func jsonMes(mes string) string {
	return fmt.Sprintf(`{"message":"%s"}`+"\n", mes)
}
