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
	"github.com/stretchr/testify/suite"
	"golang.org/x/crypto/bcrypt"
)

const (
	TEST_USER = "testuser"
	TEST_PASS = "testpass"
)

var TEST_TIME = time.Date(2024, time.January, 12, 5, 55, 35, 150, time.UTC)

type ServerSuite struct {
	suite.Suite

	ech  *echo.Echo
	serv *Server
	rec  *httptest.ResponseRecorder

	// should be setup by inheriting suites
	req *http.Request
}

func (s *ServerSuite) SetupTest() {
	s.ech = echo.New()
	s.serv = New()
	s.serv.now = func() time.Time { return TEST_TIME }
	s.rec = httptest.NewRecorder()
}

func (s *ServerSuite) serve() {
	s.ech.ServeHTTP(s.rec, s.req)
}

type LoginSuite struct {
	ServerSuite
}

func (s *LoginSuite) SetupTest() {
	s.ServerSuite.SetupTest()
	s.ech.POST("/login", s.serv.LoginUser, middleware.BasicAuth(s.serv.AuthenticateUser))
	s.req = httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(""))
}

func (s *LoginSuite) TestLoginUser_UserDidntExist() {
	s.req.SetBasicAuth(TEST_USER, TEST_PASS)

	s.serve()

	s.Equal(http.StatusCreated, s.rec.Code)
	s.Equal(
		"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."+
			"eyJleHAiOjE3MDUxMjUzMzUsInN1YiI6InRlc3R1c2VyIn0."+
			"W4s_64lN7Ob8NIj2Yf1sVfO5PiPyZbPI-UE0s6MLi2c",
		s.rec.Body.String())
}

func (s *LoginSuite) TestLoginUser_UserExisted() {
	hash, err := bcrypt.GenerateFromPassword([]byte(TEST_PASS), COST)
	s.NoError(err)
	s.serv.users[TEST_USER] = User{Name: TEST_USER, PassHash: hash}
	s.req.SetBasicAuth(TEST_USER, TEST_PASS)

	s.serve()

	s.Equal(http.StatusOK, s.rec.Code)
	s.Equal(
		"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."+
			"eyJleHAiOjE3MDUxMjUzMzUsInN1YiI6InRlc3R1c2VyIn0."+
			"W4s_64lN7Ob8NIj2Yf1sVfO5PiPyZbPI-UE0s6MLi2c",
		s.rec.Body.String())
}

func TestLoginSuite(t *testing.T) {
	suite.Run(t, new(LoginSuite))
}

func TestAddExpiryDuration(t *testing.T) {
	assert.Equal(t, TEST_TIME.Add(24*time.Hour), addExpiryDuration(TEST_TIME))
}
