package server

import (
	"bytes"
	"encoding/json"
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
	// JWT with sub = "testuser", exp = "2024-01-13T05:55:35.15Z"
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
	s.setup()
}

func (s *ServerSuite) SetupSubTest() {
	s.setup()
}

func (s *ServerSuite) setup() {
	s.ech = echo.New()
	s.serv = New()
	s.serv.now = func() time.Time { return TEST_TIME }
	s.rec = httptest.NewRecorder()
}

func (s *ServerSuite) setupDbWithUser() {
	hash, err := bcrypt.GenerateFromPassword([]byte(TEST_PASS), COST)
	s.NoError(err)
	s.serv.users[TEST_USER] = User{Name: TEST_USER, PassHash: hash}
}

func (s *ServerSuite) TestLoginUser_UserDidntExist() {
	s.ech.POST("/login", s.serv.LoginUser, middleware.BasicAuth(s.serv.AuthenticateUser))
	req := httptest.NewRequest(http.MethodPost, "/login", nil)
	req.SetBasicAuth(TEST_USER, TEST_PASS)

	s.ech.ServeHTTP(s.rec, req)

	s.Equal(http.StatusCreated, s.rec.Code)
	s.Equal(EXPECTED_JWT, s.rec.Body.String())
}

func (s *ServerSuite) TestLoginUser_UserExisted() {
	s.setupDbWithUser()
	s.ech.POST("/login", s.serv.LoginUser, middleware.BasicAuth(s.serv.AuthenticateUser))
	req := httptest.NewRequest(http.MethodPost, "/login", nil)
	req.SetBasicAuth(TEST_USER, TEST_PASS)

	s.ech.ServeHTTP(s.rec, req)

	s.Equal(http.StatusOK, s.rec.Code)
	s.Equal(EXPECTED_JWT, s.rec.Body.String())
}

func (s *ServerSuite) TestLoginUser_WrongPassword() {
	s.setupDbWithUser()
	s.ech.POST("/login", s.serv.LoginUser, middleware.BasicAuth(s.serv.AuthenticateUser))
	req := httptest.NewRequest(http.MethodPost, "/login", nil)
	req.SetBasicAuth(TEST_USER, ANOTHER_PASS)

	s.ech.ServeHTTP(s.rec, req)

	s.Equal(http.StatusUnauthorized, s.rec.Code)
	s.Equal(
		jsonMes("crypto/bcrypt: hashedPassword is not the hash of the given password"),
		s.rec.Body.String())
}

func (s *ServerSuite) TestCreateInterval() {
	start := time.Date(2024, time.January, 12, 21, 0, 0, 0, time.UTC)
	end := start.Add(8 * time.Hour)

	makeJsonBody := func(interval Interval) []byte {
		body, err := json.Marshal(map[string]any{
			"start":   interval.Start,
			"end":     interval.End,
			"quality": interval.Quality,
		})
		s.Require().NoError(err)
		return body
	}

	data := []struct {
		Name           string
		Body           []byte
		SetupUser      bool
		ExpectedStatus int
		ExpectedBody   string
	}{
		{
			Name:           "ValidInterval",
			Body:           makeJsonBody(Interval{Start: start, End: end, Quality: 1}),
			SetupUser:      true,
			ExpectedStatus: http.StatusCreated,
			ExpectedBody:   "",
		},
		{
			Name:           "EndBeforeStart",
			Body:           makeJsonBody(Interval{Start: end, End: start, Quality: 1}),
			SetupUser:      true,
			ExpectedStatus: http.StatusBadRequest,
			ExpectedBody:   jsonMes("interval end is the same or before start"),
		},
		{
			Name:           "WrongTimeFormat",
			Body:           []byte(`{"start":"starttime","end":"endtime","quality":1}`),
			SetupUser:      true,
			ExpectedStatus: http.StatusBadRequest,
			ExpectedBody:   jsonMes(`parsing time \"starttime\" as \"2006-01-02T15:04:05Z07:00\": cannot parse \"starttime\" as \"2006\"`),
		},
		{
			Name:           "QualityBelowRange",
			Body:           makeJsonBody(Interval{Start: start, End: end, Quality: 0}),
			SetupUser:      true,
			ExpectedStatus: http.StatusBadRequest,
			ExpectedBody:   jsonMes("quality out of 1-5 range"),
		},
		{
			Name:           "QualityAboveRange",
			Body:           makeJsonBody(Interval{Start: start, End: end, Quality: 10}),
			SetupUser:      true,
			ExpectedStatus: http.StatusBadRequest,
			ExpectedBody:   jsonMes("quality out of 1-5 range"),
		},
		{
			Name:           "MissingFields",
			Body:           []byte(`{"quality":1}`),
			SetupUser:      true,
			ExpectedStatus: http.StatusBadRequest,
			ExpectedBody:   jsonMes(`missing \"start\" field`),
		},
		{
			Name:           "MissingBody",
			Body:           []byte{},
			SetupUser:      true,
			ExpectedStatus: http.StatusBadRequest,
			ExpectedBody:   jsonMes("EOF"),
		},
	}

	for _, d := range data {
		s.Run(d.Name, func() {
			if d.SetupUser {
				s.setupDbWithUser()
			}
			s.ech.POST("/intervals", s.serv.CreateInterval, s.serv.JwtMiddleware())
			req := httptest.NewRequest(http.MethodPost, "/intervals", bytes.NewReader(d.Body))
			req.Header.Add("Authorization", "Bearer "+EXPECTED_JWT)

			s.ech.ServeHTTP(s.rec, req)

			s.Equal(d.ExpectedStatus, s.rec.Result().StatusCode)
			s.Equal(d.ExpectedBody, s.rec.Body.String())
		})
	}
}

func TestServerSuite(t *testing.T) {
	suite.Run(t, new(ServerSuite))
}

// ------------------------------------------------
// OTHER TESTS
// ------------------------------------------------

func TestAddExpiryDuration(t *testing.T) {
	assert.Equal(t, TEST_TIME.Add(24*time.Hour), addExpiryDuration(TEST_TIME))
}

// ------------------------------------------------
// HELPERS
// ------------------------------------------------

func jsonMes(mes string) string {
	return fmt.Sprintf(`{"message":"%s"}`+"\n", mes)
}
