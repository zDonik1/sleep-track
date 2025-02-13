package server

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/suite"
	db "github.com/zDonik1/sleep-track/database"
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

func (s *ServerSuite) TearDownTest() {
	s.teardown()
}

func (s *ServerSuite) TearDownSubTest() {
	s.teardown()
}

func (s *ServerSuite) setup() {
	s.ech = echo.New()
	s.serv = New()
	s.serv.dbSource = ":memory:"
	s.serv.now = func() time.Time { return TEST_TIME }
	s.rec = httptest.NewRecorder()

	err := s.serv.OpenDb()
	s.NoError(err)
}

func (s *ServerSuite) teardown() {
	s.serv.CloseDb()
}

func (s *ServerSuite) setupDbWithUser() {
	hash, err := bcrypt.GenerateFromPassword([]byte(TEST_PASS), COST)
	s.NoError(err)
	err = s.serv.db.AddUser(db.User{Name: TEST_USER, PassHash: hash})
	s.NoError(err)
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

	type JsonInterval struct {
		Start   time.Time `json:"start"`
		End     time.Time `json:"end"`
		Quality int       `json:"quality"`
	}

	type JsonIntervalWithId struct {
		Id int64 `json:"id"`
		JsonInterval
	}

	toJson := func(interval db.Interval) string {
		body, err := json.Marshal(JsonInterval{
			Start:   interval.Start,
			End:     interval.End,
			Quality: interval.Quality,
		})
		s.Require().NoError(err)
		return string(body)
	}

	toJsonWithId := func(interval db.Interval) string {
		body, err := json.Marshal(JsonIntervalWithId{
			Id: interval.Id,
			JsonInterval: JsonInterval{
				Start:   interval.Start,
				End:     interval.End,
				Quality: interval.Quality,
			},
		})
		s.Require().NoError(err)
		return string(body) + "\n"
	}

	data := []struct {
		Name           string
		Body           string
		ExpectedStatus int
		ExpectedBody   string
	}{
		{
			Name:           "ValidInterval",
			Body:           toJson(db.Interval{Start: start, End: end, Quality: 1}),
			ExpectedStatus: http.StatusCreated,
			ExpectedBody:   toJsonWithId(db.Interval{Id: 1, Start: start, End: end, Quality: 1}),
		},
		{
			Name:           "EndBeforeStart",
			Body:           toJson(db.Interval{Start: end, End: start, Quality: 1}),
			ExpectedStatus: http.StatusBadRequest,
			ExpectedBody:   jsonMes("interval end is the same or before start"),
		},
		{
			Name:           "WrongTimeFormat",
			Body:           `{"start":"starttime","end":"endtime","quality":1}`,
			ExpectedStatus: http.StatusBadRequest,
			ExpectedBody:   jsonMes(`parsing time \"starttime\" as \"2006-01-02T15:04:05Z07:00\": cannot parse \"starttime\" as \"2006\"`),
		},
		{
			Name:           "QualityBelowRange",
			Body:           toJson(db.Interval{Start: start, End: end, Quality: 0}),
			ExpectedStatus: http.StatusBadRequest,
			ExpectedBody:   jsonMes("quality out of 1-5 range"),
		},
		{
			Name:           "QualityAboveRange",
			Body:           toJson(db.Interval{Start: start, End: end, Quality: 10}),
			ExpectedStatus: http.StatusBadRequest,
			ExpectedBody:   jsonMes("quality out of 1-5 range"),
		},
		{
			Name:           "MissingFields",
			Body:           `{"quality":1}`,
			ExpectedStatus: http.StatusBadRequest,
			ExpectedBody:   jsonMes(`missing \"start\" field`),
		},
		{
			Name:           "MissingBody",
			Body:           "",
			ExpectedStatus: http.StatusBadRequest,
			ExpectedBody:   jsonMes("EOF"),
		},
	}

	for _, d := range data {
		s.Run(d.Name, func() {
			s.setupDbWithUser()
			s.ech.POST("/intervals", s.serv.CreateInterval, s.serv.JwtMiddleware())
			req := httptest.NewRequest(http.MethodPost, "/intervals", strings.NewReader(d.Body))
			req.Header.Add("Authorization", "Bearer "+EXPECTED_JWT)

			s.ech.ServeHTTP(s.rec, req)

			s.Equal(d.ExpectedStatus, s.rec.Result().StatusCode)
			s.Equal(d.ExpectedBody, s.rec.Body.String())
		})
	}
}

func (s *ServerSuite) TestJwtMiddleware() {
	// JWT with sub = "testuser", exp = "2024-01-11T05:55:35.15Z"
	const EXPIRED_JWT = "yJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9." +
		"eyJleHAiOjE3MDQ5NTI1MzUsInN1YiI6InRlc3R1c2VyIn0." +
		"2LMLB6-HWphjDkP9ervjFQYoX9_zfIp55GmGsKOz3U4"

	data := []struct {
		Name           string
		SetupUser      bool
		Jwt            string
		ExpectedStatus int
		ExpectedBody   string
	}{
		{
			Name:           "UserDoesntExist",
			SetupUser:      false,
			Jwt:            EXPECTED_JWT,
			ExpectedStatus: http.StatusUnauthorized,
			ExpectedBody:   jsonMes("invalid or expired jwt"),
		},
		{
			Name:           "ExpiredJWT",
			SetupUser:      true,
			Jwt:            EXPIRED_JWT,
			ExpectedStatus: http.StatusUnauthorized,
			ExpectedBody:   jsonMes("invalid or expired jwt"),
		},
		{
			Name:           "InvalidJWT",
			SetupUser:      true,
			Jwt:            "myinvalidjwt",
			ExpectedStatus: http.StatusUnauthorized,
			ExpectedBody:   jsonMes("invalid or expired jwt"),
		},
		{
			Name:           "MissingJWT",
			SetupUser:      true,
			Jwt:            "",
			ExpectedStatus: http.StatusBadRequest,
			ExpectedBody:   jsonMes("missing or malformed jwt"),
		},
	}

	for _, d := range data {
		s.Run(d.Name, func() {
			if d.SetupUser {
				s.setupDbWithUser()
			}
			s.ech.POST(
				"/temp",
				func(c echo.Context) error {
					s.Fail("Should never reach handler")
					return nil
				},
				s.serv.JwtMiddleware(),
			)
			req := httptest.NewRequest(http.MethodPost, "/temp", nil)
			req.Header.Add("Authorization", "Bearer "+d.Jwt)

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
