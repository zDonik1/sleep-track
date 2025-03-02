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
	ut "github.com/zDonik1/sleep-track/utils"
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

var (
	TEST_TIME = time.Date(2024, time.January, 12, 5, 55, 35, 150, time.UTC)
	START     = time.Date(2024, time.January, 12, 21, 0, 0, 0, time.UTC)
)

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

func (s *ServerSuite) intrToJson(interval db.Interval) string {
	res, err := json.Marshal(fromInterval(interval))
	s.Require().NoError(err)
	return string(res) + "\n"
}

func (s *ServerSuite) TestLoginUser() {
	data := []struct {
		Name           string
		SetupUser      bool
		Password       string
		ExpectedStatus int
		ExpectedBody   string
	}{
		{
			Name:           "UserDidntExist",
			SetupUser:      false,
			Password:       TEST_PASS,
			ExpectedStatus: http.StatusCreated,
			ExpectedBody:   EXPECTED_JWT,
		},
		{
			Name:           "UserExisted",
			SetupUser:      true,
			Password:       TEST_PASS,
			ExpectedStatus: http.StatusOK,
			ExpectedBody:   EXPECTED_JWT,
		},
		{
			Name:           "WrongPassword",
			SetupUser:      true,
			Password:       ANOTHER_PASS,
			ExpectedStatus: http.StatusUnauthorized,
			ExpectedBody: jsonMes(
				"crypto/bcrypt: hashedPassword is not the hash of the given password",
			),
		},
	}

	for _, d := range data {
		s.Run(d.Name, func() {
			if d.SetupUser {
				s.setupDbWithUser()
			}
			s.ech.POST("/login", s.serv.LoginUser, middleware.BasicAuth(s.serv.AuthenticateUser))
			req := httptest.NewRequest(http.MethodPost, "/login", nil)
			req.SetBasicAuth(TEST_USER, d.Password)

			s.ech.ServeHTTP(s.rec, req)

			s.Equal(d.ExpectedStatus, s.rec.Code)
			s.Equal(d.ExpectedBody, s.rec.Body.String())
		})
	}
}

func (s *ServerSuite) TestCreateInterval() {
	start := START
	end := start.Add(8 * time.Hour)

	data := []struct {
		Name           string
		Body           string
		ExpectedStatus int
		ExpectedBody   string
	}{
		{
			Name:           "ValidInterval",
			Body:           s.intrToJson(db.Interval{Start: start, End: end, Quality: 1}),
			ExpectedStatus: http.StatusCreated,
			ExpectedBody:   s.intrToJson(db.Interval{Id: 1, Start: start, End: end, Quality: 1}),
		},
		{
			Name:           "IgnoreId",
			Body:           s.intrToJson(db.Interval{Id: 10, Start: start, End: end, Quality: 1}),
			ExpectedStatus: http.StatusCreated,
			ExpectedBody:   s.intrToJson(db.Interval{Id: 1, Start: start, End: end, Quality: 1}),
		},
		{
			Name:           "EndBeforeStart",
			Body:           s.intrToJson(db.Interval{Start: end, End: start, Quality: 1}),
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
			Name:           "DisallowSubseconds",
			Body:           `{"start":"2006-01-02T15:04:05.025Z","end":"2006-01-02T16:04:05.025Z","quality":1}`,
			ExpectedStatus: http.StatusBadRequest,
			ExpectedBody:   jsonMes("subsecond values are not allowed"),
		},
		{
			Name:           "QualityBelowRange",
			Body:           s.intrToJson(db.Interval{Start: start, End: end, Quality: 0}),
			ExpectedStatus: http.StatusBadRequest,
			ExpectedBody:   jsonMes("quality out of 1-5 range"),
		},
		{
			Name:           "QualityAboveRange",
			Body:           s.intrToJson(db.Interval{Start: start, End: end, Quality: 10}),
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

func (s *ServerSuite) TestGetIntervals() {
	toJson := func(intervals []db.Interval) string {
		res, err := json.Marshal(map[string]any{"intervals": ut.Map(intervals, fromInterval)})
		s.NoError(err)
		return string(res) + "\n"
	}

	makeQuery := func(start, end string) string {
		return fmt.Sprintf("?start=%s&end=%s", start, end)
	}

	makeValidQuery := func(start, end time.Time) string {
		return makeQuery(start.Format(time.RFC3339), end.Format(time.RFC3339))
	}

	addId := func(interval db.Interval, id int64) db.Interval {
		interval.Id = id
		return interval
	}

	intervalOne := db.Interval{Start: START, End: START.Add(4 * time.Hour), Quality: 1}
	intervalOneWithId := addId(intervalOne, 1)
	intervalTwo := db.Interval{Start: START.Add(5 * time.Hour), End: START.Add(9 * time.Hour), Quality: 1}
	intervalTwoWithId := addId(intervalTwo, 2)

	data := []struct {
		Name           string
		IntervalsInDb  []db.Interval
		Query          string
		ExpectedStatus int
		ExpectedBody   string
	}{
		{
			Name:           "FullOverlap",
			IntervalsInDb:  []db.Interval{intervalOne},
			Query:          makeValidQuery(intervalOne.Start, intervalOne.End),
			ExpectedStatus: http.StatusOK,
			ExpectedBody:   toJson([]db.Interval{intervalOneWithId}),
		},
		{
			Name:          "PartiaOverlap",
			IntervalsInDb: []db.Interval{intervalOne},
			Query: makeValidQuery(
				intervalOne.Start.Add(2*time.Hour),
				intervalOne.End.Add(2*time.Hour),
			),
			ExpectedStatus: http.StatusOK,
			ExpectedBody:   toJson([]db.Interval{intervalOneWithId}),
		},
		{
			Name:           "EdgeOverlap",
			IntervalsInDb:  []db.Interval{intervalOne},
			Query:          makeValidQuery(intervalOne.End, intervalOne.End.Add(4*time.Hour)),
			ExpectedStatus: http.StatusOK,
			ExpectedBody:   toJson([]db.Interval{intervalOneWithId}),
		},
		{
			Name:          "NoOverlap",
			IntervalsInDb: []db.Interval{intervalOne},
			Query: makeValidQuery(
				intervalOne.End.Add(1*time.Hour),
				intervalOne.End.Add(5*time.Hour),
			),
			ExpectedStatus: http.StatusOK,
			ExpectedBody:   toJson([]db.Interval{}),
		},
		{
			Name:          "TwoIntervalOverlap",
			IntervalsInDb: []db.Interval{intervalOne, intervalTwo},
			Query: makeValidQuery(
				intervalOne.Start.Add(2*time.Hour),
				intervalTwo.Start.Add(2*time.Hour),
			),
			ExpectedStatus: http.StatusOK,
			ExpectedBody:   toJson([]db.Interval{intervalOneWithId, intervalTwoWithId}),
		},
		{
			Name:          "SortedByStartTime",
			IntervalsInDb: []db.Interval{intervalTwo, intervalOne},
			Query: makeValidQuery(
				intervalOne.Start.Add(2*time.Hour),
				intervalTwo.Start.Add(2*time.Hour),
			),
			ExpectedStatus: http.StatusOK,
			ExpectedBody:   toJson([]db.Interval{addId(intervalOne, 2), addId(intervalTwo, 1)}),
		},
		{
			Name:           "NoIntervals",
			IntervalsInDb:  []db.Interval{},
			Query:          makeValidQuery(intervalOne.Start, intervalOne.End),
			ExpectedStatus: http.StatusOK,
			ExpectedBody:   toJson([]db.Interval{}),
		},
		{
			Name:           "MissingQuery",
			IntervalsInDb:  []db.Interval{intervalOne},
			Query:          "",
			ExpectedStatus: http.StatusBadRequest,
			ExpectedBody:   jsonMes("missing 'start' query parameter"),
		},
		{
			Name:           "MissingStartQueryParam",
			IntervalsInDb:  []db.Interval{intervalOne},
			Query:          "?end=" + intervalOne.End.Format(time.RFC3339),
			ExpectedStatus: http.StatusBadRequest,
			ExpectedBody:   jsonMes("missing 'start' query parameter"),
		},
		{
			Name:           "MissingEndQueryParam",
			IntervalsInDb:  []db.Interval{intervalOne},
			Query:          "?start=" + intervalOne.Start.Format(time.RFC3339),
			ExpectedStatus: http.StatusBadRequest,
			ExpectedBody:   jsonMes("missing 'end' query parameter"),
		},
		{
			Name:           "WrongStartFormat",
			IntervalsInDb:  []db.Interval{intervalOne},
			Query:          makeQuery("wrongformat", intervalOne.End.Format(time.RFC3339)),
			ExpectedStatus: http.StatusBadRequest,
			ExpectedBody: jsonMes(
				`parsing time \"wrongformat\" as \"2006-01-02T15:04:05Z07:00\": ` +
					`cannot parse \"wrongformat\" as \"2006\"`,
			),
		},
		{
			Name:           "WrongEndFormat",
			IntervalsInDb:  []db.Interval{intervalOne},
			Query:          makeQuery(intervalOne.Start.Format(time.RFC3339), "wrongformat"),
			ExpectedStatus: http.StatusBadRequest,
			ExpectedBody: jsonMes(
				`parsing time \"wrongformat\" as \"2006-01-02T15:04:05Z07:00\": ` +
					`cannot parse \"wrongformat\" as \"2006\"`,
			),
		},
		{
			Name:           "DisallowSubseconds",
			IntervalsInDb:  []db.Interval{intervalOne},
			Query:          makeQuery("2006-01-02T15:04:05.025Z", "2006-01-02T16:04:05.025Z"),
			ExpectedStatus: http.StatusBadRequest,
			ExpectedBody:   jsonMes("subsecond values are not allowed"),
		},
	}

	for _, d := range data {
		s.Run(d.Name, func() {
			s.setupDbWithUser()
			for _, i := range d.IntervalsInDb {
				s.serv.db.AddInterval(TEST_USER, i)
			}

			s.ech.GET("/intervals", s.serv.GetIntervals, s.serv.JwtMiddleware())
			req := httptest.NewRequest(http.MethodGet, "/intervals"+d.Query, nil)
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
