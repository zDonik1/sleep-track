package server

import (
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	"github.com/labstack/gommon/log"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	db "github.com/zDonik1/sleep-track/database"
	"github.com/zDonik1/sleep-track/service"
	"github.com/zDonik1/sleep-track/utils"
	"golang.org/x/crypto/bcrypt"
)

const (
	DB_SOURCE    = ""
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

	_ = flag.Bool("verbose", false, "Set verbose log output")
)

type ServerSuite struct {
	Ech  *echo.Echo
	db   *db.SqlDatabase
	Serv *Server
	Rec  *httptest.ResponseRecorder
	t    *testing.T
}

func (s *ServerSuite) setup(t *testing.T) {
	s.Ech = echo.New()
	if viper.GetBool("verbose") {
		s.Ech.Logger.SetLevel(log.DEBUG)
		s.Ech.Logger.SetHeader("${time_rfc3339} ${level} ${prefix} ${short_file}:${line}")
		s.Ech.Use(middleware.LoggerWithConfig(middleware.LoggerConfig{Format: "${time_rfc3339} " +
			"http ${remote_ip} ${method} ${uri} => ${status} ${error}\n"}))
	}
	s.db = &db.SqlDatabase{}
	s.Serv = New(service.New(s.db))
	s.Serv.now = func() time.Time { return TEST_TIME }
	s.Rec = httptest.NewRecorder()
	s.t = t

	require.NoError(t, s.db.Open(DB_SOURCE))
}

func (s *ServerSuite) teardown() {
	require.NoError(s.t, s.db.Wipe())
	require.NoError(s.t, s.db.Close())
}

func (s *ServerSuite) setupDbWithUser() {
	hash, err := bcrypt.GenerateFromPassword([]byte(TEST_PASS), service.COST)
	require.NoError(s.t, err)
	err = s.db.AddUser(db.User{Name: TEST_USER, PassHash: hash})
	require.NoError(s.t, err)
}

func TestAcceptServer(t *testing.T) {
	if os.Getenv("INTEGRATION") == "0" {
		t.SkipNow()
	}
	t.Parallel()

	pflag.CommandLine.AddGoFlagSet(flag.CommandLine)
	pflag.Parse()
	require.NoError(t, viper.BindPFlags(pflag.CommandLine))

	tests := map[string](func(t *testing.T)){
		"LoginUser":      testLoginUser,
		"CreateInterval": testCreateInterval,
		"GetIntervals":   testGetIntervals,
		"JwtMiddleware":  testJwtMiddleware,
	}

	for name, test := range tests {
		t.Run(name, test)
	}
}

// testLoginUser also tests AuthenticateUser middleware since it is only used in this endpoint
func testLoginUser(t *testing.T) {
	data := []struct {
		Name           string
		SetupUser      bool
		SetupBasicAuth bool
		Username       string
		Password       string
		ExpectedStatus int
		ExpectedBody   string
	}{
		{
			Name:           "UserDidntExist",
			SetupUser:      false,
			SetupBasicAuth: true,
			Username:       TEST_USER,
			Password:       TEST_PASS,
			ExpectedStatus: http.StatusCreated,
			ExpectedBody:   EXPECTED_JWT,
		},
		{
			Name:           "UserExisted",
			SetupUser:      true,
			SetupBasicAuth: true,
			Username:       TEST_USER,
			Password:       TEST_PASS,
			ExpectedStatus: http.StatusOK,
			ExpectedBody:   EXPECTED_JWT,
		},
		{
			Name:           "InvalidUsername",
			SetupUser:      false,
			SetupBasicAuth: true,
			Username:       "",
			Password:       TEST_PASS,
			ExpectedStatus: http.StatusUnauthorized,
			ExpectedBody:   jsonMes("invalid username: the username is empty"),
		},
		{
			Name:           "InvalidPassword",
			SetupUser:      false,
			SetupBasicAuth: true,
			Username:       TEST_USER,
			Password:       "",
			ExpectedStatus: http.StatusUnauthorized,
			ExpectedBody:   jsonMes("invalid password: the password is empty"),
		},
		{
			Name:           "WrongPassword",
			SetupUser:      true,
			SetupBasicAuth: true,
			Username:       TEST_USER,
			Password:       ANOTHER_PASS,
			ExpectedStatus: http.StatusUnauthorized,
			ExpectedBody: jsonMes(
				"crypto/bcrypt: hashedPassword is not the hash of the given password",
			),
		},
		{
			Name:           "NoBasicAuth",
			SetupUser:      false,
			SetupBasicAuth: false,
			ExpectedStatus: http.StatusUnauthorized,
			ExpectedBody:   jsonMes("Unauthorized"),
		},
	}

	for _, d := range data {
		t.Run(d.Name, func(t *testing.T) {
			s := ServerSuite{}
			s.setup(t)
			defer s.teardown()
			if d.SetupUser {
				s.setupDbWithUser()
			}
			s.Ech.POST("/login", s.Serv.LoginUser, middleware.BasicAuth(s.Serv.AuthenticateUser))
			req := httptest.NewRequest(http.MethodPost, "/login", nil)
			if d.SetupBasicAuth {
				req.SetBasicAuth(d.Username, d.Password)
			}

			s.Ech.ServeHTTP(s.Rec, req)

			assert.Equal(t, d.ExpectedStatus, s.Rec.Code)
			assert.Equal(t, d.ExpectedBody, s.Rec.Body.String())
		})
	}
}

func testCreateInterval(t *testing.T) {
	start := START
	end := start.Add(8 * time.Hour)
	interval := service.Interval{Start: start, End: end}

	data := []struct {
		Name           string
		Body           string
		ExpectedStatus int
		ExpectedBody   string
	}{
		{
			Name:           "ValidInterval",
			Body:           toJson(t, service.SleepInterval{Interval: interval, Quality: 1}),
			ExpectedStatus: http.StatusCreated,
			ExpectedBody:   toJson(t, service.SleepInterval{Interval: interval, Id: 1, Quality: 1}),
		},
		{
			Name:           "IgnoreId",
			Body:           toJson(t, service.SleepInterval{Interval: interval, Id: 10, Quality: 1}),
			ExpectedStatus: http.StatusCreated,
			ExpectedBody:   toJson(t, service.SleepInterval{Interval: interval, Id: 1, Quality: 1}),
		},
		{
			Name: "EndBeforeStart",
			Body: toJson(t, service.SleepInterval{
				Interval: service.Interval{Start: interval.End, End: interval.Start},
				Quality:  1,
			}),
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
			Body:           toJson(t, service.SleepInterval{Interval: interval, Quality: 0}),
			ExpectedStatus: http.StatusBadRequest,
			ExpectedBody:   jsonMes("quality out of 1-5 range"),
		},
		{
			Name:           "QualityAboveRange",
			Body:           toJson(t, service.SleepInterval{Interval: interval, Quality: 10}),
			ExpectedStatus: http.StatusBadRequest,
			ExpectedBody:   jsonMes("quality out of 1-5 range"),
		},
		{
			Name:           "MissingStartField",
			Body:           `{"end":"2006-01-02T15:04:05Z","quality":1}`,
			ExpectedStatus: http.StatusBadRequest,
			ExpectedBody:   jsonMes(`missing \"start\" field`),
		},
		{
			Name:           "MissingEndField",
			Body:           `{"start":"2006-01-02T15:04:05Z","quality":1}`,
			ExpectedStatus: http.StatusBadRequest,
			ExpectedBody:   jsonMes(`missing \"end\" field`),
		},
		{
			Name:           "MissingQualityField",
			Body:           toJson(t, map[string]any{"start": start, "end": end}),
			ExpectedStatus: http.StatusBadRequest,
			ExpectedBody:   jsonMes(`missing \"quality\" field`),
		},
		{
			Name:           "MissingBody",
			Body:           "",
			ExpectedStatus: http.StatusBadRequest,
			ExpectedBody:   jsonMes("EOF"),
		},
	}

	for _, d := range data {
		t.Run(d.Name, func(t *testing.T) {
			s := ServerSuite{}
			s.setup(t)
			defer s.teardown()
			s.setupDbWithUser()
			s.Ech.POST("/intervals", s.Serv.CreateInterval, s.Serv.JwtMiddleware())
			req := httptest.NewRequest(http.MethodPost, "/intervals", strings.NewReader(d.Body))
			req.Header.Add("Authorization", "Bearer "+EXPECTED_JWT)

			s.Ech.ServeHTTP(s.Rec, req)

			assert.Equal(t, d.ExpectedStatus, s.Rec.Result().StatusCode)
			assert.Equal(t, d.ExpectedBody, s.Rec.Body.String())
		})
	}
}

func testGetIntervals(t *testing.T) {
	intervalsToJson := func(t *testing.T, intervals []service.SleepInterval) string {
		res, err := json.Marshal(map[string]any{"intervals": utils.Map(intervals, fromSvcInterval)})
		require.NoError(t, err)
		return string(res) + "\n"
	}

	makeQuery := func(start, end string) string {
		return fmt.Sprintf("?start=%s&end=%s", start, end)
	}

	makeValidQuery := func(start, end time.Time) string {
		return makeQuery(start.Format(time.RFC3339), end.Format(time.RFC3339))
	}

	addId := func(interval service.SleepInterval, id int64) service.SleepInterval {
		interval.Id = id
		return interval
	}

	intervalOne := service.SleepInterval{Interval: service.Interval{Start: START, End: START.Add(4 * time.Hour)}, Quality: 1}
	intervalOneWithId := addId(intervalOne, 1)
	intervalTwo := service.SleepInterval{Interval: service.Interval{Start: START.Add(5 * time.Hour), End: START.Add(9 * time.Hour)}, Quality: 1}
	intervalTwoWithId := addId(intervalTwo, 2)

	data := []struct {
		Name           string
		IntervalsInDb  []service.SleepInterval
		Query          string
		ExpectedStatus int
		ExpectedBody   string
	}{
		{
			Name:           "FullOverlap",
			IntervalsInDb:  []service.SleepInterval{intervalOne},
			Query:          makeValidQuery(intervalOne.Start, intervalOne.End),
			ExpectedStatus: http.StatusOK,
			ExpectedBody:   intervalsToJson(t, []service.SleepInterval{intervalOneWithId}),
		},
		{
			Name:          "PartiaOverlap",
			IntervalsInDb: []service.SleepInterval{intervalOne},
			Query: makeValidQuery(
				intervalOne.Start.Add(2*time.Hour),
				intervalOne.End.Add(2*time.Hour),
			),
			ExpectedStatus: http.StatusOK,
			ExpectedBody:   intervalsToJson(t, []service.SleepInterval{intervalOneWithId}),
		},
		{
			Name:           "EdgeOverlap",
			IntervalsInDb:  []service.SleepInterval{intervalOne},
			Query:          makeValidQuery(intervalOne.End, intervalOne.End.Add(4*time.Hour)),
			ExpectedStatus: http.StatusOK,
			ExpectedBody:   intervalsToJson(t, []service.SleepInterval{intervalOneWithId}),
		},
		{
			Name:          "NoOverlap",
			IntervalsInDb: []service.SleepInterval{intervalOne},
			Query: makeValidQuery(
				intervalOne.End.Add(1*time.Hour),
				intervalOne.End.Add(5*time.Hour),
			),
			ExpectedStatus: http.StatusOK,
			ExpectedBody:   intervalsToJson(t, []service.SleepInterval{}),
		},
		{
			Name:          "TwoIntervalOverlap",
			IntervalsInDb: []service.SleepInterval{intervalOne, intervalTwo},
			Query: makeValidQuery(
				intervalOne.Start.Add(2*time.Hour),
				intervalTwo.Start.Add(2*time.Hour),
			),
			ExpectedStatus: http.StatusOK,
			ExpectedBody:   intervalsToJson(t, []service.SleepInterval{intervalOneWithId, intervalTwoWithId}),
		},
		{
			Name:          "SortedByStartTime",
			IntervalsInDb: []service.SleepInterval{intervalTwo, intervalOne},
			Query: makeValidQuery(
				intervalOne.Start.Add(2*time.Hour),
				intervalTwo.Start.Add(2*time.Hour),
			),
			ExpectedStatus: http.StatusOK,
			ExpectedBody:   intervalsToJson(t, []service.SleepInterval{addId(intervalOne, 2), addId(intervalTwo, 1)}),
		},
		{
			Name:           "NoIntervals",
			IntervalsInDb:  []service.SleepInterval{},
			Query:          makeValidQuery(intervalOne.Start, intervalOne.End),
			ExpectedStatus: http.StatusOK,
			ExpectedBody:   intervalsToJson(t, []service.SleepInterval{}),
		},
		{
			Name:           "EndBeforeStart",
			IntervalsInDb:  []service.SleepInterval{},
			Query:          makeValidQuery(intervalOne.End, intervalOne.Start),
			ExpectedStatus: http.StatusBadRequest,
			ExpectedBody:   jsonMes("interval end is the same or before start"),
		},
		{
			Name:           "MissingQuery",
			IntervalsInDb:  []service.SleepInterval{intervalOne},
			Query:          "",
			ExpectedStatus: http.StatusBadRequest,
			ExpectedBody:   jsonMes("missing 'start' query parameter"),
		},
		{
			Name:           "MissingStartQueryParam",
			IntervalsInDb:  []service.SleepInterval{intervalOne},
			Query:          "?end=" + intervalOne.End.Format(time.RFC3339),
			ExpectedStatus: http.StatusBadRequest,
			ExpectedBody:   jsonMes("missing 'start' query parameter"),
		},
		{
			Name:           "MissingEndQueryParam",
			IntervalsInDb:  []service.SleepInterval{intervalOne},
			Query:          "?start=" + intervalOne.Start.Format(time.RFC3339),
			ExpectedStatus: http.StatusBadRequest,
			ExpectedBody:   jsonMes("missing 'end' query parameter"),
		},
		{
			Name:           "WrongStartFormat",
			IntervalsInDb:  []service.SleepInterval{intervalOne},
			Query:          makeQuery("wrongformat", intervalOne.End.Format(time.RFC3339)),
			ExpectedStatus: http.StatusBadRequest,
			ExpectedBody: jsonMes(
				`parsing time \"wrongformat\" as \"2006-01-02T15:04:05Z07:00\": ` +
					`cannot parse \"wrongformat\" as \"2006\"`,
			),
		},
		{
			Name:           "WrongEndFormat",
			IntervalsInDb:  []service.SleepInterval{intervalOne},
			Query:          makeQuery(intervalOne.Start.Format(time.RFC3339), "wrongformat"),
			ExpectedStatus: http.StatusBadRequest,
			ExpectedBody: jsonMes(
				`parsing time \"wrongformat\" as \"2006-01-02T15:04:05Z07:00\": ` +
					`cannot parse \"wrongformat\" as \"2006\"`,
			),
		},
	}

	for _, d := range data {
		t.Run(d.Name, func(t *testing.T) {
			s := ServerSuite{}
			s.setup(t)
			defer s.teardown()
			s.setupDbWithUser()
			for _, i := range d.IntervalsInDb {
				_, err := s.Serv.svc.CreateInterval(TEST_USER, i)
				require.NoError(t, err)
			}

			s.Ech.GET("/intervals", s.Serv.GetIntervals, s.Serv.JwtMiddleware())
			req := httptest.NewRequest(http.MethodGet, "/intervals"+d.Query, nil)
			req.Header.Add("Authorization", "Bearer "+EXPECTED_JWT)

			s.Ech.ServeHTTP(s.Rec, req)

			assert.Equal(t, d.ExpectedStatus, s.Rec.Result().StatusCode)
			assert.Equal(t, d.ExpectedBody, s.Rec.Body.String())
		})

	}
}

func testJwtMiddleware(t *testing.T) {
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
	// The case with empty string subject and missing subject should never happen since the server
	// never creates JWT with empty subjec. Verified by TestLoginUser tests.

	for _, d := range data {
		t.Run(d.Name, func(t *testing.T) {
			s := ServerSuite{}
			s.setup(t)
			defer s.teardown()
			if d.SetupUser {
				s.setupDbWithUser()
			}
			s.Ech.POST(
				"/temp",
				func(c echo.Context) error {
					assert.Fail(t, "should never reach handler")
					return nil
				},
				s.Serv.JwtMiddleware(),
			)
			req := httptest.NewRequest(http.MethodPost, "/temp", nil)
			req.Header.Add("Authorization", "Bearer "+d.Jwt)

			s.Ech.ServeHTTP(s.Rec, req)

			assert.Equal(t, d.ExpectedStatus, s.Rec.Result().StatusCode)
			assert.Equal(t, d.ExpectedBody, s.Rec.Body.String())
		})
	}
}

// ------------------------------------------------
// HELPERS
// ------------------------------------------------

func jsonMes(mes string) string {
	return fmt.Sprintf(`{"message":"%s"}`+"\n", mes)
}

func toJson(t *testing.T, v any) string {
	if i, ok := v.(service.SleepInterval); ok {
		v = fromSvcInterval(i)
	}
	res, err := json.Marshal(v)
	require.NoError(t, err)
	return string(res) + "\n"
}
