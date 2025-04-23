package server

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/labstack/echo-jwt/v4"
	"github.com/labstack/echo/v4"
	db "github.com/zDonik1/sleep-track/database"
	ut "github.com/zDonik1/sleep-track/utils"
	"golang.org/x/crypto/bcrypt"
)

type NoSsTime struct {
	time.Time
}

func (t *NoSsTime) UnmarshalJSON(b []byte) error {
	var tm time.Time
	err := json.Unmarshal(b, &tm)
	if err != nil {
		return err
	}
	if tm.Nanosecond() != 0 {
		return errors.New("subsecond values are not allowed")
	}

	t.Time = tm
	return nil
}

func (t *NoSsTime) Parse(layout, value string) error {
	tm, err := time.Parse(layout, value)
	if err != nil {
		return err
	}
	if tm.Nanosecond() != 0 {
		return errors.New("subsecond values are not allowed")
	}

	t.Time = tm
	return nil
}

type validatingInterval struct {
	Id      int64
	Start   NoSsTime
	End     NoSsTime
	Quality int
}

type jsonIntervalNoId struct {
	Start   *NoSsTime `json:"start"`
	End     *NoSsTime `json:"end"`
	Quality *int      `json:"quality"`
}

type jsonInterval struct {
	Id *int64 `json:"id"`
	jsonIntervalNoId
}

func (i validatingInterval) MarshalJSON() ([]byte, error) {
	intrNoId := jsonIntervalNoId{Start: &i.Start, End: &i.End, Quality: &i.Quality}
	if i.Id == 0 {
		return json.Marshal(intrNoId)
	}
	return json.Marshal(jsonInterval{Id: &i.Id, jsonIntervalNoId: intrNoId})
}

func (i *validatingInterval) UnmarshalJSON(b []byte) error {
	var jsonIntr jsonInterval
	err := json.Unmarshal(b, &jsonIntr)
	if err != nil {
		return err
	}

	if jsonIntr.Start == nil {
		return errors.New("missing \"start\" field")
	}
	if jsonIntr.End == nil {
		return errors.New("missing \"end\" field")
	}
	if jsonIntr.Quality == nil {
		return errors.New("missing \"quality\" field")
	}

	i.Start = *jsonIntr.Start
	i.End = *jsonIntr.End
	i.Quality = *jsonIntr.Quality
	return nil
}

func toInterval(i validatingInterval) db.Interval {
	return db.Interval{Id: i.Id, Start: i.Start.Time, End: i.End.Time, Quality: i.Quality}
}

func fromInterval(it db.Interval) validatingInterval {
	var i validatingInterval
	i.Id = it.Id
	i.Start.Time = it.Start
	i.End.Time = it.End
	i.Quality = it.Quality
	return i
}

const (
	COST = 8
)

var (
	key           = []byte("secret")
	jwtSignMethod = jwt.SigningMethodHS256
)

type Server struct {
	db db.Database

	dbSource string
	now      func() time.Time
}

func New() *Server {
	return &Server{
		db:       &db.SqlDatabase{},
		dbSource: "./sleep-track.db",
		now: func() time.Time { // notest
			return time.Now()
		},
	}
}

func (s *Server) OpenDb() error {
	return s.db.Open(db.DriverSqlite, s.dbSource)
}

func (s *Server) CloseDb() {
	s.db.Close()
}

func (s *Server) AuthenticateUser(username, pass string, c echo.Context) (bool, error) {
	if username == "" {
		return false, echo.NewHTTPError(
			http.StatusUnauthorized,
			"invalid username: the username is empty",
		)
	}
	if pass == "" {
		return false, echo.NewHTTPError(
			http.StatusUnauthorized,
			"invalid password: the password is empty",
		)
	}

	exists, err := s.db.UserExists(username)
	if err != nil {
		return false, err
	}

	if !exists {
		hash, err := bcrypt.GenerateFromPassword([]byte(pass), COST)
		if err != nil {
			return false, err
		}
		s.db.AddUser(db.User{Name: username, PassHash: hash})
		c.Logger().Infof("New user signed up: %s", username)
	} else {
		user, err := s.db.GetUser(username)
		if err != nil {
			return false, err
		}

		if err := bcrypt.CompareHashAndPassword(user.PassHash, []byte(pass)); err != nil {
			return false, echo.NewHTTPError(http.StatusUnauthorized, err)
		}
		c.Logger().Infof("Existing user signed in: %s", username)
	}
	c.Set("user", username)
	c.Set("created", !exists)
	return true, nil
}

func (s *Server) LoginUser(c echo.Context) error {
	username, ok := c.Get("user").(string)
	if !ok {
		return errors.New("context field 'user' is not set or isn't a of type string")
	}
	created, ok := c.Get("created").(bool)
	if !ok {
		return errors.New("context field 'created' is not set or isn't a of type bool")
	}

	token := jwt.NewWithClaims(jwtSignMethod, jwt.MapClaims{
		"sub": username,
		"exp": jwt.NewNumericDate(addExpiryDuration(s.now())),
	})
	strTok, err := token.SignedString(key)
	if err != nil {
		return err
	}

	status := http.StatusOK
	if created {
		status = http.StatusCreated
	}
	return c.String(status, strTok)
}

func (s *Server) CreateInterval(c echo.Context) error {
	username, ok := c.Get("username").(string)
	if !ok {
		return errors.New("context field 'username' is not set or isn't a of type string")
	}

	interval := validatingInterval{}
	err := json.NewDecoder(c.Request().Body).Decode(&interval)
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, err)
	}

	if interval.Start.Compare(interval.End.Time) != -1 {
		return echo.NewHTTPError(http.StatusBadRequest, "interval end is the same or before start")
	}
	if interval.Quality < 1 || interval.Quality > 5 {
		return echo.NewHTTPError(http.StatusBadRequest, "quality out of 1-5 range")
	}

	i, err := s.db.AddInterval(username, toInterval(interval))
	if err != nil {
		return err
	}
	return c.JSON(http.StatusCreated, fromInterval(i))
}

func (s *Server) GetIntervals(c echo.Context) error {
	username, ok := c.Get("username").(string)
	if !ok {
		return errors.New("context field 'username' is not set or isn't a of type string")
	}

	qp := c.QueryParams()
	if !qp.Has("start") {
		return echo.NewHTTPError(http.StatusBadRequest, "missing 'start' query parameter")
	}
	if !qp.Has("end") {
		return echo.NewHTTPError(http.StatusBadRequest, "missing 'end' query parameter")
	}

	var start, end NoSsTime
	err := start.Parse(time.RFC3339, qp.Get("start"))
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, err)
	}
	err = end.Parse(time.RFC3339, qp.Get("end"))
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, err)
	}

	intervals, err := s.db.GetIntervals(username, start.Time, end.Time)
	if err != nil {
		return err
	}
	validatingIntervals := ut.Map(intervals, fromInterval)
	return c.JSON(http.StatusOK, map[string]any{"intervals": validatingIntervals})
}

func (s *Server) JwtMiddleware() echo.MiddlewareFunc {
	// JWT middleware is wrapped with our UserVerification handler
	// echo -> JWT -> UserVerification -> next
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		userVerification := func(c echo.Context) error {
			token, ok := c.Get("user").(*jwt.Token)
			if !ok { // notest: since directly connected to JwtMiddleware in same scope
				return errors.New("context field 'user' is not set or isn't of type *jwt.Token")
			}
			sub, err := token.Claims.GetSubject()
			if err != nil {
				return err
			}
			exists, err := s.db.UserExists(sub)
			if err != nil {
				return err
			}
			if !exists {
				return echo.NewHTTPError(http.StatusUnauthorized, "invalid or expired jwt")
			}
			c.Set("username", sub)
			return next(c)
		}

		jwtMw := echojwt.WithConfig(echojwt.Config{ParseTokenFunc: s.parseTokenFunc})
		return jwtMw(userVerification)
	}
}

// Implementation taken from echojwt. Only necessary so we can pass custom time func
// for parsing claims
func (s *Server) parseTokenFunc(_ echo.Context, auth string) (interface{}, error) { // notest
	keyFunc := func(token *jwt.Token) (interface{}, error) {
		if token.Method.Alg() != jwtSignMethod.Alg() {
			return nil, &echojwt.TokenError{
				Token: token,
				Err:   fmt.Errorf("unexpected jwt signing method=%v", token.Header["alg"]),
			}
		}
		return key, nil
	}

	token, err := jwt.ParseWithClaims(auth, jwt.MapClaims{}, keyFunc, jwt.WithTimeFunc(s.now))
	if err != nil {
		return nil, &echojwt.TokenError{Token: token, Err: err}
	}
	if !token.Valid {
		return nil, &echojwt.TokenError{Token: token, Err: errors.New("invalid token")}
	}
	return token, nil
}

func addExpiryDuration(t time.Time) time.Time {
	return t.Add(24 * time.Hour)
}
