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
	"golang.org/x/crypto/bcrypt"
)

type User struct {
	Name     string
	PassHash []byte
}

type Interval struct {
	Start   time.Time
	End     time.Time
	Quality int
}

func (i *Interval) UnmarshalJSON(b []byte) error {
	var interval struct {
		Start   *time.Time `json:"start"`
		End     *time.Time `json:"end"`
		Quality *int       `json:"quality"`
	}
	err := json.Unmarshal(b, &interval)
	if err != nil {
		return err
	}

	if interval.Start == nil {
		return errors.New("missing \"start\" field")
	}
	if interval.End == nil {
		return errors.New("missing \"end\" field")
	}
	if interval.Quality == nil {
		return errors.New("missing \"quality\" field")
	}

	i.Start = *interval.Start
	i.End = *interval.End
	i.Quality = *interval.Quality
	return nil
}

const (
	COST = 8
)

var (
	key           = []byte("secret")
	jwtSignMethod = jwt.SigningMethodHS256
)

type Server struct {
	users     map[string]User
	intervals map[string][]Interval

	now func() time.Time
}

func New() *Server {
	return &Server{
		users:     make(map[string]User),
		intervals: make(map[string][]Interval),
		now:       func() time.Time { return time.Now() },
	}
}

func (s *Server) AuthenticateUser(username, pass string, c echo.Context) (bool, error) {
	user, ok := s.users[username]
	if !ok {
		hash, err := bcrypt.GenerateFromPassword([]byte(pass), COST)
		if err != nil {
			return false, echo.NewHTTPError(http.StatusUnauthorized, err)
		}
		s.users[username] = User{Name: username, PassHash: hash}
		c.Logger().Infof("New user signed up: %s", username)
	} else {
		if err := bcrypt.CompareHashAndPassword(user.PassHash, []byte(pass)); err != nil {
			return false, echo.NewHTTPError(http.StatusUnauthorized, err)
		}
		c.Logger().Infof("Existing user signed in: %s", username)
	}
	c.Set("user", username)
	c.Set("created", !ok)
	return true, nil
}

func (s *Server) LoginUser(c echo.Context) error {
	username, ok := c.Get("user").(string)
	if !ok {
		return errors.New("could not cast context field 'user' to string")
	}
	created, ok := c.Get("created").(bool)
	if !ok {
		return errors.New("could not cast context field 'created' to bool")
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
	token, ok := c.Get("user").(*jwt.Token)
	if !ok {
		return errors.New("could not cast context field 'user' to *jwt.Token")
	}

	username, err := token.Claims.GetSubject()
	if err != nil {
		return echo.NewHTTPError(http.StatusUnauthorized, err)
	}

	interval := Interval{}
	err = json.NewDecoder(c.Request().Body).Decode(&interval)
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, err)
	}

	if interval.Start.Compare(interval.End) != -1 {
		return echo.NewHTTPError(http.StatusBadRequest, "interval end is the same or before start")
	}
	if interval.Quality < 1 || interval.Quality > 5 {
		return echo.NewHTTPError(http.StatusBadRequest, "quality out of 1-5 range")
	}

	s.intervals[username] = append(s.intervals[username], interval)
	c.Logger().Infof("interval %v added for user %s", s.intervals[username], username)
	return c.NoContent(http.StatusCreated)
}

func (s *Server) JwtMiddleware() echo.MiddlewareFunc {
	keyFunc := func(token *jwt.Token) (interface{}, error) {
		if token.Method.Alg() != jwtSignMethod.Alg() {
			return nil, &echojwt.TokenError{Token: token, Err: fmt.Errorf("unexpected jwt signing method=%v", token.Header["alg"])}
		}
		return key, nil
	}

	return echojwt.WithConfig(echojwt.Config{
		ParseTokenFunc: func(c echo.Context, auth string) (interface{}, error) {
			token, err := jwt.ParseWithClaims(
				auth,
				jwt.MapClaims{},
				keyFunc,
				jwt.WithTimeFunc(s.now),
			)
			if err != nil {
				return nil, &echojwt.TokenError{Token: token, Err: err}
			}
			if !token.Valid {
				return nil, &echojwt.TokenError{Token: token, Err: errors.New("invalid token")}
			}
			return token, nil
		},
	})
}

func addExpiryDuration(t time.Time) time.Time {
	return t.Add(24 * time.Hour)
}
