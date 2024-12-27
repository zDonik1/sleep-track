package server

import (
	"encoding/json"
	"errors"
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
	Start   time.Time `json:"start"`
	End     time.Time `json:"end"`
	Quality int       `json:"quality"`
}

const (
	COST = 8
)

var (
	key = []byte("secret")
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

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
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
		return echo.NewHTTPError(http.StatusUnauthorized, "JWT token missing or invalid")
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

	s.intervals[username] = append(s.intervals[username], interval)
	c.Logger().Infof("interval %v added for user %s", s.intervals[username], username)
	return c.NoContent(http.StatusCreated)
}

func GetJwtMiddleware() echo.MiddlewareFunc {
	return echojwt.JWT(key)
}

func addExpiryDuration(t time.Time) time.Time {
	return t.Add(24 * time.Hour)
}
