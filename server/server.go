package server

import (
	"encoding/json"
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
}

func New() *Server {
	return &Server{users: make(map[string]User), intervals: make(map[string][]Interval)}
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
	return true, nil
}

func (s *Server) LoginUser(c echo.Context) error {
	username, ok := c.Get("user").(string)
	if !ok {
		return echo.NewHTTPError(http.StatusUnauthorized, "Invalid username")
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub": username,
		"exp": jwt.NewNumericDate(time.Now().Add(24 * time.Hour)),
	})
	strTok, err := token.SignedString(key)
	if err != nil {
		return err
	}
	return c.String(http.StatusOK, strTok)
}

func (s *Server) CreateInterval(c echo.Context) error {
	token, ok := c.Get("user").(*jwt.Token)
	if !ok {
		return echo.NewHTTPError(http.StatusUnauthorized, "JWT token missing or invalid")
	}

	expiration, err := token.Claims.GetExpirationTime()
	if err != nil {
		return echo.NewHTTPError(http.StatusUnauthorized, err)
	}
	if time.Now().Compare(expiration.Time) > 0 {
		return echo.NewHTTPError(http.StatusUnauthorized, "JWT token is expired")
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
	return c.NoContent(http.StatusOK)
}

func GetJwtMiddleware() echo.MiddlewareFunc {
	return echojwt.JWT(key)
}
