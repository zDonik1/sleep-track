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
	"golang.org/x/crypto/bcrypt"
)

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
		db:       db.Database{},
		dbSource: "./sleep-track.db",
		now:      func() time.Time { return time.Now() },
	}
}

func (s *Server) OpenDb() error {
	return s.db.Open(db.DriverSqlite, s.dbSource)
}

func (s *Server) CloseDb() {
	s.db.Close()
}

func (s *Server) AuthenticateUser(username, pass string, c echo.Context) (bool, error) {
	exists, err := s.db.UserExists(username)
	if err != nil {
		return false, err
	}

	if !exists {
		hash, err := bcrypt.GenerateFromPassword([]byte(pass), COST)
		if err != nil {
			return false, echo.NewHTTPError(http.StatusUnauthorized, err)
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

	interval := db.Interval{}
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

	i, err := s.db.AddInterval(username, interval)
	if err != nil {
		return err
	}
	c.Logger().Infof("interval %v added for user %s", i, username)
	return c.JSON(http.StatusCreated, i)
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
			sub, err := token.Claims.GetSubject()
			if err != nil {
				return nil, &echojwt.TokenError{Token: token, Err: err}
			}

			exists, err := s.db.UserExists(sub)
			if err != nil {
				return nil, err
			}
			if !exists {
				return nil, fmt.Errorf("user \"%s\" doesn't exist", sub)
			}
			return token, nil
		},
	})
}

func addExpiryDuration(t time.Time) time.Time {
	return t.Add(24 * time.Hour)
}
