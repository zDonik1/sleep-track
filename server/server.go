package server

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/go-playground/validator/v10"
	"github.com/golang-jwt/jwt/v5"
	"github.com/labstack/echo-jwt/v4"
	"github.com/labstack/echo/v4"
	svc "github.com/zDonik1/sleep-track/service"
	ut "github.com/zDonik1/sleep-track/utils"
)

var (
	validate      *validator.Validate = validator.New(validator.WithRequiredStructEnabled())
	key                               = []byte("secret")
	jwtSignMethod                     = jwt.SigningMethodHS256
)

type interval struct {
	Id      *int64     `json:"id,omitempty"`
	Start   *time.Time `json:"start" validate:"required"`
	End     *time.Time `json:"end" validate:"required"`
	Quality *int       `json:"quality" validate:"required"`
}

type Server struct {
	svc svc.Service

	now func() time.Time
}

func New(svc svc.Service) *Server {
	return &Server{
		svc: svc,
		now: func() time.Time { // notest
			return time.Now()
		},
	}
}

func (s *Server) Health(c echo.Context) error {
	return c.NoContent(http.StatusOK)
}

func (s *Server) AuthenticateUser(username, pass string, c echo.Context) (bool, error) {
	created, err := s.svc.AuthenticateUser(username, pass)
	if err != nil {
		if _, ok := err.(svc.UnauthorizedError); ok {
			err = echo.NewHTTPError(http.StatusUnauthorized, err)
		}
		return false, err
	}

	c.Set("user", username)
	c.Set("created", created)
	return true, nil
}

func (s *Server) LoginUser(c echo.Context) error {
	username, ok := c.Get("user").(string)
	if !ok {
		return errors.New("context field 'user' is not set or isn't of type string")
	}
	created, ok := c.Get("created").(bool)
	if !ok {
		return errors.New("context field 'created' is not set or isn't of type bool")
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
		return errors.New("context field 'username' is not set or isn't of type string")
	}

	interval := interval{}
	if err := json.NewDecoder(c.Request().Body).Decode(&interval); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, err)
	}
	if err := validate.Struct(interval); err != nil {
		var validationErrs validator.ValidationErrors
		if errors.As(err, &validationErrs) {
			err = fmt.Errorf(`missing "%s" field`, strings.ToLower(validationErrs[0].Field()))
		}
		return echo.NewHTTPError(http.StatusBadRequest, err)
	}

	intr, err := s.svc.CreateInterval(username, toSvcInterval(interval))
	if err != nil {
		if _, ok := err.(svc.ValidationError); ok {
			err = echo.NewHTTPError(http.StatusBadRequest, err)
		}
		return err
	}
	return c.JSON(http.StatusCreated, fromSvcInterval(intr))
}

func (s *Server) GetIntervals(c echo.Context) error {
	username, ok := c.Get("username").(string)
	if !ok {
		return errors.New("context field 'username' is not set or isn't of type string")
	}

	qp := c.QueryParams()
	if !qp.Has("start") {
		return echo.NewHTTPError(http.StatusBadRequest, "missing 'start' query parameter")
	}
	if !qp.Has("end") {
		return echo.NewHTTPError(http.StatusBadRequest, "missing 'end' query parameter")
	}

	start, err := time.Parse(time.RFC3339, qp.Get("start"))
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, err)
	}
	end, err := time.Parse(time.RFC3339, qp.Get("end"))
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, err)
	}

	intervals, err := s.svc.GetIntervals(username, svc.Interval{Start: start, End: end})
	if err != nil {
		if _, ok := err.(svc.ValidationError); ok {
			err = echo.NewHTTPError(http.StatusBadRequest, err)
		}
		return err
	}
	return c.JSON(http.StatusOK, map[string]any{"intervals": ut.Map(intervals, fromSvcInterval)})
}

func (s *Server) JwtMiddleware() echo.MiddlewareFunc {
	// JWT middleware warps our UserVerification handler
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
			exists, err := s.svc.UserExists(sub)
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
func (s *Server) parseTokenFunc(_ echo.Context, auth string) (any, error) { // notest
	keyFunc := func(token *jwt.Token) (any, error) {
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

func fromSvcInterval(i svc.SleepInterval) interval {
	return interval{
		Id:      &i.Id,
		Start:   &i.Start,
		End:     &i.End,
		Quality: &i.Quality,
	}
}

func toSvcInterval(i interval) svc.SleepInterval {
	var id int64 = 0
	if i.Id != nil {
		id = *i.Id
	}
	return svc.SleepInterval{
		Interval: svc.Interval{Start: *i.Start, End: *i.End},
		Id:       id,
		Quality:  *i.Quality,
	}
}
