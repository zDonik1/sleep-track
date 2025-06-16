package server

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/go-playground/validator/v10"
	"github.com/golang-jwt/jwt/v5"
	"github.com/labstack/echo-jwt/v4"
	"github.com/labstack/echo/v4"
	db "github.com/zDonik1/sleep-track/database"
	ut "github.com/zDonik1/sleep-track/utils"
	"golang.org/x/crypto/bcrypt"
)

var validate *validator.Validate = validator.New(validator.WithRequiredStructEnabled())

var validationMessages map[string]string = map[string]string{
	"Start required":   "missing \"start\" field",
	"End required":     "missing \"end\" field",
	"End gtfield":      "interval end is the same or before start",
	"Quality required": "missing \"quality\" field",
	"Quality gte":      "quality out of 1-5 range",
	"Quality lte":      "quality out of 1-5 range",
}

type interval struct {
	Id      *int64     `json:"id,omitempty"`
	Start   *time.Time `json:"start" validate:"required"`
	End     *time.Time `json:"end" validate:"required,gtfield=Start"`
	Quality *int       `json:"quality" validate:"required,gte=1,lte=5"`
}

func toInterval(i interval) db.Interval {
	return db.Interval{Id: *i.Id, Start: *i.Start, End: *i.End, Quality: *i.Quality}
}

func fromInterval(it db.Interval) interval {
	var i interval
	i.Id = &it.Id
	i.Start = &it.Start
	i.End = &it.End
	i.Quality = &it.Quality
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

	now func() time.Time
}

func New() *Server {
	return &Server{
		db: &db.SqlDatabase{},
		now: func() time.Time { // notest
			return time.Now()
		},
	}
}

func (s *Server) OpenDb(source string) error {
	return s.db.Open(source)
}

func (s *Server) CloseDb() error {
	return s.db.Close()
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
		err = s.db.AddUser(db.User{Name: username, PassHash: hash})
		if err != nil {
			return false, err
		}
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
			for _, err := range validationErrs {
				if msg, ok := validationMessages[fmt.Sprintf("%s %s", err.Field(), err.Tag())]; ok {
					return echo.NewHTTPError(http.StatusBadRequest, msg)
				}
			}
		}
		return echo.NewHTTPError(http.StatusBadRequest, err) // notest
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

	intervals, err := s.db.GetIntervals(username, start, end)
	if err != nil {
		return err
	}
	return c.JSON(http.StatusOK, map[string]any{"intervals": ut.Map(intervals, fromInterval)})
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
