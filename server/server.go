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
	key       = []byte("secret")
	users     = map[string]User{}
	intervals = map[string][]Interval{}
)

func AuthenticateUser(username, pass string, c echo.Context) (bool, error) {
	user, ok := users[username]
	if !ok {
		hash, err := bcrypt.GenerateFromPassword([]byte(pass), COST)
		if err != nil {
			return false, echo.NewHTTPError(http.StatusUnauthorized, err)
		}
		users[username] = User{Name: username, PassHash: hash}
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

func LoginUser(c echo.Context) error {
	username, ok := c.Get("user").(string)
	if !ok {
		return echo.NewHTTPError(http.StatusUnauthorized, "Invalid username")
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub": username,
		"exp": jwt.NewNumericDate(time.Now().Add(24 * time.Hour)),
	})
	s, err := token.SignedString(key)
	if err != nil {
		return err
	}
	return c.String(http.StatusOK, s)
}

func GetJwtMiddleware() echo.MiddlewareFunc {
	return echojwt.JWT(key)
}

func CreateInterval(c echo.Context) error {
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

	intervals[username] = append(intervals[username], interval)
	c.Logger().Infof("interval %v added for user %s", intervals[username], username)
	return c.NoContent(http.StatusOK)
}
