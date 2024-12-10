package main

import (
	"net/http"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/labstack/echo-jwt/v4"
	"github.com/labstack/echo/v4"
	"github.com/labstack/gommon/log"
	"golang.org/x/crypto/bcrypt"
)

type User struct {
	Name     string
	PassHash []byte
}

const (
	COST = 8
)

var (
	key   = []byte("secret")
	users = map[string]User{}
)

func main() {
	e := echo.New()
	e.Logger.SetLevel(log.DEBUG)

	e.POST("/login", func(c echo.Context) error {
		unameCookie, err := c.Cookie("user")
		if err != nil {
			return err
		}
		username := unameCookie.Name

		passCookie, err := c.Cookie("password")
		if err != nil {
			return err
		}
		password := passCookie.Name

		// add new or check existing user
		user, ok := users[username]
		if !ok {
			hash, err := bcrypt.GenerateFromPassword([]byte(password), COST)
			if err != nil {
				return err
			}
			users[username] = User{Name: username, PassHash: hash}
			e.Logger.Infof("New user signed up: %s", username)
		} else {
			if err := bcrypt.CompareHashAndPassword(user.PassHash, []byte(password)); err != nil {
				return err
			}
			e.Logger.Infof("Existing user signed in: %s", username)
		}

		// return token
		token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
			"sub": username,
			"exp": time.Now().Add(24 * time.Hour).Unix(),
		})
		s, err := token.SignedString(key)
		if err != nil {
			return err
		}
		return c.String(http.StatusOK, s)
	})

	intervalsGroup := e.Group("/intervals")
	intervalsGroup.Use(echojwt.JWT(key))

	intervalsGroup.POST("", func(c echo.Context) error {
		return c.NoContent(http.StatusNoContent)
	})

	e.Logger.Fatal(e.Start(":8001"))
}
