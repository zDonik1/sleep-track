package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"slices"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/labstack/echo-jwt/v4"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	"github.com/labstack/gommon/log"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"
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

type Config struct {
	LogFormat string `mapstructure:"log-format"`
}

const (
	COST = 8
)

var (
	key       = []byte("secret")
	users     = map[string]User{}
	intervals = map[string][]Interval{}
)

func setupConfig() (*Config, error) {
	var config Config
	pflag.StringP("log-format", "l", "text", "Set log format [text, json]")
	pflag.Parse()
	viper.BindPFlags(pflag.CommandLine)
	viper.Unmarshal(&config)

	if !slices.Contains([]string{"text", "json"}, config.LogFormat) {
		return nil, fmt.Errorf("Allowed values for --log-format (-l): [text, json]. Given '%s'",
			config.LogFormat)
	}
	return &config, nil
}

func setupEcho(conf *Config) *echo.Echo {
	e := echo.New()
	e.Logger.SetLevel(log.DEBUG)

	if conf.LogFormat == "text" {
		e.Logger.SetHeader("${time_rfc3339} ${level} ${prefix} ${short_file}:${line}")
		e.Use(middleware.LoggerWithConfig(middleware.LoggerConfig{Format: "${time_rfc3339} http " +
			"${remote_ip} ${method} ${uri} => ${status} ${error}"}))
	} else {
		e.Use(middleware.Logger())
	}
	return e
}

func main() {
	conf, err := setupConfig()
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	e := setupEcho(conf)

	loginGroup := e.Group("/login", middleware.BasicAuth(func(username, pass string, c echo.Context) (bool, error) {
		user, ok := users[username]
		if !ok {
			hash, err := bcrypt.GenerateFromPassword([]byte(pass), COST)
			if err != nil {
				return false, err
			}
			users[username] = User{Name: username, PassHash: hash}
			e.Logger.Infof("New user signed up: %s", username)
		} else {
			if err := bcrypt.CompareHashAndPassword(user.PassHash, []byte(pass)); err != nil {
				return false, err
			}
			c.Logger().Infof("Existing user signed in: %s", username)
		}
		c.Set("user", username)
		return true, nil
	}))
	loginGroup.POST("", func(c echo.Context) error {
		username, ok := c.Get("user").(string)
		if !ok {
			c.Logger().Error("could not cast username to string")
			return c.String(http.StatusUnauthorized, "Invalid username")
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
	})

	intervalsGroup := e.Group("/intervals", echojwt.JWT(key))
	intervalsGroup.POST("", func(c echo.Context) error {
		token, ok := c.Get("user").(*jwt.Token)
		if !ok {
			return errors.New("JWT token missing or invalid")
		}

		expiration, err := token.Claims.GetExpirationTime()
		if err != nil {
			return err
		}
		if time.Now().Compare(expiration.Time) > 0 {
			return c.String(http.StatusUnauthorized, "JWT token is expired")
		}

		username, err := token.Claims.GetSubject()
		if err != nil {
			return err
		}

		interval := Interval{}
		err = json.NewDecoder(c.Request().Body).Decode(&interval)
		if err != nil {
			return err
		}

		intervals[username] = append(intervals[username], interval)
		e.Logger.Debug(intervals[username])
		return c.NoContent(http.StatusOK)
	})

	e.Logger.Fatal(e.Start(":8001"))
}
