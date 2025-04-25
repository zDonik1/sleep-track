package main

import (
	"fmt"
	"os"
	"slices"

	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	"github.com/labstack/gommon/log"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"

	"github.com/zDonik1/sleep-track/server"
)

type Config struct {
	LogFormat string `mapstructure:"log-format"`
}

func setupConfig() (*Config, error) {
	var config Config
	pflag.StringP("log-format", "l", "text", "Set log format [text, json]")
	pflag.Parse()
	if err := viper.BindPFlags(pflag.CommandLine); err != nil {
		return nil, err
	}
	if err := viper.Unmarshal(&config); err != nil {
		return nil, err
	}

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
		e.Use(middleware.LoggerWithConfig(middleware.LoggerConfig{Format: "${time_rfc3339} " +
			"http ${remote_ip} ${method} ${uri} => ${status} ${error}\n"}))
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
	s := server.New()
	if err = s.OpenDb(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	defer s.CloseDb()

	e.POST("/login", s.LoginUser, middleware.BasicAuth(s.AuthenticateUser))

	intervalsGroup := e.Group("/intervals", s.JwtMiddleware())
	intervalsGroup.POST("", s.CreateInterval)

	e.Logger.Fatal(e.Start(":8001"))
}
