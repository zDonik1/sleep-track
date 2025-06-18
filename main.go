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

	"github.com/zDonik1/sleep-track/database"
	"github.com/zDonik1/sleep-track/server"
	"github.com/zDonik1/sleep-track/service"
)

type Config struct {
	LogFormat string `mapstructure:"log-format"`
	DbSource  string `mapstructure:"db-source"`
}

func setupConfig() (*Config, error) {
	var config Config
	pflag.StringP("log-format", "l", "text", "Set log format [text, json]")
	pflag.Parse()
	if err := viper.BindPFlags(pflag.CommandLine); err != nil {
		return nil, err
	}
	viper.SetDefault("db-source", "./sleep-track.db")
	if err := viper.Unmarshal(&config); err != nil {
		return nil, err
	}

	if !slices.Contains([]string{"text", "json"}, config.LogFormat) {
		return nil, fmt.Errorf("allowed values for --log-format (-l): [text, json]. Given '%s'",
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
	db := database.SqlDatabase{}
	s := server.New(service.New(&db))
	if err = db.Open(conf.DbSource); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	defer func() {
		if err := db.Close(); err != nil {
			panic(err)
		}
	}()

	e.POST("/login", s.LoginUser, middleware.BasicAuth(s.AuthenticateUser))

	intervalsGroup := e.Group("/intervals", s.JwtMiddleware())
	intervalsGroup.GET("", s.GetIntervals)
	intervalsGroup.POST("", s.CreateInterval)

	e.Logger.Fatal(e.Start(":8001"))
}
