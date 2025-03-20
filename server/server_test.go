package server

import (
	"testing"
	"time"

	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/assert"
	db "github.com/zDonik1/sleep-track/database"
)

type MockDatabase struct{}

func (d MockDatabase) Open(driver db.Driver, source string) error {
	return nil
}

func (d MockDatabase) Close() {}

func (d MockDatabase) UserExists(username string) (bool, error) {
	return false, nil
}

func (d MockDatabase) GetUser(username string) (*db.User, error) {
	return &db.User{}, nil
}

func (d MockDatabase) GetIntervals(username string, start, end time.Time) ([]db.Interval, error) {
	return []db.Interval{}, nil
}

func (d MockDatabase) AddUser(u db.User) error {
	return nil
}

func (d MockDatabase) AddInterval(username string, i db.Interval) (db.Interval, error) {
	return db.Interval{}, nil
}

func TestMissingUsernameContextKey(t *testing.T) {
	data := []struct {
		Name    string
		Handler func(*Server, echo.Context) error
	}{
		{Name: "CreateInterval", Handler: (*Server).CreateInterval},
		{Name: "GetIntervals", Handler: (*Server).GetIntervals},
	}

	for _, d := range data {
		t.Run(d.Name, func(t *testing.T) {
			serv := New()
			serv.db = MockDatabase{}
			e := echo.New()
			ctx := e.AcquireContext()
			defer e.ReleaseContext(ctx)

			err := d.Handler(serv, ctx)

			assert.ErrorContains(t, err, "context field 'username' is not set or isn't a of type string")
		})
	}
}
