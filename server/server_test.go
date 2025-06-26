package server

import (
	"fmt"
	"testing"
	"time"

	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/assert"
	"github.com/zDonik1/sleep-track/service"
)

type MockDatabase struct{}

func (d MockDatabase) Open(source string) error { return nil }
func (d MockDatabase) Close() error             { return nil }
func (d MockDatabase) Wipe() error              { return nil }

func TestUnitServer(t *testing.T) {
	t.Parallel()

	tests := map[string](func(t *testing.T)){
		"MissingUsernameContextKey":     testMissingUsernameContextKey,
		"MissingContextKeysInLoginUser": testMissingContextKeysInLoginUser,
		"AddExpiryDuration":             testAddExpiryDuration,
	}

	for name, test := range tests {
		t.Run(name, test)
	}
}

func testMissingContextKeysInLoginUser(t *testing.T) {
	t.Parallel()

	keyvalues := map[string]any{
		"user":    "someuser",
		"created": false,
	}

	data := []struct {
		Name  string
		Key   string
		Type  string
		Value any
	}{
		{Name: "UserKey", Key: "user", Type: "string"},
		{Name: "CreatedKey", Key: "created", Type: "bool"},
	}

	for _, d := range data {
		t.Run(d.Name, func(t *testing.T) {
			t.Parallel()

			serv := New(service.Service{})
			e := echo.New()
			ctx := e.AcquireContext()
			defer e.ReleaseContext(ctx)

			for k, v := range keyvalues {
				if k == d.Key {
					continue
				}
				ctx.Set(k, v)
			}

			err := serv.LoginUser(ctx)

			assert.ErrorContains(t, err, fmt.Sprintf(
				"context field '%s' is not set or isn't of type %s",
				d.Key,
				d.Type,
			))
		})
	}
}

func testMissingUsernameContextKey(t *testing.T) {
	t.Parallel()

	data := []struct {
		Name    string
		Handler func(*Server, echo.Context) error
	}{
		{Name: "CreateInterval", Handler: (*Server).CreateInterval},
		{Name: "GetIntervals", Handler: (*Server).GetIntervals},
	}

	for _, d := range data {
		t.Run(d.Name, func(t *testing.T) {
			t.Parallel()

			serv := New(service.Service{})
			e := echo.New()
			ctx := e.AcquireContext()
			defer e.ReleaseContext(ctx)

			err := d.Handler(serv, ctx)

			assert.ErrorContains(
				t,
				err,
				"context field 'username' is not set or isn't of type string",
			)
		})
	}
}

func testAddExpiryDuration(t *testing.T) {
	t.Parallel()

	assert.Equal(t, TEST_TIME.Add(24*time.Hour), addExpiryDuration(TEST_TIME))
}
