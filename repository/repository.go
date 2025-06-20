//go:generate sqlc generate

package repository

import (
	"context"
	_ "embed"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/zDonik1/sleep-track/repository/sleepdb"
)

//go:embed schema.sql
var schema string

type User struct {
	Name     string
	PassHash []byte
}

type Interval struct {
	Id      int64
	Start   time.Time
	End     time.Time
	Quality int
}

type Database interface {
	Open(source string) error
	Close() error
	Wipe() error
	UserExists(username string) (bool, error)
	GetUser(username string) (User, error)
	GetIntervals(username string, start, end time.Time) ([]Interval, error)
	AddUser(u User) error
	AddInterval(username string, i Interval) (Interval, error)
}

func New() Database {
	return &sqlDatabase{}
}

type sqlDatabase struct {
	conn    *pgx.Conn
	queries *sleepdb.Queries
}

func (d *sqlDatabase) Open(source string) error {
	conn, err := pgx.Connect(context.Background(), source)
	if err != nil {
		return err
	}
	d.conn = conn
	_, err = d.conn.Exec(context.Background(), schema)
	d.queries = sleepdb.New(conn)
	return err
}

func (d *sqlDatabase) Close() error {
	return d.conn.Close(context.Background())
}

func (d *sqlDatabase) Wipe() error {
	return d.queries.Wipe(context.Background())
}

func (d *sqlDatabase) UserExists(username string) (bool, error) {
	return d.queries.UserExists(context.Background(), username)
}

func (d *sqlDatabase) GetUser(username string) (User, error) {
	user, err := d.queries.GetUser(context.Background(), username)
	return User{Name: user.Name, PassHash: user.Passhash}, err
}

func (d *sqlDatabase) GetIntervals(username string, start, end time.Time) ([]Interval, error) {
	rows, err := d.queries.GetIntervals(context.Background(), sleepdb.GetIntervalsParams{
		Username:  username,
		Intrstart: pgtype.Timestamptz{Time: end, Valid: true},
		Intrend:   pgtype.Timestamptz{Time: start, Valid: true},
	})
	if err != nil {
		return nil, err
	}

	result := make([]Interval, 0)
	for _, v := range rows {
		start, sok := v.Timezone.(time.Time)
		end, eok := v.Timezone_2.(time.Time)
		if !sok || !eok { // notest
			return nil, errors.New("could not cast timezone field to Time type")
		}
		result = append(result, Interval{
			Id:      int64(v.ID),
			Start:   start,
			End:     end,
			Quality: int(v.Quality),
		})
	}
	return result, nil
}

func (d *sqlDatabase) AddUser(u User) error {
	return d.queries.AddUser(context.Background(), sleepdb.AddUserParams{
		Name:     u.Name,
		Passhash: u.PassHash,
	})
}

func (d *sqlDatabase) AddInterval(username string, i Interval) (Interval, error) {
	id, err := d.queries.AddInterval(context.Background(), sleepdb.AddIntervalParams{
		Intrstart: pgtype.Timestamptz{Time: i.Start, Valid: true},
		Intrend:   pgtype.Timestamptz{Time: i.End, Valid: true},
		Quality:   int32(i.Quality),
		Username:  username,
	})
	i.Id = int64(id)
	return i, err
}
