package database

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5"
)

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
	GetUser(username string) (*User, error)
	GetIntervals(username string, start, end time.Time) ([]Interval, error)
	AddUser(u User) error
	AddInterval(username string, i Interval) (Interval, error)
}

var schema = `
CREATE TABLE IF NOT EXISTS Users (
    Name TEXT PRIMARY KEY NOT NULL,
    PassHash BYTEA NOT NULL
);

CREATE TABLE IF NOT EXISTS Intervals (
    Id SERIAL PRIMARY KEY,
    IntrStart TIMESTAMP WITH TIME ZONE NOT NULL,
    IntrEnd TIMESTAMP WITH TIME ZONE NOT NULL,
    Quality INTEGER NOT NULL,
    Username TEXT,
    FOREIGN KEY (Username) REFERENCES Users(Name)
);
`

type SqlDatabase struct{ conn *pgx.Conn }

func (d *SqlDatabase) Open(source string) error {
	conn, err := pgx.Connect(context.Background(), source)
	if err != nil {
		return err
	}
	d.conn = conn
	_, err = d.conn.Exec(context.Background(), schema)
	return err
}

func (d *SqlDatabase) Close() error {
	return d.conn.Close(context.Background())
}

func (d *SqlDatabase) Wipe() error {
	_, err := d.conn.Exec(
		context.Background(),
		"DROP TABLE IF EXISTS Intervals; DROP TABLE IF EXISTS Users",
	)
	return err
}

func (d *SqlDatabase) UserExists(username string) (bool, error) {
	var name string
	err := d.conn.QueryRow(
		context.Background(),
		"SELECT Name FROM Users WHERE Name = $1",
		username,
	).Scan(&name)
	if err == pgx.ErrNoRows {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return true, nil
}

func (d *SqlDatabase) GetUser(username string) (*User, error) {
	var name string
	var hash []byte
	err := d.conn.QueryRow(
		context.Background(),
		"SELECT Name, PassHash FROM Users WHERE Name = $1",
		username,
	).Scan(&name, &hash)
	if err != nil {
		return nil, err
	}
	return &User{Name: name, PassHash: hash}, nil
}

func (d *SqlDatabase) GetIntervals(username string, start, end time.Time) ([]Interval, error) {
	rows, err := d.conn.Query(
		context.Background(),
		`SELECT Id, IntrStart AT TIME ZONE 'UTC', IntrEnd AT TIME ZONE 'UTC', Quality FROM Intervals
		WHERE Username = $1 AND (IntrStart <= $2 AND IntrEnd >= $3)
		ORDER BY IntrStart`,
		username, end, start,
	)
	if err != nil {
		return nil, err
	}

	result := make([]Interval, 0)
	for rows.Next() {
		var i Interval
		err := rows.Scan(&i.Id, &i.Start, &i.End, &i.Quality)
		if err != nil {
			return nil, err
		}
		result = append(result, i)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return result, nil
}

func (d *SqlDatabase) AddUser(u User) error {
	_, err := d.conn.Exec(
		context.Background(),
		"INSERT INTO Users VALUES ($1,$2)",
		u.Name, u.PassHash,
	)
	if err != nil {
		return err
	}
	return nil
}

func (d *SqlDatabase) AddInterval(username string, i Interval) (Interval, error) {
	var id int64
	err := d.conn.QueryRow(
		context.Background(),
		`INSERT INTO Intervals (IntrStart, IntrEnd, Quality, Username)
		VALUES ($1,$2,$3,$4) RETURNING Id`,
		i.Start, i.End, i.Quality, username,
	).Scan(&id)
	if err != nil {
		return Interval{}, err
	}
	i.Id = id
	return i, err
}
