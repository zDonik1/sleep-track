package database

import (
	"database/sql"
	_ "embed"
	"fmt"
	"time"

	_ "github.com/mattn/go-sqlite3"
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
	Open(driver Driver, source string) error
	Close()
	UserExists(username string) (bool, error)
	GetUser(username string) (*User, error)
	GetIntervals(username string, start, end time.Time) ([]Interval, error)
	AddUser(u User) error
	AddInterval(username string, i Interval) (Interval, error)
}

type SqlDatabase struct {
	db *sql.DB
}

type Driver string

const (
	DriverSqlite Driver = "sqlite3"
)

//go:embed sqlite_schema.sql
var createSchema string

func (d *SqlDatabase) Open(driver Driver, source string) error {
	db, err := sql.Open("sqlite3", source)
	if err != nil {
		return err
	}
	d.db = db

	_, err = db.Exec(string(createSchema))
	if err != nil {
		return err
	}
	return nil
}

func (d *SqlDatabase) Close() {
	d.db.Close()
}

func (d *SqlDatabase) UserExists(username string) (bool, error) {
	var name string
	statement := fmt.Sprintf(`SELECT Name FROM Users WHERE Name = '%s'`, username)
	err := d.db.QueryRow(statement).Scan(&name)

	if err == sql.ErrNoRows {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return true, nil
}

func (d *SqlDatabase) GetUser(username string) (*User, error) {
	statement := fmt.Sprintf(`SELECT Name, PassHash FROM Users WHERE Name = '%s'`, username)
	var name string
	var hash []byte
	err := d.db.QueryRow(statement).Scan(&name, &hash)

	if err != nil {
		return nil, err
	}
	return &User{Name: name, PassHash: hash}, nil
}

func (d *SqlDatabase) GetIntervals(username string, start, end time.Time) ([]Interval, error) {
	rows, err := d.db.Query(
		`SELECT Id, Start, End, Quality FROM Intervals `+
			`WHERE Username = ? AND (Start <= ? AND End >= ?)`+
			`ORDER BY Start`,
		username,
		end,
		start,
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
	if rows.Err() != nil {
		return nil, err
	}
	return result, nil
}

func (d *SqlDatabase) AddUser(u User) error {
	_, err := d.db.Exec("INSERT INTO Users VALUES (?,?)", u.Name, u.PassHash)
	if err != nil {
		return err
	}
	return nil
}

func (d *SqlDatabase) AddInterval(username string, i Interval) (Interval, error) {
	r, err := d.db.Exec(
		"INSERT INTO Intervals (Start, End, Quality, Username) VALUES (?,?,?,?)",
		i.Start,
		i.End,
		i.Quality,
		username,
	)
	if err != nil {
		return Interval{}, err
	}

	id, err := r.LastInsertId()
	if err != nil {
		return Interval{}, err
	}

	i.Id = id
	return i, err
}
