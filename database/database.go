package database

import (
	"database/sql"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	_ "github.com/mattn/go-sqlite3"
)

type User struct {
	Name     string
	PassHash []byte
}

type Interval struct {
	Id      int
	Start   time.Time
	End     time.Time
	Quality int
}

func (i *Interval) UnmarshalJSON(b []byte) error {
	var interval struct {
		Start   *time.Time `json:"start"`
		End     *time.Time `json:"end"`
		Quality *int       `json:"quality"`
	}
	err := json.Unmarshal(b, &interval)
	if err != nil {
		return err
	}

	if interval.Start == nil {
		return errors.New("missing \"start\" field")
	}
	if interval.End == nil {
		return errors.New("missing \"end\" field")
	}
	if interval.Quality == nil {
		return errors.New("missing \"quality\" field")
	}

	i.Start = *interval.Start
	i.End = *interval.End
	i.Quality = *interval.Quality
	return nil
}

type Database struct {
	db *sql.DB
}

type Driver string

const (
	DriverSqlite Driver = "sqlite3"
)

//go:embed sqlite_schema.sql
var createSchema string

func (d *Database) Open(driver Driver, source string) error {
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

func (d *Database) Close() {
	d.db.Close()
}

func (d *Database) UserExists(username string) (bool, error) {
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

func (d *Database) GetUser(username string) (*User, error) {
	statement := fmt.Sprintf(`SELECT Name, PassHash FROM Users WHERE Name = '%s'`, username)
	var name string
	var hash []byte
	err := d.db.QueryRow(statement).Scan(&name, &hash)

	if err != nil {
		return nil, err
	}
	return &User{Name: name, PassHash: hash}, nil
}

func (d *Database) AddUser(u User) error {
	_, err := d.db.Exec("INSERT INTO Users VALUES (?,?)", u.Name, u.PassHash)
	if err != nil {
		return err
	}
	return nil
}
