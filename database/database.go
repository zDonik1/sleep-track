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

type NoSsTime struct {
	time.Time
}

func (t *NoSsTime) UnmarshalJSON(b []byte) error {
	var tm time.Time
	err := json.Unmarshal(b, &tm)
	if err != nil {
		return err
	}
	if tm.Nanosecond() != 0 {
		return errors.New("subsecond values are not allowed")
	}

	t.Time = tm
	return nil
}

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

type jsonIntervalNoId struct {
	Start   *NoSsTime `json:"start"`
	End     *NoSsTime `json:"end"`
	Quality *int      `json:"quality"`
}

type jsonInterval struct {
	Id *int64 `json:"id"`
	jsonIntervalNoId
}

func (i Interval) MarshalJSON() ([]byte, error) {
	interval := jsonInterval{
		Id: &i.Id,
		jsonIntervalNoId: jsonIntervalNoId{
			Start:   &NoSsTime{Time: i.Start},
			End:     &NoSsTime{Time: i.End},
			Quality: &i.Quality,
		},
	}
	json, err := json.Marshal(interval)
	if err != nil {
		return nil, err
	}
	return json, nil
}

func (i *Interval) UnmarshalJSON(b []byte) error {
	var intr jsonIntervalNoId
	err := json.Unmarshal(b, &intr)
	if err != nil {
		return err
	}

	if intr.Start == nil {
		return errors.New("missing \"start\" field")
	}
	if intr.End == nil {
		return errors.New("missing \"end\" field")
	}
	if intr.Quality == nil {
		return errors.New("missing \"quality\" field")
	}

	i.Start = intr.Start.Time
	i.End = intr.End.Time
	i.Quality = *intr.Quality
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

func (d *Database) AddInterval(username string, i Interval) (Interval, error) {
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
