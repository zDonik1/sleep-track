package repository

import (
	"context"

	"github.com/zDonik1/sleep-track/repository/psqldb"
	"github.com/zDonik1/sleep-track/repository/sqlitedb"
)

type User struct {
	Name     string
	PassHash []byte
}

type UserRepository interface {
	Exists(username string) (bool, error)
	Get(username string) (User, error)
	Create(u User) error
}

func NewPsqlUserRepo(db psqldb.DBTX) UserRepository {
	return (*psqlUserRepository)(psqldb.New(db))
}

func NewSqliteUserRepo(db sqlitedb.DBTX) UserRepository {
	return (*sqliteUserRepository)(sqlitedb.New(db))
}

type psqlUserRepository psqldb.Queries

func (q *psqlUserRepository) Exists(username string) (bool, error) {
	return (*psqldb.Queries)(q).UserExists(context.Background(), username)
}

func (q *psqlUserRepository) Get(username string) (User, error) {
	user, err := (*psqldb.Queries)(q).GetUser(context.Background(), username)
	return User{Name: user.Name, PassHash: user.Passhash}, err
}

func (q *psqlUserRepository) Create(u User) error {
	return (*psqldb.Queries)(q).CreateUser(context.Background(), psqldb.CreateUserParams{
		Name:     u.Name,
		Passhash: u.PassHash,
	})
}

type sqliteUserRepository sqlitedb.Queries

func (q *sqliteUserRepository) Exists(username string) (bool, error) {
	exists, err := (*sqlitedb.Queries)(q).UserExists(context.Background(), username)
	return exists != 0, err
}

func (q *sqliteUserRepository) Get(username string) (User, error) {
	user, err := (*sqlitedb.Queries)(q).GetUser(context.Background(), username)
	return User{Name: user.Name, PassHash: user.Passhash}, err
}

func (q *sqliteUserRepository) Create(u User) error {
	return (*sqlitedb.Queries)(q).CreateUser(context.Background(), sqlitedb.CreateUserParams{
		Name:     u.Name,
		Passhash: u.PassHash,
	})
}
