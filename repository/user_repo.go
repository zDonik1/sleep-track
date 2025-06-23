package repository

import (
	"context"

	"github.com/zDonik1/sleep-track/repository/sleepdb"
)

type User struct {
	Name     string
	PassHash []byte
}

type UserRepository interface {
	Exists(username string) (bool, error)
	Get(username string) (User, error)
	Add(u User) error
}

func NewPsqlUserRepo(db sleepdb.DBTX) UserRepository {
	return (*psqlUserRepository)(sleepdb.New(db))
}

type psqlUserRepository sleepdb.Queries

func (q *psqlUserRepository) Exists(username string) (bool, error) {
	return (*sleepdb.Queries)(q).UserExists(context.Background(), username)
}

func (q *psqlUserRepository) Get(username string) (User, error) {
	user, err := (*sleepdb.Queries)(q).GetUser(context.Background(), username)
	return User{Name: user.Name, PassHash: user.Passhash}, err
}

func (q *psqlUserRepository) Add(u User) error {
	return (*sleepdb.Queries)(q).AddUser(context.Background(), sleepdb.AddUserParams{
		Name:     u.Name,
		Passhash: u.PassHash,
	})
}
