package repository

import (
	"context"

	"github.com/zDonik1/sleep-track/repository/psqldb"
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
