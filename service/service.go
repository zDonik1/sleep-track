package service

import (
	"errors"
	"fmt"
	"github.com/zDonik1/sleep-track/utils"
	"time"

	"github.com/go-playground/validator/v10"
	db "github.com/zDonik1/sleep-track/database"
	"golang.org/x/crypto/bcrypt"
)

const COST = 8

var (
	validate *validator.Validate = validator.New(validator.WithRequiredStructEnabled())

	validationMessages map[string]string = map[string]string{
		"End gtfield": "interval end is the same or before start",
		"Quality gte": "quality out of 1-5 range",
		"Quality lte": "quality out of 1-5 range",
	}
)

type UnauthorizedError string

func (e UnauthorizedError) Error() string {
	return string(e)
}

type ValidationError string

func (e ValidationError) Error() string {
	return string(e)
}

type Interval struct {
	Start time.Time
	End   time.Time `validate:"gtfield=Start"`
}

type SleepInterval struct {
	Interval
	Id      int64
	Quality int `validate:"gte=1,lte=5"`
}

type Service struct {
	db db.Database
}

func New(db db.Database) Service {
	return Service{db: db}
}

func (s *Service) UserExists(username string) (bool, error) {
	return s.db.UserExists(username)
}

func (s *Service) AuthenticateUser(username, pass string) (bool, error) {
	if username == "" {
		return false, UnauthorizedError("invalid username: the username is empty")
	}
	if pass == "" {
		return false, UnauthorizedError("invalid password: the password is empty")
	}

	exists, err := s.UserExists(username)
	if err != nil {
		return false, err
	}

	if !exists {
		hash, err := bcrypt.GenerateFromPassword([]byte(pass), COST)
		if err != nil {
			return false, err
		}
		err = s.db.AddUser(db.User{Name: username, PassHash: hash})
		if err != nil {
			return false, err
		}
	} else {
		user, err := s.db.GetUser(username)
		if err != nil {
			return false, err
		}

		if err := bcrypt.CompareHashAndPassword(user.PassHash, []byte(pass)); err != nil {
			return false, UnauthorizedError(err.Error())
		}
	}
	return !exists, nil
}

func (s *Service) CreateInterval(username string, interval SleepInterval) (SleepInterval, error) {
	if err := validate.Struct(interval); err != nil {
		return SleepInterval{}, ValidationError(
			transformValidationError(err, getValidationErrorMessage).Error(),
		)
	}

	dbInterval, err := s.db.AddInterval(username, toDbInterval(interval))
	if err != nil {
		return SleepInterval{}, err
	}
	return fromDbInterval(dbInterval), nil
}

func (s *Service) GetIntervals(username string, i Interval) ([]SleepInterval, error) {
	if err := validate.Struct(i); err != nil {
		return nil, ValidationError(
			transformValidationError(err, getValidationErrorMessage).Error(),
		)
	}
	intervals, err := s.db.GetIntervals(username, i.Start, i.End)
	if err != nil {
		return nil, err
	}
	return utils.Map(intervals, fromDbInterval), nil
}

func transformValidationError(err error, transform func(field, tag string) error) error {
	var validationErrs validator.ValidationErrors
	if errors.As(err, &validationErrs) {
		for _, verr := range validationErrs {
			if err = transform(verr.Field(), verr.Tag()); err != nil {
				break
			}
		}
	}
	return err
}

func getValidationErrorMessage(field, tag string) error {
	var err error
	if msg, ok := validationMessages[fmt.Sprintf("%s %s", field, tag)]; ok {
		err = errors.New(msg)
	}
	return err
}

func fromDbInterval(i db.Interval) SleepInterval {
	return SleepInterval{
		Interval: Interval{Start: i.Start, End: i.End},
		Id:       i.Id,
		Quality:  i.Quality,
	}
}

func toDbInterval(i SleepInterval) db.Interval {
	return db.Interval{
		Id:      i.Id,
		Start:   i.Start,
		End:     i.End,
		Quality: i.Quality,
	}
}
