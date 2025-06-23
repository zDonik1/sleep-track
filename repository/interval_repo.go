package repository

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5/pgtype"
	"github.com/zDonik1/sleep-track/repository/sleepdb"
)

type Interval struct {
	Id      int64
	Start   time.Time
	End     time.Time
	Quality int
}

type IntervalRepository interface {
	Get(username string, start, end time.Time) ([]Interval, error)
	Add(username string, i Interval) (Interval, error)
}

func NewPsqlIntervalRepo(db sleepdb.DBTX) IntervalRepository {
	return (*psqlIntervalRepository)(sleepdb.New(db))
}

type psqlIntervalRepository sleepdb.Queries

func (q *psqlIntervalRepository) Get(username string, start, end time.Time) ([]Interval, error) {
	rows, err := (*sleepdb.Queries)(q).GetIntervals(
		context.Background(),
		sleepdb.GetIntervalsParams{
			Username:  username,
			Intrstart: pgtype.Timestamptz{Time: end, Valid: true},
			Intrend:   pgtype.Timestamptz{Time: start, Valid: true},
		},
	)
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

func (q *psqlIntervalRepository) Add(username string, i Interval) (Interval, error) {
	id, err := (*sleepdb.Queries)(q).AddInterval(context.Background(), sleepdb.AddIntervalParams{
		Intrstart: pgtype.Timestamptz{Time: i.Start, Valid: true},
		Intrend:   pgtype.Timestamptz{Time: i.End, Valid: true},
		Quality:   int32(i.Quality),
		Username:  username,
	})
	i.Id = int64(id)
	return i, err
}
