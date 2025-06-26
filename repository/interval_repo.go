package repository

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5/pgtype"

	"github.com/zDonik1/sleep-track/repository/psqldb"
	"github.com/zDonik1/sleep-track/repository/sqlitedb"
)

type Interval struct {
	Id      int64
	Start   time.Time
	End     time.Time
	Quality int
}

type IntervalRepository interface {
	Get(username string, start, end time.Time) ([]Interval, error)
	Create(username string, i Interval) (Interval, error)
}

func NewPsqlIntervalRepo(db psqldb.DBTX) IntervalRepository {
	return (*psqlIntervalRepository)(psqldb.New(db))
}

func NewSqliteIntervalRepo(db sqlitedb.DBTX) IntervalRepository {
	return (*sqliteIntervalRepository)(sqlitedb.New(db))
}

type psqlIntervalRepository psqldb.Queries

func (q *psqlIntervalRepository) Get(username string, start, end time.Time) ([]Interval, error) {
	rows, err := (*psqldb.Queries)(q).GetIntervals(
		context.Background(),
		psqldb.GetIntervalsParams{
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

func (q *psqlIntervalRepository) Create(username string, i Interval) (Interval, error) {
	id, err := (*psqldb.Queries)(q).CreateInterval(
		context.Background(),
		psqldb.CreateIntervalParams{
			Intrstart: pgtype.Timestamptz{Time: i.Start, Valid: true},
			Intrend:   pgtype.Timestamptz{Time: i.End, Valid: true},
			Quality:   int32(i.Quality),
			Username:  username,
		},
	)
	i.Id = int64(id)
	return i, err
}

type sqliteIntervalRepository sqlitedb.Queries

func (q *sqliteIntervalRepository) Get(username string, start, end time.Time) ([]Interval, error) {
	rows, err := (*sqlitedb.Queries)(q).GetIntervals(
		context.Background(),
		sqlitedb.GetIntervalsParams{
			Username:  username,
			Intrstart: end.Format(time.RFC3339),
			Intrend:   start.Format(time.RFC3339),
		},
	)
	if err != nil {
		return nil, err
	}

	result := make([]Interval, 0)
	for _, v := range rows {
		start, err := time.Parse(time.RFC3339, v.Intrstart)
		if err != nil {
			return nil, err
		}
		end, err := time.Parse(time.RFC3339, v.Intrend)
		if err != nil {
			return nil, err
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

func (q *sqliteIntervalRepository) Create(username string, i Interval) (Interval, error) {
	id, err := (*sqlitedb.Queries)(q).CreateInterval(
		context.Background(),
		sqlitedb.CreateIntervalParams{
			Intrstart: i.Start.Format(time.RFC3339),
			Intrend:   i.End.Format(time.RFC3339),
			Quality:   int64(i.Quality),
			Username:  username,
		},
	)
	i.Id = id
	return i, err
}
