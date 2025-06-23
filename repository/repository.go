//go:generate sqlc generate

package repository

import (
	_ "embed"
)

//go:embed schema.sql
var Schema string

//
// type Database interface {
// 	Open(source string) error
// 	Close() error
// 	Wipe() error
// }
//
// func NewPsqlDatabase() Database {
// 	return &psqlDatabase{}
// }
//
// type psqlDatabase struct {
// 	conn    *pgx.Conn
// 	queries *sleepdb.Queries
// }
//
// func (d *psqlDatabase) Open(source string) error {
// 	conn, err := pgx.Connect(context.Background(), source)
// 	if err != nil {
// 		return err
// 	}
// 	d.conn = conn
// 	_, err = d.conn.Exec(context.Background(), schema)
// 	d.queries = sleepdb.New(conn)
// 	return err
// }
//
// func (d *psqlDatabase) Close() error {
// 	return d.conn.Close(context.Background())
// }
//
// func (d *psqlDatabase) Wipe() error {
// 	return d.queries.Wipe(context.Background())
// }
