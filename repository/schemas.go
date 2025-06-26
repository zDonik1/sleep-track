//go:generate sqlc generate

package repository

import (
	_ "embed"
)

//go:embed psql_schema.sql
var PsqlSchema string

//go:embed sqlite_schema.sql
var SqliteSchema string
