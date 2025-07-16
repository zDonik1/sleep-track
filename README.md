# sleep-track

A showcase of a simple RESTful API server written in Go for storing and tracking sleep.

## Tech stack

- **Echo:** router
- **PostgreSQL:** backend database
- **JWT:** bearer token authentication
- **sqlc:** code-gen from SQL
- **Swagger:** documentation

## Docker
The docker compose deployment is only meant for development and not production. It does not have persistence of the database by default.

Simply run
```sh
docker compose up -d
```

The API is served to `localhost:8080` at root `/` and the Swagger documentation is served at `/docs`.

## Deployment

A docker image is provided in [packages](https://github.com/zDonik1/sleep-track/pkgs/container/sleep-track) that can be used to deploy the server on a Kubernetes cluster.

The dependency services required by the sleep tracker server:
- PostgreSQL

Optionally:
- Swagger

## Development

Running all tests (requires that PostgreSQL is set up):

```sh
just test
```

Running tests without PostgreSQL:

```sh
just devtest
```
