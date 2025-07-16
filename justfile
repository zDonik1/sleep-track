set shell := ["bash", "-c"]

export PGDATABASE := "testsleep"

help:
    @just --list --unsorted --justfile {{ justfile() }}

# ---- NIX DEVELOP COMMANDS ---- #

# enter development shell
[group("nix develop")]
dev:
    nix develop -c nu

# generate source files
[group("nix develop")]
gen:
    nix develop -c go generate ./...

# run tests
[group("nix develop")]
test *ARGS:
    INTEGRATION=1 nix develop -c gotest ./server -count=1 {{ ARGS }}

# run tests in development mode
[group("nix develop")]
devtest *ARGS:
    nix develop -c gotest ./server -failfast -count=1 -v {{ ARGS }}

# start server
[group("nix develop")]
run:
    nix develop -c go run main.go

# run lint and format check
[group("nix develop")]
lint:
    nix develop -c bash -c "golangci-lint run && golangci-lint fmt -d"
