set shell := ["bash", "-c"]

help:
    @just --list --unsorted --justfile {{ justfile() }}

# run tests in development mode
devtest *ARGS:
    gotest ./server -failfast -count=1 -v {{ ARGS }}

# ---- NIX DEVELOP COMMANDS ---- #

# enter development shell
[group("nix develop")]
dev:
    nix develop -c nu

# start server
[group("nix develop")]
run:
    nix develop -c go run main.go
