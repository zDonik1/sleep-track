set shell := ["bash", "-c"]

help:
    @just --list --unsorted --justfile {{ justfile() }}

# ---- NIX DEVELOP COMMANDS ---- #

# enter development shell
[group("nix develop")]
dev:
    nix develop -c nu

# run tests in development mode
[group("nix develop")]
devtest *ARGS:
    nix develop -c gotest ./server -failfast -count=1 -v {{ ARGS }}

# start server
[group("nix develop")]
run:
    nix develop -c go run main.go
