set shell := ["bash", "-c"]

help:
    @just --list --unsorted --justfile {{ justfile() }}


# ---- NIX DEVELOP COMMANDS ---- #

# enter development shell
[group("nix develop")]
dev:
    nix develop -c nu
