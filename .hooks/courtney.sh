#!/usr/bin/env bash

set -e

go list ./... | grep -v -E "sleepdb" | xargs courtney -e || {
    exit_code=$?
    go tool cover -html=coverage.out
    exit $exit_code
}
