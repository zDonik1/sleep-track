#!/usr/bin/env bash

set -e

go list ./... | grep -v -E "(psqldb|sqlitedb)" | INTEGRATION=1 xargs courtney -e || {
    exit_code=$?
    go tool cover -html=coverage.out
    exit $exit_code
}
