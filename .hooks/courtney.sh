#!/usr/bin/env bash

set -e

courtney -e || {
    exit_code=$?
    go tool cover -html=coverage.out
    exit $exit_code
}
