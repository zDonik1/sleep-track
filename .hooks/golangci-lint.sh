#!/usr/bin/env bash

set -e

golangci-lint run && golangci-lint fmt -d
