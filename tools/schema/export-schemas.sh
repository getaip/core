#!/usr/bin/env sh
set -eu

cargo run -p getaip-cli -- schema export schemas/aip
