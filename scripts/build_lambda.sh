#!/usr/bin/env bash
# Builds the Lambda deployment dir without Docker: dependencies for linux/arm64 + our source.
set -euo pipefail
cd "$(dirname "$0")/.."
rm -rf build/lambda && mkdir -p build/lambda
pip install -q --target build/lambda --platform manylinux2014_aarch64 --only-binary=:all: \
    --python-version 3.13 --implementation cp pyyaml
cp -r src/archguard build/lambda/archguard
cp api_handlers/*.py build/lambda/
find build/lambda -name "__pycache__" -type d -prune -exec rm -rf {} +
echo "built build/lambda ($(du -sh build/lambda | cut -f1))"
