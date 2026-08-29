#!/bin/sh
set -e

if [ "${AUTO_MIGRATE:-true}" = "true" ]; then
  echo "Running auth database migrations..."
  bun ./dist/db/migrate.js
fi

exec "$@"
