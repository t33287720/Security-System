#!/bin/bash
set -e

echo "[entrypoint] Waiting for MySQL at ${MYSQL_HOST}:${MYSQL_PORT:-3306}..."
until (echo > /dev/tcp/${MYSQL_HOST}/${MYSQL_PORT:-3306}) 2>/dev/null; do
    sleep 2
done
echo "[entrypoint] MySQL is ready."

exec /usr/bin/supervisord -c /etc/supervisor/supervisord.conf
