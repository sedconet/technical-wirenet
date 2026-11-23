#!/bin/sh
# Nightly consistent backup of the database. Add to cron:  15 2 * * * /opt/technical-wirenet/deploy/backup.sh
set -e
DEST=/var/backups/technical-wirenet
mkdir -p "$DEST"
sqlite3 /var/lib/technical-wirenet/technical.db ".backup '$DEST/technical-$(date +%F).db'"
find "$DEST" -name 'technical-*.db' -mtime +30 -delete
