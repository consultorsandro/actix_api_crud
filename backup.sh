#!/bin/bash
# backup.sh

set -e

BACKUP_DIR="./backups"
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
BACKUP_FILE="backup_${TIMESTAMP}.sql"

echo "🔄 Iniciando backup do banco de dados..."

# Criar diretório de backup
mkdir -p $BACKUP_DIR

# Realizar backup
docker-compose exec -T postgres pg_dump -U postgres actix_crud > "${BACKUP_DIR}/${BACKUP_FILE}"

# Comprimir backup
gzip "${BACKUP_DIR}/${BACKUP_FILE}"

echo "✅ Backup criado: ${BACKUP_DIR}/${BACKUP_FILE}.gz"

# Limpar backups antigos (manter últimos 7 dias)
find $BACKUP_DIR -name "backup_*.sql.gz" -mtime +7 -delete

echo "🧹 Backups antigos removidos"
