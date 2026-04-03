#!/usr/bin/env bash
# =============================================================================
# scripts/start_db.sh
#
# Gestión rápida de la base de datos PostgreSQL en Docker.
# Uso:
#   ./scripts/start_db.sh            # Levanta la DB (default)
#   ./scripts/start_db.sh up         # Levanta la DB
#   ./scripts/start_db.sh down       # Para la DB (datos se conservan)
#   ./scripts/start_db.sh restart    # Reinicia la DB
#   ./scripts/start_db.sh reset      # ⚠️  BORRA todo y recrea desde cero
#   ./scripts/start_db.sh logs       # Ver logs de PostgreSQL
#   ./scripts/start_db.sh status     # Estado del contenedor
#   ./scripts/start_db.sh psql       # Abrir consola psql
# =============================================================================

set -euo pipefail

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$PROJECT_ROOT"

# Cargar .env si existe
if [[ -f ".env" ]]; then
    set -a
    # shellcheck disable=SC1091
    source .env
    set +a
fi

ACTION="${1:-up}"

# Puerto para conectarse desde el host (el que expone Docker)
DB_PORT_HOST="${DB_PORT_HOST:-5433}"
DB_HOST_LOCAL="127.0.0.1"

echo "=== SOC Platform — DB Manager ==="

case "$ACTION" in

  up)
    echo "[INFO] Levantando PostgreSQL + pgAdmin..."
    docker compose up -d postgres pgadmin

    echo "[INFO] Esperando que PostgreSQL esté listo..."
    for i in $(seq 1 30); do
        if docker compose exec postgres pg_isready -U "${DB_USER:-soc_user}" -d "${DB_NAME:-soc_db}" >/dev/null 2>&1; then
            echo "[OK] PostgreSQL listo"
            break
        fi
        echo "  ... intento $i/30"
        sleep 2
    done

    echo ""
    echo "  PostgreSQL: 127.0.0.1:${DB_PORT_HOST}"
    echo "  pgAdmin:    http://localhost:8080"
    echo ""
    echo "  Conectar desde la app:"
    echo "    DB_HOST=127.0.0.1"
    echo "    DB_PORT=${DB_PORT_HOST}"
    echo ""
    echo "  Conectar con psql:"
    echo "    PGPASSWORD=\$DB_PASSWORD psql -h 127.0.0.1 -p ${DB_PORT_HOST} -U \$DB_USER -d \$DB_NAME"
    ;;

  down)
    echo "[INFO] Deteniendo contenedores (los datos se conservan)..."
    docker compose stop postgres pgadmin
    echo "[OK] Contenedores detenidos"
    ;;

  restart)
    echo "[INFO] Reiniciando..."
    docker compose restart postgres pgadmin
    echo "[OK] Reiniciado"
    ;;

  reset)
    echo ""
    echo "⚠️  ADVERTENCIA: Esto borrará TODOS los datos de la DB."
    read -r -p "¿Continuar? (escribe 'si' para confirmar): " CONFIRM
    if [[ "$CONFIRM" != "si" ]]; then
        echo "[CANCELADO]"
        exit 0
    fi
    echo "[INFO] Borrando contenedores y volúmenes..."
    docker compose down -v postgres pgadmin
    echo "[INFO] Recreando desde cero..."
    docker compose up -d postgres pgadmin
    echo "[OK] DB recreada. Las migrations SQL se ejecutaron automáticamente."
    ;;

  logs)
    docker compose logs -f postgres
    ;;

  status)
    docker compose ps postgres pgadmin
    ;;

  psql)
    echo "[INFO] Abriendo consola psql..."
    docker compose exec postgres psql -U "${DB_USER:-soc_user}" -d "${DB_NAME:-soc_db}"
    ;;

  *)
    echo "Uso: $0 {up|down|restart|reset|logs|status|psql}"
    exit 1
    ;;

esac
