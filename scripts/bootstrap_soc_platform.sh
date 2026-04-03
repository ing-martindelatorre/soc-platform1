#!/usr/bin/env bash
set -euo pipefail

echo "=== Bootstrap SOC Platform ==="

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$PROJECT_ROOT"

echo "[INFO] Proyecto en: $PROJECT_ROOT"

# -----------------------------
# 1) Paquetes base del sistema
# -----------------------------
if command -v apt >/dev/null 2>&1; then
  echo "[INFO] Instalando dependencias base con apt..."
  sudo apt update
  sudo apt install -y \
    python3 \
    python3-venv \
    python3-pip \
    git \
    curl \
    jq \
    ca-certificates \
    gnupg
else
  echo "[WARN] apt no disponible. Instala manualmente: python3, pip, git, curl, jq"
fi

# -----------------------------
# 2) Node.js + npm (Linux)
# -----------------------------
if ! command -v node >/dev/null 2>&1; then
  echo "[INFO] Node.js no encontrado. Instalando nodejs y npm..."
  if command -v apt >/dev/null 2>&1; then
    sudo apt install -y nodejs npm
  else
    echo "[ERROR] No se pudo instalar Node.js automáticamente en este sistema."
    exit 1
  fi
else
  echo "[OK] Node.js ya instalado: $(node -v)"
fi

echo "[INFO] npm version: $(npm -v)"

# -----------------------------
# 3) Snyk CLI en Linux
# -----------------------------
WINDOWS_SNYK_PATH="/mnt/c/Users/ingma/AppData/Roaming/npm/snyk"
if command -v snyk >/dev/null 2>&1; then
  CURRENT_SNYK="$(command -v snyk || true)"
  echo "[INFO] snyk actual: $CURRENT_SNYK"
  if [[ "$CURRENT_SNYK" == /mnt/c/* ]]; then
    echo "[WARN] Se detectó snyk de Windows en WSL. Se instalará uno nativo de Linux."
  fi
else
  echo "[INFO] snyk no encontrado en PATH. Instalando..."
fi

if npm install -g snyk; then
  echo "[OK] snyk instalado globalmente con npm"
else
  echo "[WARN] Falló instalación global de snyk con npm. Reintentando con sudo..."
  sudo npm install -g snyk
fi

hash -r

if ! command -v snyk >/dev/null 2>&1; then
  echo "[ERROR] snyk no quedó disponible después de la instalación."
  exit 1
fi

echo "[OK] snyk instalado en: $(which snyk)"
echo "[OK] snyk version: $(snyk --version)"

# -----------------------------
# 4) GitHub CLI (gh)
# -----------------------------
if ! command -v gh >/dev/null 2>&1; then
  echo "[INFO] GitHub CLI no encontrado. Intentando instalar..."
  if command -v apt >/dev/null 2>&1; then
    sudo apt install -y gh || true
  fi
fi

if command -v gh >/dev/null 2>&1; then
  echo "[OK] gh disponible: $(gh --version | head -n 1)"
else
  echo "[WARN] gh no está instalado. El sync con GitHub fallará hasta instalarlo."
fi

# -----------------------------
# 5) Virtualenv Python
# -----------------------------
if [[ ! -d "$PROJECT_ROOT/venv" ]]; then
  echo "[INFO] Creando virtualenv..."
  python3 -m venv "$PROJECT_ROOT/venv"
else
  echo "[OK] venv ya existe"
fi

# shellcheck disable=SC1091
source "$PROJECT_ROOT/venv/bin/activate"

echo "[INFO] Actualizando pip..."
python -m pip install --upgrade pip setuptools wheel

if [[ -f "$PROJECT_ROOT/requirements.txt" ]]; then
  echo "[INFO] Instalando requirements.txt..."
  pip install -r "$PROJECT_ROOT/requirements.txt"
fi

echo "[INFO] Instalando dependencias adicionales necesarias..."
pip install "psycopg[binary]" python-dotenv

# -----------------------------
# 6) Estructura de datos
# -----------------------------
mkdir -p "$PROJECT_ROOT/data/repos"
mkdir -p "$PROJECT_ROOT/data/raw/snyk"
mkdir -p "$PROJECT_ROOT/data/logs/snyk"

echo "[OK] Directorios de datos creados"

# -----------------------------
# 7) Validaciones rápidas
# -----------------------------
echo "=== Validaciones ==="
echo "[PYTHON] $(python --version)"
echo "[PIP] $(pip --version)"
echo "[NODE] $(node -v)"
echo "[NPM] $(npm -v)"
echo "[SNYK] $(snyk --version)"
if command -v gh >/dev/null 2>&1; then
  echo "[GH] $(gh --version | head -n 1)"
fi

echo ""
echo "=== Siguientes pasos ==="
echo "1. Carga variables:"
echo "   set -a; source .env; set +a"
echo ""
echo "2. Verifica autenticaciones:"
echo "   gh auth status"
echo "   snyk whoami"
echo ""
echo "3. Ejecuta pipeline:"
echo "   python3 -m app.pipeline.backfill_snyk"