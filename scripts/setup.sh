#!/bin/bash

set -e  # Detener si algo falla

echo "========================================="
echo "🚀 Leviathan SOC Platform - Setup Script"
echo "========================================="

# Validar OS
if [[ "$OSTYPE" != "linux-gnu"* ]]; then
    echo "❌ Este script está pensado para Linux (Kali, Ubuntu, WSL)"
    exit 1
fi

# ----------------------------------------
# 🧱 Actualizar sistema
# ----------------------------------------
echo "[+] Actualizando paquetes..."
sudo apt update -y && sudo apt upgrade -y

# ----------------------------------------
# 📦 Dependencias base
# ----------------------------------------
echo "[+] Instalando dependencias base..."
sudo apt install -y \
    python3 \
    python3-venv \
    python3-pip \
    git \
    curl \
    jq \
    net-tools \
    build-essential \
    libpq-dev

# ----------------------------------------
# 🐍 Crear entorno virtual
# ----------------------------------------
if [ ! -d "venv" ]; then
    echo "[+] Creando entorno virtual..."
    python3 -m venv venv
else
    echo "[i] Entorno virtual ya existe"
fi

echo "[+] Activando entorno virtual..."
source venv/bin/activate

# ----------------------------------------
# 📚 Instalar dependencias Python
# ----------------------------------------
echo "[+] Instalando dependencias Python..."

if [ -f "requirements.txt" ]; then
    pip install --upgrade pip
    pip install -r requirements.txt
else
    echo "[⚠] No existe requirements.txt, instalando básicos..."
    pip install psycopg2-binary python-dotenv requests
fi

# ----------------------------------------
# 🔐 Variables de entorno
# ----------------------------------------
if [ -f ".env" ]; then
    echo "[+] Cargando variables de entorno..."
    set -a
    source .env
    set +a
else
    echo "[⚠] No existe archivo .env"
    echo "👉 Crea uno basado en .env.example"
fi

# ----------------------------------------
# 🗄️ Validar conexión a DB
# ----------------------------------------
if command -v psql &> /dev/null && [ ! -z "$DB_HOST" ]; then
    echo "[+] Probando conexión a PostgreSQL..."

    PGPASSWORD=$DB_PASSWORD psql \
        -h $DB_HOST \
        -p $DB_PORT \
        -U $DB_USER \
        -d $DB_NAME \
        -c "\q" && echo "✅ DB OK" || echo "❌ Error de conexión DB"
else
    echo "[i] Saltando validación de DB"
fi

# ----------------------------------------
# 📊 Generar dashboards iniciales
# ----------------------------------------
echo "[+] Generando dashboards iniciales..."

if [ -f "dashboard/run_sentinel_dashboard.py" ]; then
    python dashboard/run_sentinel_dashboard.py || true
fi

if [ -f "dashboard/run_nmap_dashboard.py" ]; then
    python -m dashboard.run_nmap_dashboard || true
fi

# ----------------------------------------
# ✅ Final
# ----------------------------------------
echo "========================================="
echo "✅ Setup completado"
echo "========================================="
echo ""
echo "👉 Activa el entorno con:"
echo "source venv/bin/activate"
echo ""
echo "👉 Carga variables:"
echo "set -a; source .env; set +a"
echo ""
echo "👉 Ejecuta dashboards:"
echo "python dashboard/run_sentinel_dashboard.py"
echo "python -m dashboard.run_nmap_dashboard"
echo ""