from __future__ import annotations

import os
from contextlib import contextmanager

import psycopg2
from psycopg2.extras import RealDictCursor, execute_values


def get_connection():
    """
    Crea y devuelve una conexión a PostgreSQL usando variables de entorno.
    """
    return psycopg2.connect(
        host=os.getenv("DB_HOST", "127.0.0.1"),
        port=int(os.getenv("DB_PORT", "5432")),
        dbname=os.getenv("DB_NAME", "soc_db"),
        user=os.getenv("DB_USER", "soc_user"),
        password=os.getenv("DB_PASSWORD", ""),
        cursor_factory=RealDictCursor,
        connect_timeout=10,
        application_name=os.getenv("DB_APP_NAME", "soc-platform"),
    )


@contextmanager
def db_connection():
    """
    Context manager para abrir/cerrar conexión automáticamente.
    Hace rollback si ocurre error.
    """
    conn = get_connection()
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


@contextmanager
def db_cursor():
    """
    Context manager para abrir conexión + cursor automáticamente.
    Hace commit si todo sale bien, rollback si falla.
    """
    with db_connection() as conn:
        cur = conn.cursor()
        try:
            yield cur
        finally:
            cur.close()


@contextmanager
def get_conn():
    """
    Alias compatible con loaders que esperan `with get_conn() as conn:`
    """
    with db_connection() as conn:
        yield conn


def bulk_upsert(conn, sql: str, values: list[tuple], page_size: int = 500):
    """
    Ejecuta INSERT/UPSERT masivo usando execute_values de psycopg2.
    """
    if not values:
        return 0

    with conn.cursor() as cur:
        execute_values(cur, sql, values, page_size=page_size)

    return len(values)


def test_connection() -> bool:
    """
    Prueba rápida de conexión a la base de datos.
    """
    try:
        with db_cursor() as cur:
            cur.execute("SELECT 1 AS ok;")
            row = cur.fetchone()
            return bool(row and row["ok"] == 1)
    except Exception:
        return False