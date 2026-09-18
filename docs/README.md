# Documentación de SOC Platform 1

| Documento | Contenido |
|---|---|
| [arquitectura.md](arquitectura.md) | Visión general, patrón ETL, registry, scheduler, jobs y tablas de control |
| [modulos.md](modulos.md) | Qué recolecta cada módulo, cómo se configura y cómo se ejecuta |
| [variables-entorno.md](variables-entorno.md) | Todas las variables del `.env`, con valor por defecto |
| [base-de-datos.md](base-de-datos.md) | Tablas por dominio, migraciones y política de retención |
| [alertas.md](alertas.md) | Reglas, deduplicación, plantillas de correo y Slack |
| [dashboard-api.md](dashboard-api.md) | Servidor del dashboard, autenticación y endpoints REST |
| [operacion.md](operacion.md) | Instalación, systemd, tareas de mantenimiento y diagnóstico |
| [problemas-conocidos.md](problemas-conocidos.md) | Inconsistencias, deuda técnica y riesgos detectados |

Convenciones del código: comentarios y docstrings en español, logger
`"soc-platform"`, `from __future__ import annotations` y cursor
`RealDictCursor` (las filas son diccionarios).

> Estos documentos describen el estado del código a septiembre de 2026.
> Si cambias un módulo, una variable o una migración, actualiza el documento
> correspondiente en el mismo commit.
