# Evidencias y avance para la Clase 3 — DNSentinel v0.2

Esta guía describe controles implementados en esta entrega. No sustituye las capturas que el equipo debe tomar después de ejecutar el proyecto en su computador. Las ubicaciones corresponden a los archivos incluidos; cambiarán si se edita el código.

## Matriz de controles

| Control | Referencia relacionada (ASVS 5.0.0) | Archivo y línea inicial | Hallazgo |
|---|---|---|---|
| Validación positiva en el servidor | v5.0.0-2.2.1 y v5.0.0-2.2.2 | `dnsentinel/validation.py`, línea 10 | Rechaza URL, rutas, direcciones IP, etiquetas mal formadas, campos desconocidos y tipos incorrectos. La API se prueba directamente sin JavaScript. |
| Protección CSRF | v5.0.0-3.5.1 | `dnsentinel/security.py`, línea 72 | Comprueba token de sesión en cabecera y Origin si está presente. Se prueba ausencia de token, token no ASCII y origen ajeno. |
| Autorización por operación | v5.0.0-8.2.1 | `dnsentinel/security.py`, línea 83 | Las operaciones de escritura y la auditoría requieren rol administrador. El rol viewer solo consulta reglas/eventos y ejecuta simulaciones. |
| Errores genéricos | v5.0.0-16.5.1 | `dnsentinel/__init__.py`, línea 110 | El usuario recibe un mensaje controlado e identificador. El registro técnico contiene solo clase de excepción e identificador, sin cuerpos ni valores de la excepción. |
| Registro de seguridad | v5.0.0-16.2.1 (relacionado, alcance local) | `dnsentinel/security.py`, línea 22 | Registra fecha UTC, actor, acción, resultado y detalle controlado. El historial de simulaciones es independiente. No se declara cumplimiento de todo V16. |
| Longitud de contraseñas | v5.0.0-6.2.1 | `dnsentinel/validation.py`, línea 52 | Se exige una frase de 15 a 128 caracteres al crear la cuenta. Se calcula Argon2id con argon2-cffi. No se declara cumplimiento integral de autenticación ASVS. |

Los requisitos se contrastaron con el CSV oficial de OWASP ASVS 5.0.0. Son referencias por control; estas pruebas no certifican conformidad completa de ASVS ni de un nivel. No copiar la numeración V5/V6/V7 de la guía de clase como si perteneciera a ASVS 5.0.

Fuente: https://raw.githubusercontent.com/OWASP/ASVS/master/5.0/docs_en/OWASP_Application_Security_Verification_Standard_5.0.0_en.csv

## Resultados obtenidos

- Pruebas de integración: 24 casos aprobados; ver `pruebas.txt` y `pruebas.xml`.
- HTTP real: comprobación con Waitress de inicio de sesión, reglas, simulación y cierre de sesión; ver `http-smoke.txt`.
- Bandit 1.9.4: 0 hallazgos y 0 errores sobre `dnsentinel/` y `run.py`; ver `bandit.txt` y `bandit.json`. Los tests y JavaScript no forman parte de ese análisis SAST.
- detect-secrets 1.5.0: 0 candidatos en el árbol entregable, excluyendo datos de ejecución, cachés, entorno virtual y la propia carpeta de evidencias; ver `secretos.json`.
- En una primera ejecución que incluía la caché, se detectó la firma estándar de `.pytest_cache/CACHEDIR.TAG`. Se revisó como falso positivo. La caché no es código del proyecto ni se incluye en la entrega; el análisis final usa exclusiones explícitas. No se borró ni rotó ninguna credencial real.
- Revisión manual del alcance: no hay contraseñas predeterminadas, tokens fijos, archivos .env, claves ni bases de datos en el ZIP. Las credenciales de prueba se generan en memoria. No se revisó el historial de un repositorio del usuario.
- Se comprobó la sintaxis de los tres archivos JavaScript con `node --check`. No se realizó un SAST de JavaScript ni una prueba visual completa de navegador en esta entrega.

## Capturas que debe tomar el equipo

1. Código de domain_name/rule_input y una petición inválida rechazada por la API (la suite prueba esto sin navegador).
2. Pantalla de inicio de sesión y código de Argon2id; no fotografiar contraseñas, hashes completos ni cookies.
3. Código de require_admin y resultado de un intento de escritura con rol viewer (403).
4. Código de check_csrf y prueba de petición sin token (403).
5. Auditoría mostrando una validación rechazada y un cambio administrativo.
6. Terminal con las 24 pruebas aprobadas.
7. Terminal/reporte de Bandit con su alcance y resultado.
8. Resultado de detect-secrets y .gitignore; no mostrar secretos si aparecieran candidatos reales.

## Qué falta y no debe declararse como implementado

- Servidor DNS UDP/TCP, reenvío con dnspython y pruebas de conectividad de clientes.
- HTTPS y validación de certificados en despliegue, cookie Secure en ese entorno y cifrado del volumen de la base y copias. Actualmente el servidor es HTTP de loopback; no debe exponerse a la LAN.
- Listas de contraseñas comprometidas, MFA, gestión gráfica de usuarios y recuperación de acceso.
- Pruebas de carga, análisis de dependencias (SCA), SAST de JavaScript y validación visual en los dispositivos del equipo.
- Capturas auténticas producidas por el equipo al ejecutar esta versión en Windows.

## Interpretación para el informe

El backend administrativo incorpora controles verificables de validación, autorización, CSRF, contraseñas y sesiones. Las pruebas automatizadas verifican decisiones de la API y persistencia. El análisis estático no encontró los patrones inseguros que Bandit conoce dentro del alcance analizado; esto no demuestra ausencia total de vulnerabilidades. Los controles de comunicaciones y cifrado en reposo permanecen pendientes y se deben registrar así en el informe.

No usar una declaración automática que afirme que todos los controles del proyecto ya están implementados.
