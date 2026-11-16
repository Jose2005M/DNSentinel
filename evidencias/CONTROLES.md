# Trazabilidad de controles — DNSentinel 1.1

Revisión de requisitos seleccionados; no constituye evaluación completa ni certificación ASVS. Las líneas corresponden al código de este ZIP. Los requisitos se resumen en español, sin sustituir su texto oficial.

| Control | Norma / requisito | Archivo / línea | Hallazgo y evidencia |
|---|---|---|---|
| Protección CSRF | ASVS 5.0.0 · 3.5.1 | `dnsentinel/security.py:77` · `check_csrf` | Rechaza tokens ausentes o incorrectos y origen distinto. Se probó también la carga multipart. |
| Autorización por función | ASVS 5.0.0 · 8.2.1 | `dnsentinel/security.py:88` · `require_admin` | El lector recibe 403 al modificar reglas, importar listas o consultar auditoría; la decisión se toma en Python. |
| Cookie inaccesible a JavaScript | ASVS 5.0.0 · 3.3.4 | `dnsentinel/__init__.py:86` · `security_headers` | Cookie HttpOnly transmitida con Set-Cookie. En HTTPS incorpora Secure y prefijo __Host-; no se entrega el token de sesión en JSON. |
| Registro de autenticación | ASVS 5.0.0 · 16.3.1 | `dnsentinel/__init__.py:154` · `login` | Se auditan inicio de sesión correcto e incorrecto y cierre de sesión. No se guardan contraseñas ni tokens en logs. |
| Errores públicos controlados | ASVS 5.0.0 · 16.5.1 | `dnsentinel/__init__.py:120` · `unexpected_error` | La API responde con mensaje genérico e identificador. La prueba verifica que no se filtran trazas ni valores internos. |

## Prácticas complementarias

- NIST SSDF 1.1, PW.7: revisión y análisis del código mediante Bandit y revisión manual del hallazgo. Evidencias: `bandit.json`, `bandit.txt` y `INFORME_FINAL.md`.
- NIST SSDF 1.1, PW.8: pruebas de API y de ejecutables, protocolo DNS real, TLS y recuperación/migración. Evidencias: `pruebas.txt`, `pruebas.xml` y `tests/`.
- NIST SSDF 1.1, RV.1.1: consulta automatizada de avisos de dependencias mediante pip-audit. No equivale a comprobar todas las CVE de NVD ni a demostrar ausencia de fallos.
- AES-256-GCM protege campos de consultas y auditoría; no sustituye permisos, cifrado de volumen, respaldo de claves ni almacenamiento separado de auditoría. No se implementó envío a SIEM ni inmutabilidad forense.

## Fuentes oficiales consultadas

- [OWASP ASVS 5.0.0, V3](https://github.com/OWASP/ASVS/blob/v5.0.0/5.0/en/0x12-V3-Web-Frontend-Security.md).
- [OWASP ASVS 5.0.0, V8](https://github.com/OWASP/ASVS/blob/v5.0.0/5.0/en/0x17-V8-Authorization.md).
- [OWASP ASVS 5.0.0, V16](https://github.com/OWASP/ASVS/blob/v5.0.0/5.0/en/0x25-V16-Security-Logging-and-Error-Handling.md).
- [NIST SP 800-218, SSDF 1.1](https://csrc.nist.gov/pubs/sp/800/218/final).
- [dnspython, consultas asíncronas UDP/TCP](https://dnspython.readthedocs.io/en/stable/async-query.html).
- [cryptography, cifrado autenticado](https://cryptography.io/en/latest/hazmat/primitives/aead/).
- [Bandit B104](https://bandit.readthedocs.io/en/1.9.4/plugins/b104_hardcoded_bind_all_interfaces.html).

Las referencias ASVS están fijadas a la versión 5.0.0 para no mezclar numeraciones de versiones anteriores.
