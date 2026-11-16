> Informe histórico de la versión 1.0. Para los cambios y resultados actuales consulta INFORME_LANZADOR.md.

# Informe de cierre — DNSentinel 1.0

Fecha: 10 de noviembre de 2026. Proyecto académico: bloqueo de dominios mediante DNS.

## Resultado

La versión 0.2 disponía del panel administrativo y evaluación de reglas, pero no interceptaba consultas DNS reales. Esta versión incorpora un servicio UDP/TCP que recibe preguntas de clientes autorizados, aplica la política compartida y devuelve REFUSED al bloquear. Las consultas permitidas se reenvían a un servidor upstream. La respuesta se devuelve al cliente y se registra su decisión.

Se añadieron importación de listas desde archivo, HTTPS local, cifrado de campos de consultas y auditoría, seudonimización de clientes, recuperación local de contraseñas y migración de datos de 0.2. El panel distingue tráfico real de simulaciones y muestra el estado del servicio y fallos de registro.

## Justificación de tecnologías

| Tecnología | Justificación en este proyecto |
|---|---|
| Python | Permite desarrollar el protocolo, las validaciones y la administración en un mismo proyecto con bibliotecas mantenidas y pruebas reproducibles. Se prioriza el alcance de laboratorio; no se declara rendimiento de un resolver empresarial. |
| Flask | Organiza la API, los controles por petición y comandos locales de mantenimiento. No se usa su servidor de desarrollo para la configuración final. |
| dnspython + asyncio | Procesa mensajes DNS y consultas UDP/TCP, con reintento TCP ante truncamiento UDP del upstream. Evita implementar manualmente todo el formato del protocolo. |
| SQLite | Persistencia local sin desplegar un servidor de base de datos; consultas parametrizadas y transacciones para conservar reglas y usuarios. Es apropiado para un único servidor académico. |
| Argon2id | Hash de contraseñas con sal y parámetros gestionados por argon2-cffi; no se guardan contraseñas reversibles. |
| cryptography | AES-256-GCM para confidencialidad e integridad de campos de logs, y generación de certificados X.509 locales. La clave de logs se conserva fuera del proyecto. |
| Cheroot + TLS de Python | Sirve la interfaz por HTTPS con TLS 1.2 o superior y certificado verificable de la CA local. |
| HTML, CSS y JavaScript | Mantiene la interfaz existente, sin compilación frontend ni dependencias de recursos externos. JavaScript consume la API y no decide permisos. |
| pytest, Bandit, detect-secrets y pip-audit | Combinan pruebas funcionales, SAST, búsqueda de secretos y revisión de avisos de dependencias. Sus resultados tienen alcances diferentes. |

## Verificación ejecutada

Entorno: Linux, Python 3.12.14. Las pruebas de sockets usan loopback y un upstream de prueba que devuelve direcciones reservadas de documentación. Los certificados y contraseñas de prueba son temporales y no se incluyen en el paquete.

| Comprobación | Resultado y alcance |
|---|---|
| pytest | 44 pruebas aprobadas. Informe XML y salida en esta carpeta. |
| DNS real | Se comprobaron UDP/TCP, bloqueo exacto y por subdominios, excepciones, límites de etiqueta y ausencia de reenvío de nombres bloqueados. |
| Resolución | Reenvío a upstream controlado, conservación de NXDOMAIN, cambio a TCP por respuesta UDP truncada y SERVFAIL ante upstream inaccesible. |
| Robustez DNS | Rechazo de ANY/AXFR/IXFR, consultas malformadas y múltiples preguntas; ACL de cliente y bucket de límites con memoria acotada. No se realizó una campaña de fuzzing o prueba de denegación de servicio a escala. |
| Administración | Autenticación, CSRF, rol lector, validación estricta, CRUD persistente, importación, límites, errores públicos y revocación de sesiones. |
| HTTPS | Peticiones reales con validación de la CA temporal, cookie Secure, autenticación, carga multipart y recursos estáticos. No se usó verify=False ni una conexión TLS sin verificar. |
| Cifrado y migración | Logs cifrados, identificación de cliente seudónima, rechazo de manipulación/clave incorrecta y migración de eventos de 0.2. |
| Arranque | Se ejecutaron los comandos CLI en una copia aislada, se inició run.py con HTTPS y se verificó check_dns.py en UDP/TCP. |
| JavaScript | Sintaxis validada con node --check y correspondencia de selectores con elementos HTML. No se realizó una prueba visual automatizada de navegador en esta entrega. |
| Bandit 1.9.4 | 1 hallazgo de severidad media, revisado como falso positivo. 0 hallazgos de severidad alta. No se ocultó con #nosec. |
| detect-secrets 1.5.0 | 0 candidatos en los archivos revisados. Se excluyeron datos de ejecución, entorno virtual, cachés y evidencias. No se examinó historial de Git, que no forma parte de este paquete. |
| pip-audit 2.10.1 | 0 vulnerabilidades conocidas reportadas para las 17 dependencias resueltas de ejecución en la fecha de análisis. Resultado en dependencias.json. No garantiza ausencia de vulnerabilidades futuras o no publicadas. |

## Hallazgo estático revisado

Bandit B104 marcó `dnsentinel/lists.py`, línea 20, por la cadena `0.0.0.0`. En ese lugar el código **lee una línea de un archivo hosts**, identifica una dirección de bloqueo y extrae el dominio. No crea sockets ni establece una dirección de escucha. Por ese contexto se clasificó como falso positivo, sin eliminar la cadena necesaria ni desactivar la regla. El reporte original conserva el hallazgo y su referencia CWE-605.

Los sockets se configuran en `run.py` y `dns_server.py`: loopback por defecto y redes de clientes explícitas cuando el administrador solicita uso LAN. No debe abrirse un resolver público.

## Vulnerabilidades y NIST/NVD

En esta revisión no se confirmó una CVE aplicable a las versiones de dependencias analizadas. El hallazgo B104 de Bandit **no es una CVE de NVD** y no permite afirmar que se descubrió o parchó una vulnerabilidad NIST. pip-audit consulta avisos del ecosistema de dependencias; no constituye una búsqueda exhaustiva de todo NVD.

Los controles de seguridad y mejoras añadidos tampoco prueban que la versión anterior fuese explotable. La conclusión sustentada es que se incorporaron defensas y se validaron comportamientos concretos. La trazabilidad con requisitos seleccionados de OWASP ASVS y prácticas NIST SSDF se documenta en CONTROLES.md, sin declarar certificación.

## Lo que completa esta versión

- Servicio DNS real con bloqueo por listas, excepciones y reglas de subdominios.
- Panel local con administración autenticada y cambios aplicados al servicio en ejecución.
- Importación de listas y persistencia de reglas, consultas y auditoría.
- HTTPS, controles de sesión, validación y cifrado de campos sensibles de logs.
- Pruebas reproducibles, guía de instalación, recuperación y migración.

## Verificaciones pendientes en el equipo del estudiante

1. Instalar dependencias y confiar únicamente en la CA generada para su instalación.
2. Ejecutar las pruebas en su Windows/Python y verificar que los puertos estén disponibles.
3. Probar bloqueo real con check_dns.py y guardar capturas de respuestas UDP/TCP, reglas, registro y auditoría.
4. Si se desea filtrar el navegador o una LAN, configurar DNS 53, clientes y firewall de forma autorizada, documentando también cómo restaurar la configuración original.
5. Revisar una fuente real de dominios, su licencia y actualización; importar la lista y gestionar falsos positivos.
6. Revisar permisos de archivos, custodiar clave y respaldo, y adjuntar sus propias evidencias al informe académico.

No se han realizado esos cambios en el equipo Windows ni publicado el código en GitHub. La entrega de código no demuestra por sí sola el despliegue en esa red.

## Límites y mejoras futuras

El objetivo entregado es filtrado DNS basado en listas. No se incorporaron detección automática de malware, actualización programada de feeds, inspección de archivos, antivirus, filtrado completo de CNAME, validación DNSSEC propia ni control de evasión por IP directa, DoH, VPN o rutas DNS alternativas. Tampoco incluye alta disponibilidad ni SIEM.

El DNS convencional no cifra sus consultas. HTTPS protege el panel. AES-GCM protege campos de logs, no la totalidad de SQLite ni sus respaldos; un propietario del servidor con acceso a la clave puede leerlos. Las cuotas evitan crecimiento ilimitado, pero puede perderse registro bajo carga y los contadores lo reflejan. La escala y disponibilidad deben evaluarse antes de ampliar el uso fuera del laboratorio.

La actividad puede cerrarse como prototipo funcional de laboratorio una vez que el estudiante documente instalación, pruebas reales y correspondencia con su rúbrica. No puede garantizarse aprobación académica sin revisar esa rúbrica completa.
