# DNSentinel 1.2 — bloqueo DNS y Chrome con lanzador Windows

Proyecto académico para una red de laboratorio autorizada. Incluye servidor DNS real UDP/TCP, panel local HTTPS, reglas de bloqueo y excepciones, importación de listas, registro de consultas y auditoría. El motor aplica listas; no determina automáticamente si un dominio es malicioso.

## Inicio recomendado: ventana automática

Abre **INICIO_AUTOMATICO.md** y completa la instalación única de la extensión según **[CHROME.md](CHROME.md)**. Incluye `Iniciar DNSentinel.cmd`, selección del adaptador, UAC para el componente de red, respaldo del DNS original y botón **Detener protección** con restauración. Los mismos botones aplican y retiran las reglas de Chrome y bloquean/recargan las pestañas correspondientes en cada ciclo, sin reiniciar el navegador. `Restaurar DNS.cmd` permite recuperar un respaldo después de un cierre inesperado.

Si actualizas, detén la instancia anterior y restaura cualquier cambio manual a `127.0.0.1` antes de iniciar. Conserva usuarios y reglas copiando `instance` con el servidor detenido, como explica esa guía. El panel, el servidor y el canal nativo no se elevan; solo el componente de red y su supervisor. La capa DNS sigue usando el DNS del sistema; la extensión aplica además las reglas en el perfil de Chrome donde está habilitada.

La validación disponible incluye lógica con adaptador simulado y sockets reales en Linux. UAC y cambios de adaptador deben verificarse en Windows. Las instrucciones siguientes corresponden al modo manual, que también se conserva.

## Instalación en Windows (PowerShell)

Extrae el ZIP en una **carpeta nueva**. Abre la carpeta `DNSentinel` que contiene `run.py`, `requirements.txt` y este documento. Conserva tu versión 0.2; consulta la migración antes de mover sus datos.

Requiere Python 3.12 o superior. Las pruebas incluidas se ejecutaron con Python 3.12 en Linux; la configuración de Windows, sus permisos, el firewall y el navegador deben verificarse en tu equipo. No necesitas activar el entorno ni modificar la política de ejecución de PowerShell.

```powershell
py -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe -m flask --app dnsentinel:create_app create-user admin
```

Escribe y confirma una frase de **15 a 128 caracteres**. No se muestra mientras escribes. No publiques contraseñas, claves ni tu base de datos.

Crea reglas de demostración y certificados locales:

```powershell
.\.venv\Scripts\python.exe -m flask --app dnsentinel:create_app seed-demo
.\.venv\Scripts\python.exe setup_tls.py
```

`seed-demo` usa dominios reservados `.test`; no son amenazas reales. No borra reglas anteriores. Los comandos de usuarios y `seed-demo` deben ejecutarse con el servidor detenido.

### Confiar en el certificado del laboratorio

`setup_tls.py` crea una CA exclusiva para esta instalación y un certificado para `localhost`, `127.0.0.1` y `::1`. La clave privada de la CA se descarta; la clave del servidor permanece en `instance/tls/server-key.pem`. Antes de abrir el panel, instala **solo el certificado público `local-ca.pem` generado por ti** en la confianza de tu usuario Windows:

```powershell
certutil -user -addstore Root .\instance\tls\local-ca.pem
```

Esto añade una autoridad de confianza al usuario actual. No importes certificados de terceros ni compartas `server-key.pem`. No desactives la validación TLS ni ignores advertencias del navegador. Si el equipo es administrado y no permite instalarla, solicita la configuración al responsable del laboratorio.

Inicia ambos servicios:

```powershell
.\.venv\Scripts\python.exe run.py
```

Abre **https://localhost:8443**. El DNS escucha en **127.0.0.1:5353 UDP y TCP**. El panel solo escucha en loopback. Ctrl+C detiene ambos servicios. El programa no cambia el DNS de Windows.

El certificado del servidor vence a los 90 días. Para renovarlo, detén la aplicación, guarda los certificados anteriores de forma privada, retira su CA de la confianza de usuario y genera un conjunto nuevo en una carpeta vacía. Vuelve a instalar únicamente la nueva CA. Puedes administrar la confianza desde `certmgr.msc` → Entidades de certificación raíz de confianza → Certificados → DNSentinel CA local; comprueba el certificado antes de retirarlo.

## Comprobar el bloqueo real

Con el servidor abierto, usa otra terminal de la carpeta del proyecto:

```powershell
.\.venv\Scripts\python.exe check_dns.py malware.test
.\.venv\Scripts\python.exe check_dns.py malware.test --tcp
.\.venv\Scripts\python.exe check_dns.py example.com
```

Los dos primeros deben devolver `REFUSED` si la regla de demostración está activa. El último se reenvía al upstream configurado, por defecto `1.1.1.1:53`, y requiere conectividad externa. Una respuesta `SERVFAIL` indica un fallo del upstream o de conectividad; no demuestra un bloqueo por regla. Las consultas aparecerán en el registro como **DNS real**. La pantalla «Probar una consulta» sigue siendo una evaluación de política sin tráfico DNS.

Prueba también `seguro.malware.test`: la excepción de demostración permite reenviarlo, pero al ser un nombre reservado no se espera una dirección pública. «Permitido» significa que pasó el filtro, no que exista o sea seguro.

## Aplicar el filtro a las aplicaciones del equipo

Esta sección describe el modo manual **solo DNS**. Para activar/desactivar páginas en Chrome en cada ciclo sin reiniciar, utiliza el lanzador con la extensión de [CHROME.md](CHROME.md).

5353 permite probar sin cambiar la red. Para que Windows use DNSentinel como DNS habitual, el servicio debe escuchar en el puerto estándar **53**:

```powershell
.\.venv\Scripts\python.exe run.py --dns-port 53
```

En un equipo de laboratorio propio o autorizado:

1. Anota la configuración DNS original del adaptador, incluida IPv6, antes de cambiarla.
2. Configura el DNS preferido IPv4 del adaptador como `127.0.0.1` con el servicio funcionando en el puerto 53. No pongas un DNS alternativo externo si buscas que todas las consultas pasen por el filtro.
3. Comprueba que el navegador usa el DNS del sistema. DNS seguro/DoH, VPN, DNS alternativos y la ruta IPv6 pueden evitar el filtro; este software no controla esas rutas.
4. Vacía la caché con `ipconfig /flushdns`, reinicia el navegador y verifica primero con los dominios `.test` y los registros del panel.
5. Antes de detener definitivamente DNSentinel, **restaura la configuración DNS original**. Dejar `127.0.0.1` sin un servicio activo puede impedir resolver nombres.

En este modo manual configuras el adaptador tú mismo; el lanzador descrito en INICIO_AUTOMATICO.md automatiza el ciclo de activación y restauración. Si el puerto 53 está ocupado o restringido, conserva 5353 y usa `check_dns.py`; el bloqueo habitual del navegador no estará activado.

Para clientes de una LAN autorizada, especifica la IP del servidor y la red real, por ejemplo:

```powershell
.\.venv\Scripts\python.exe run.py --dns-host 192.168.1.20 --dns-port 53 --allow-network 192.168.1.0/24
```

Sustituye esos valores por los de tu laboratorio; configura los clientes para consultar esa IP y, si corresponde, permite **UDP y TCP 53 solo desde esa red** en el firewall. El panel sigue siendo local. Nunca publiques el servicio en Internet ni redirijas puertos del router. Las redes `/0` se rechazan. Por defecto solo se aceptan clientes loopback.

## Registrar o importar dominios

En **Control de dominios**, agrega reglas manuales o pulsa **Importar lista**:

- Archivo UTF-8 de hasta 1 MiB; un dominio por línea o una línea hosts como `0.0.0.0 dominio.test`. Se admite un nombre por línea hosts.
- No se admiten URL, rutas, expresiones regulares ni reglas Adblock.
- Puedes seleccionar bloqueo o excepción e incluir subdominios. Las excepciones activas tienen prioridad.
- Los duplicados del mismo tipo se conservan sin sobrescribir su descripción, alcance o estado. Para reactivar una regla inactiva, edítala en el panel.
- Se informan dominios agregados, existentes y líneas inválidas ignoradas. Si supera las 5.000 reglas totales, no se incorpora ninguna.
- `ejemplos/lista-prueba.txt` permite demostrar la importación sin visitar sitios peligrosos.

Revisa origen, licencia y fecha de cualquier lista externa. La herramienta **no descarga ni actualiza listas automáticamente** y una lista puede producir falsos positivos. Mantenerlas actualizadas es responsabilidad del administrador.

## Seguridad y almacenamiento

- Contraseñas Argon2id; no hay cuentas predeterminadas. Sesiones opacas revocables de hasta 8 horas y 15 minutos sin solicitudes HTTP. La actualización del panel cuenta como actividad. Inicio de sesión con límites de intentos.
- Cookies HTTPS `__Host-`, Secure, HttpOnly y SameSite=Strict. CSRF en operaciones de cambio. Roles `admin` y `viewer` verificados en Python.
- HTTPS TLS 1.2 o superior en el panel, sin depurador. El protocolo DNS de clientes y upstream es DNS convencional sin cifrar; HTTPS del panel no cifra ese tráfico.
- Los campos textuales de consultas y auditoría usan AES-256-GCM con nonce aleatorio por campo. El cliente DNS se registra mediante un seudónimo HMAC, no su IP en claro.
- **No se cifra el archivo SQLite completo**: reglas, nombres de usuario, metadatos numéricos y estructura permanecen accesibles al propietario del archivo. Las contraseñas están hasheadas y los tokens de sesión se almacenan como hashes. El cifrado de logs no protege frente a alguien que controle el servidor y también pueda leer la clave.
- La clave de logs se crea fuera del proyecto: en Windows, `%LOCALAPPDATA%\DNSentinel\data.key`; en Linux, `~/.local/share/DNSentinel/data.key`. `DNSENTINEL_KEY_FILE` permite establecer una ruta privada distinta antes del primer inicio. No borres ni reemplaces la clave de una base existente.
- Protege con permisos de tu usuario tanto esa carpeta como `instance/`; en Windows revisa Propiedades → Seguridad. Los modos POSIX de creación no sustituyen una ACL de Windows. No uses carpetas compartidas o de acceso público.
- Registros: últimas 2.000 consultas; hasta 10.000 eventos de auditoría; retención máxima de 7 días mientras la aplicación está activa. Purga al iniciar, diariamente y con el comando `purge-expired`. Una copia de respaldo conserva su contenido hasta que la elimines según tu política.
- Cola de logs acotada: 256 entradas. Bajo saturación pueden descartarse logs; el panel muestra los contadores de descartes y errores. No es un sistema de auditoría forense inmutable.
- DNS: 30 consultas/s por cliente con ráfaga de 60, 100/s global con ráfaga de 200, 64 consultas simultáneas y 32 conexiones TCP. Al superar límites se descartan consultas o se cierra la conexión. Son límites de laboratorio, no una garantía de rendimiento.

`instance/`, `.env`, certificados, claves y bases están excluidos de Git. Ninguno se distribuye dentro del ZIP.

### Usuarios y recuperación local

Con el servidor detenido:

```powershell
.\.venv\Scripts\python.exe -m flask --app dnsentinel:create_app create-user lector --role viewer
.\.venv\Scripts\python.exe -m flask --app dnsentinel:create_app reset-password admin
.\.venv\Scripts\python.exe -m flask --app dnsentinel:create_app purge-expired
```

Restablecer la contraseña revoca las sesiones de esa cuenta. El comando es una función de recuperación del propietario que tiene acceso local a los archivos; no debe exponerse como servicio remoto. El lector puede consultar reglas y eventos y usar la evaluación de política, pero no modifica reglas ni consulta la auditoría.

## Migración desde 0.2

1. Detén la versión anterior y conserva una copia privada completa de su carpeta `instance/`. No copies una base SQLite mientras el servidor la modifica.
2. Extrae esta versión en otra carpeta y crea su entorno con `requirements.txt`.
3. Copia la carpeta `instance/` anterior a la nueva raíz `DNSentinel` (junto a `run.py`). Si ya existe una base nueva, consérvala aparte; no mezcles bases.
4. Genera los certificados con `setup_tls.py` y configura la confianza como se explicó arriba. No necesitas volver a crear las cuentas existentes; `reset-password` permite recuperarlas.
5. El primer inicio añade los campos de origen y cliente a los eventos y cifra los registros anteriores con la clave de logs externa. Se mantienen usuarios y reglas. Los registros con más de 7 días se purgan según la política.
6. Confirma reglas, acceso y pruebas DNS. Conserva una copia privada de la base **y de su clave** para recuperación. Si pierdes la clave, los logs cifrados no podrán leerse; la aplicación rechaza una clave incorrecta.

La copia antigua v0.2 mantiene logs en claro. La migración reduce remanentes dentro de SQLite, pero no borra respaldos antiguos ni garantiza eliminación física en SSD o instantáneas. Para proteger todos los datos en reposo, configura cifrado de volumen y permisos fuera de la aplicación según el equipo del laboratorio.

## Resolver problemas

| Situación | Acción |
|---|---|
| WinError 10013 o puerto ocupado | Prueba `run.py --web-port 8444 --dns-port 5354`; abre el puerto nuevo y usa `check_dns.py malware.test --port 5354`. Revisa reservas, firewall y otros servicios. |
| Usuario ya existe | Conserva la cuenta o usa `reset-password nombre`; no borres la base. |
| Contraseña rechazada | Usa una frase de 15 a 128 caracteres. |
| Certificado no confiable | Verifica hostname, fecha, archivo de CA instalado y confianza del navegador. No ignores el error. |
| DNS permitido devuelve SERVFAIL | Revisa upstream y salida UDP/TCP al puerto configurado. El bloqueo por regla devuelve REFUSED. |
| Panel no abre | Usa `run.py`, no `http.server`; revisa el mensaje de inicio en terminal. |
| Clave incorrecta / base no carga | Detén el servicio y restaura el par base-clave de tu respaldo. No regeneres una clave para una base cifrada. |
| Dominio recién bloqueado sigue abriendo | En el lanzador comprueba la confirmación de Chrome, extensión habilitada en ese perfil y excepciones. Consulta CHROME.md. En modo manual solo DNS, revisa caché, conexiones y DNS utilizado. |

Para desarrollo aislado existe `run.py --http --web-port 8080`. Abre `http://127.0.0.1:8080` y usa únicamente datos de prueba: este modo desactiva TLS y usa otra cookie. No representa la configuración final. Usa `127.0.0.1` para evitar interferencia con HSTS de `localhost`.

## Pruebas y evidencias

```powershell
.\.venv\Scripts\python.exe -m pip install -r requirements-dev.txt
.\.venv\Scripts\python.exe -m pytest -q
node --test tests/test_chrome_extension.mjs
.\.venv\Scripts\python.exe -m bandit -r dnsentinel desktop run.py launcher.py control_windows.py setup_tls.py check_dns.py
.\.venv\Scripts\python.exe -m pip_audit -r requirements.txt
.\.venv\Scripts\python.exe -m detect_secrets scan --all-files --exclude-files '(^|/)(instance|evidencias|\.venv|__pycache__|\.pytest_cache)/'
```

Consulta `evidencias/INFORME_LANZADOR.md` para los resultados de 1.1, `evidencias/INFORME_FINAL.md` como informe histórico de la base 1.0 y `evidencias/CONTROLES.md` para la trazabilidad normativa. Los tests usan upstream controlado con direcciones de documentación; no descargan malware ni dependen del DNS público. La prueba del panel valida el certificado de su CA temporal y no omite la verificación TLS.

## Archivos y arquitectura

| Componente / archivo | Función y dependencia |
|---|---|
| `run.py` | Arranca panel HTTPS (Cheroot) y DNS real. `--http` usa Waitress solo para desarrollo. |
| `setup_tls.py` | Genera CA local y certificado del panel. Requiere cryptography. |
| `dnsentinel/static/index.html` | Archivo principal de la interfaz; usa `styles.css`, `api.js` y `app.js`. |
| `dnsentinel/static/login.html` | Acceso al panel con `login.js`. |
| `dnsentinel/__init__.py` | API Flask y CLI de usuarios/mantenimiento. |
| `dnsentinel/security.py` | Sesiones, CSRF, roles, auditoría y límites de intentos. |
| `dnsentinel/validation.py` | Validación en el servidor. |
| `dnsentinel/policy.py` | Instantánea de reglas compartida por API y DNS, con exclusión mutua. |
| `dnsentinel/dns_server.py` | Recepción UDP/TCP, ACL, límites, filtrado y reenvío con dnspython. |
| `dnsentinel/lists.py` | Importación validada a SQLite y actualización de la política. |
| `dnsentinel/db.py` y `crypto_store.py` | SQLite, migración, retención y cifrado de consultas/auditoría. |
| `check_dns.py` | Cliente de prueba UDP/TCP sin cambiar el DNS del sistema. |
| `tests/` | Pruebas de API, protocolo real, TLS, migración y arranque. |

Flujo DNS: cliente autorizado → servidor UDP/TCP → política de reglas → bloqueo REFUSED o consulta upstream → respuesta al cliente. En paralelo se encola el registro para cifrarlo en SQLite. El panel administra la misma política y lee registros mediante endpoints autenticados.

## Alcance final

Cumple el objetivo de **bloquear por DNS dominios registrados en listas**, con administración y demostración en una red de laboratorio. No incluye antivirus, análisis de archivos, detección automática de amenazas, actualización automática de feeds, inspección HTTPS, validación DNSSEC propia, filtrado exhaustivo de cadenas CNAME, prevención de evasión por IP/DoH/VPN ni alta disponibilidad. No se declara certificación NIST/OWASP ni ausencia absoluta de vulnerabilidades.

Las listas necesitan mantenimiento y las pruebas en la red real del estudiante deben adjuntarse a la entrega académica. No se ha modificado ni publicado tu repositorio GitHub desde este paquete.
