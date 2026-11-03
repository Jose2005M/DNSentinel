# DNSentinel v0.2 — backend administrativo

Primera etapa del backend del proyecto académico. Mantiene el diseño de la interfaz v0.1 y ahora usa Flask y SQLite para usuarios, reglas, eventos simulados y auditoría.

## Qué funciona

- Inicio de sesión real, sin usuario ni contraseña predeterminados.
- Hash de contraseñas Argon2id con sal generada por la biblioteca.
- Sesiones opacas almacenadas en el servidor; rotación al iniciar sesión, revocación al salir, caducidad absoluta de 8 horas e inactividad de 15 minutos.
- Roles `admin` y `viewer` verificados en el servidor en cada operación.
- Protección CSRF de las operaciones POST/PUT/DELETE, incluido el inicio de sesión.
- Validación positiva en Python de dominios, descripciones, tipos y campos JSON. Límite de petición de 8 KiB.
- CRUD de reglas persistentes con consultas SQL parametrizadas, hasta 5000 reglas.
- Evaluación de política en Python: excepciones primero, coincidencia exacta o por subdominios.
- Auditoría de acceso, cambios administrativos, validaciones y peticiones rechazadas. No se registra el cuerpo de las peticiones, contraseñas ni tokens.
- Historial de las últimas 200 evaluaciones simuladas y exportación CSV.
- Retención de 7 días para eventos y auditoría, con máximo de 10.000 registros de auditoría. Purga al iniciar y diariamente cuando llegan solicitudes; comando para ejecución programada si el servicio está inactivo.
- Intentos de inicio de sesión limitados por cuenta (5) y origen (20) por ventana de 15 minutos; máximo de 60 simulaciones/minuto por usuario.
- Cabeceras defensivas, caché deshabilitada y sin dependencias de fuentes externas en la interfaz.

## Instalación en Windows (PowerShell)

Requiere Python 3.12 o superior instalado. Extrae el ZIP en una carpeta nueva; conserva la versión anterior como referencia. Abre **la carpeta DNSentinel** que contiene `run.py` en Visual Studio Code.

Ejecuta los siguientes comandos en la terminal de esa carpeta. No necesitas activar el entorno ni cambiar la política de ejecución de PowerShell:

```powershell
py -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe -m flask --app dnsentinel:create_app create-user admin
```

La terminal solicitará y confirmará la contraseña. Usa una frase de 15 a 128 caracteres. No aparecerá mientras escribes. No la pongas en comandos, capturas ni el repositorio.

Agrega reglas de ejemplo y ejecuta el servidor:

```powershell
.\.venv\Scripts\python.exe -m flask --app dnsentinel:create_app seed-demo
.\.venv\Scripts\python.exe run.py
```

Abre **http://127.0.0.1:5000** e inicia sesión con la cuenta que acabas de crear. Detén el servidor con **Ctrl+C**. No ejecutes el servidor estático `http.server` de la versión anterior: esta interfaz necesita la API de Flask.

Para crear una cuenta de consulta:

```powershell
.\.venv\Scripts\python.exe -m flask --app dnsentinel:create_app create-user lector --role viewer
```

`seed-demo` agrega únicamente dominios reservados `.test`; no borra reglas existentes. Las reglas de localStorage de v0.1 no se importan automáticamente. El panel comienza vacío si no ejecutas `seed-demo`.

## Archivos principales

| Archivo | Responsabilidad |
|---|---|
| `run.py` | Servidor Waitress, restringido a 127.0.0.1:5000 y sin depurador |
| `dnsentinel/__init__.py` | Aplicación Flask, endpoints, autorización, errores y comandos |
| `dnsentinel/validation.py` | Validación en el servidor |
| `dnsentinel/security.py` | Sesiones, CSRF, auditoría y límites |
| `dnsentinel/db.py` | Esquema SQLite, mantenimiento y evaluación de reglas |
| `dnsentinel/static/index.html` | Interfaz administrativa |
| `dnsentinel/static/styles.css` | Estilos |
| `dnsentinel/static/app.js` | Panel conectado a la API |
| `dnsentinel/static/api.js` | Peticiones HTTP y CSRF |
| `dnsentinel/static/login.html` y `login.js` | Inicio de sesión |
| `tests/test_security.py` | Pruebas de integración y seguridad |
| `evidencias/` | Resultados reproducibles y guía para la Clase 3 |

Al ejecutar la aplicación se crea `instance/dnsentinel.sqlite3` y una clave local `instance/rate-limit.key`. Son datos de ejecución excluidos de Git y del ZIP. La clave se usa para seudonimizar los contadores de origen; no es la contraseña del administrador. Protege la carpeta con permisos de tu usuario en Windows.

## Verificación para la Clase 3

```powershell
.\.venv\Scripts\python.exe -m pip install -r requirements-dev.txt
.\.venv\Scripts\python.exe -m pytest -q
.\.venv\Scripts\python.exe -m bandit -r dnsentinel run.py -f json -o evidencias/bandit.json
.\.venv\Scripts\python.exe -m detect_secrets scan --all-files --exclude-files '(^|/)(instance|evidencias|\.venv|__pycache__|\.pytest_cache)/' > evidencias/secretos.json
```

Para consultar la auditoría, usa la opción **Auditoría de seguridad** con una cuenta administradora. Solo se muestran los últimos 200 eventos, aunque la base conserva hasta 10.000 dentro del periodo de retención.

En Windows PowerShell 5, `>` puede producir UTF-16. Si necesitas que `secretos.json` quede en UTF-8, utiliza PowerShell 7 o `| Out-File -Encoding utf8 evidencias/secretos.json` en lugar de la redirección final.

La carpeta de evidencias incluye resultados obtenidos en el entorno de desarrollo Linux/Python 3.12; ejecuta de nuevo las herramientas en tu computador antes de tomar las capturas. Bandit revisa Python; no verifica JavaScript, dependencias, TLS ni la ausencia total de vulnerabilidades. La revisión de secretos es del árbol de archivos de esta entrega, no del historial de un repositorio del usuario.

Para comprobar la retención de forma manual o mediante el Programador de tareas:

```powershell
.\.venv\Scripts\python.exe -m flask --app dnsentinel:create_app purge-expired
```

## Límites de esta entrega

**Todavía no escucha consultas DNS en UDP/TCP ni bloquea tráfico real.** La pantalla de pruebas evalúa reglas en el servidor Python; elegir UDP/TCP solo etiqueta esa simulación. Próxima etapa: integrar dnspython y el servidor DNS de laboratorio.

El panel se ejecuta por **HTTP exclusivamente en la interfaz de loopback**. No se debe abrir a otros equipos ni utilizar como despliegue de producción. HTTPS, certificados y cifrado en reposo están pendientes: SQLite estándar no cifra automáticamente la base y Argon2id no cifra los eventos. Antes de exponer el panel, configurar un servidor HTTPS, certificado válido, almacenamiento cifrado, nombres de host permitidos y `DNSENTINEL_COOKIE_SECURE=1`; no basta con activar esa variable. No se ha comprobado rendimiento empresarial ni disponibilidad ante ataques distribuidos.

No hay servicio de IA en ejecución. Codex se utiliza como apoyo al desarrollo; las políticas se deciden por reglas.

## Referencias

- Flask: https://flask.palletsprojects.com/en/stable/web-security/
- Argon2: https://argon2-cffi.readthedocs.io/en/stable/howto.html
- Bandit: https://bandit.readthedocs.io/en/latest/start.html
- OWASP ASVS 5.0.0: https://asvs.owasp.org/
- NIST SSDF 1.1: https://csrc.nist.gov/pubs/sp/800/218/final
