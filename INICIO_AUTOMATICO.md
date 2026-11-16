# DNSentinel 1.2 — inicio y parada de DNS y Chrome en Windows

La ventana local administra el ciclo de protección. El panel web sigue sirviendo para gestionar dominios y consultar registros.

## Actualizar desde la versión que ya estás utilizando

1. En el servidor anterior, pulsa **Ctrl+C**. No ejecutes dos instancias en el puerto 53.
2. Si configuraste manualmente el adaptador como `127.0.0.1`, **restaura primero su configuración DNS original**. Si antes era automática, vuelve a «Obtener la dirección del servidor DNS automáticamente». Si tenía direcciones fijas, repón esas direcciones. No adivines la configuración de una red administrada.
3. Extrae este ZIP en otra carpeta. Copia completa la carpeta privada **`instance`** de tu versión actual a la nueva carpeta `DNSentinel`, junto a `run.py`. Hazlo con el servidor detenido. Así conservas base de datos, usuarios, reglas y certificados. Conserva también la clave externa de logs que ya utiliza tu instalación; no la regeneres.
4. Abre una terminal en la nueva carpeta y crea su entorno:

```powershell
py -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
```

No copies el entorno virtual de otra ubicación: créalo en la nueva carpeta. Si copiaste una instalación 1.0, no vuelvas a crear usuarios ni certificados existentes. La CA local que ya instalaste continúa siendo válida si conservas el mismo certificado y no ha vencido.

La carpeta debe estar en un disco local con permisos de tu usuario; no la ejecutes desde una ubicación compartida o modificable por otras personas. Para elevar operaciones se ejecutará el código local que hayas extraído.

## Instalación nueva, una sola vez

Si no tienes una instalación anterior, instala Python 3.12 o superior para Windows incluyendo **Tcl/Tk e IDLE**, crea el entorno y ejecuta:

```powershell
.\.venv\Scripts\python.exe -m flask --app dnsentinel:create_app create-user admin
.\.venv\Scripts\python.exe -m flask --app dnsentinel:create_app seed-demo
.\.venv\Scripts\python.exe setup_tls.py
certutil -user -addstore Root .\instance\tls\local-ca.pem
```

Usa una contraseña de 15 a 128 caracteres. El último comando agrega a la confianza del usuario únicamente la CA que generaste para esta instalación. No importes una CA ajena ni compartas claves privadas. El lanzador no instala certificados ni desactiva validación TLS por su cuenta.

Antes del primer inicio completa **[CHROME.md](CHROME.md)**: ejecuta `Instalar integracion Chrome.cmd` y carga `chrome_extension` una vez en tu perfil de Chrome.

## Uso cotidiano

1. Haz doble clic en **`Iniciar DNSentinel.cmd`**. Se abre la ventana del lanzador sin elevar el panel ni el servidor.
2. Selecciona tu adaptador conectado, por ejemplo **Wi-Fi** o **Ethernet**. Si solo hay uno conectado, aparece seleccionado. Se modifica únicamente ese adaptador. La ventana ofrece adaptadores conectados con IPv4 habilitado; no automatiza interfaces solo IPv6.
3. Deja el puerto HTTPS **8444** y el upstream **1.1.1.1**, o usa el DNS externo autorizado de tu red. Pulsa **Iniciar protección**.
4. El lanzador inicia el servidor y verifica HTTPS con la confianza del sistema, respuestas de su propio DNS en UDP/TCP y conectividad al upstream. Si falla o el puerto 53 está ocupado, detiene su intento sin cambiar el DNS del adaptador. No cierra otros programas para liberar puertos.
5. Windows solicita permisos de administrador para el componente de red. Acepta para continuar. Cancelar no cambia el DNS y detiene el servidor que se estaba preparando.
6. El componente guarda primero el modo DNS original y sus direcciones, inicia el supervisor de recuperación y configura `127.0.0.1`. Si el adaptador tiene IPv6 habilitado, configura también `::1` y el servidor escucha en ambos loopbacks.
7. Cuando aparece **Protección activa en DNS y Chrome**, el lanzador abre **https://localhost:8444** en tu navegador habitual. Inicia sesión normalmente. Instala antes la extensión siguiendo **CHROME.md**; el lanzador exige su confirmación antes de solicitar UAC y cambiar el DNS.
8. Gestiona dominios y listas en el panel. Mantén abierta la ventana local de protección.
9. Para finalizar, pulsa **Detener protección** en esa ventana. Primero se restaura el DNS original y luego se solicita la parada del servidor y la retirada de reglas de Chrome. Las pestañas bloqueadas vuelven a cargar. Espera la confirmación de ambos estados. Cerrar normalmente la ventana también solicita esta secuencia.

Puedes crear un acceso directo a `Iniciar DNSentinel.cmd` en el escritorio. El uso diario no requiere ejecutar comandos en una terminal. UAC se solicita después de pulsar Iniciar protección, cuando se necesita modificar la red.

## Chrome y prueba de bloqueo

Instala una vez **`Instalar integracion Chrome.cmd`** y carga la carpeta **`chrome_extension`** en `chrome://extensions`, tal como explica **[CHROME.md](CHROME.md)**. Después usa los mismos botones del lanzador con Chrome abierto. La extensión aplica reglas y aparta las pestañas bloqueadas; al detener, retira las reglas y recarga sus direcciones originales. Puedes repetir el ciclo sin reiniciar Chrome.

El lanzador no modifica políticas ni preferencias de Chrome. Para comprobar también la capa DNS, configura una vez `chrome://settings/security` → **Usar DNS seguro** desactivado o con DNS del sistema. VPN/proxy/DoH pueden eludir esa capa.

Agrega `example.com` como bloqueo activo con subdominios en el panel, sin excepción permitida. La pestaña debe mostrar **Página bloqueada**. Las solicitudes detenidas en Chrome pueden no alcanzar el servidor DNS ni generar una consulta **DNS real**. Comprueba esa capa por separado con `check_dns.py`. Un dominio `.test` que no abre no demuestra bloqueo por sí solo.

Si tienes varias conexiones activas o cambias de Wi-Fi/Ethernet, otras rutas pueden evitar el filtro. Detén la protección y actívala de nuevo seleccionando el adaptador correcto. El software no modifica todos los adaptadores ni controla VPN, DoH o políticas de una organización.

## Cierres inesperados y recuperación

Se ejecuta un supervisor elevado separado mientras la protección está activa. Si detecta que se cerró el lanzador, el componente de control o el servidor, intenta restaurar el respaldo. El componente principal también comprueba la salud del DNS y que el supervisor siga vivo.

Si no puede restaurar, conserva el respaldo y muestra **Restauración pendiente**. Si el servidor sigue disponible, no lo detiene deliberadamente tras un fallo de restauración. No se garantiza conectividad ante fallos de Windows, pérdida de alimentación, cierre forzado de todos los procesos o problemas físicos de red.

Después de un apagado abrupto, o si no recuperas la resolución de nombres:

1. Abre **`Restaurar DNS.cmd`**.
2. Acepta la solicitud de administrador.
3. Espera **DNS original restaurado**. La recuperación usa el respaldo persistente y no necesita consultar Internet ni arrancar el servidor.

También existe el botón **Restaurar DNS guardado**. Si hay una sesión activa, utiliza primero Detener protección en esa sesión. No borres el respaldo ni sustituyas automáticamente DNS fijos por DHCP.

El respaldo se guarda en:

```text
C:\ProgramData\DNSentinel\NetworkProtection\state.json
```

La ruta utiliza la carpeta ProgramData de Windows, que puede estar en otra unidad. La escritura queda restringida a Administradores y SYSTEM; los usuarios pueden leer el estado. Contiene el GUID del adaptador, modo automático/fijo y direcciones originales. No contiene contraseñas de tu cuenta ni la clave de cifrado de los logs.

Si una herramienta externa cambia el DNS mientras está activo, la restauración detecta el conflicto y evita sobrescribir sin más esa nueva configuración. Revisa el adaptador y el respaldo con el administrador de la red. Si se borró/desinstaló el adaptador, reconéctalo o restaura su configuración con el responsable de la red.

## Qué hace y qué conserva

| Aspecto | Comportamiento |
|---|---|
| DNS original automático | Restaura el modo automático, permitiendo recibir los DNS actuales de la red. No congela direcciones antiguas de DHCP. |
| DNS original fijo | Repone todas las direcciones guardadas, en su orden, por familia. |
| DNS previo ya en loopback | Rechaza la activación: debes restaurar primero el ajuste manual anterior, porque no puede reconstruirlo. |
| Usuarios, reglas y consultas | Se conservan en `instance`; el lanzador no borra ni reinicia la base. |
| Privilegios | Solo control de red y supervisor usan UAC. El servidor y el panel se inician como tu usuario. |
| Certificados y contraseña | Configuración inicial; no se cambian automáticamente. |
| IP del equipo, puerta de enlace y firewall | No se configuran desde este lanzador. |
| Chrome / DNS seguro | La extensión sincroniza reglas y pestañas; no cambia preferencias ni políticas. El DNS del sistema aplica la capa DNS. |
| Inicio de Windows | No se instala servicio, tarea programada ni inicio automático. |

## Archivos añadidos

- `Iniciar DNSentinel.cmd`: entrada de uso diario.
- `Restaurar DNS.cmd`: acceso a recuperación.
- `launcher.py`: ventana local y arranque del servidor sin elevación.
- `control_windows.py`: componente elevado y supervisor separado.
- `desktop/core.py`: respaldo transaccional y restauración.
- `desktop/windows.py`: APIs de Windows, registro de origen DNS y comandos netsh por índice de adaptador.
- `desktop/probe.py`: comprobación de identidad del DNS por UDP/TCP e IPv4/IPv6.

Los archivos temporales de sesión y el log del servidor están en `instance/launcher/<identificador>/`. No los subas a GitHub. No hay un endpoint web para modificar el DNS de Windows.

## Validación de esta entrega

Se probaron en Linux la lógica de respaldo/restauración con un adaptador simulado, fallos parciales, cancelación UAC simulada, recuperación por supervisor, sockets reales IPv4/IPv6, HTTPS y parada por señal de sesión. **No se han ejecutado UAC, netsh, ACL NTFS ni cambios en un adaptador Windows real desde este entorno.** Realiza primero una prueba de inicio y parada en tu equipo y confirma que vuelve a su DNS original antes de usarlo durante periodos largos.

Referencias oficiales de implementación: [netsh interface](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/netsh-interface), [Get-NetAdapter](https://learn.microsoft.com/en-us/powershell/module/netadapter/get-netadapter) y [ShellExecuteExW](https://learn.microsoft.com/en-us/windows/win32/api/shellapi/nf-shellapi-shellexecuteexw).
