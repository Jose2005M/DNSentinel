# Cambios y validación — DNSentinel 1.1

Fecha: 10 de noviembre de 2026. Esta entrega actualiza 1.0 para activar y detener el filtrado desde una ventana local de Windows.

## Funcionamiento implementado

- Entradas `Iniciar DNSentinel.cmd` y `Restaurar DNS.cmd`, con comprobación de entorno y dependencias.
- Ventana Tkinter para seleccionar un adaptador conectado con IPv4 habilitado, upstream y puerto HTTPS (8444 por defecto).
- Arranque de servidor y panel sin elevación. Comprobación de identidad propia por DNS TXT reservado, UDP/TCP y, cuando corresponde, IPv4/IPv6; HTTPS se valida con la confianza del sistema. Una consulta al upstream verifica conectividad antes de cambiar el adaptador.
- UAC a través de ShellExecuteEx para un componente separado. Solo control de red y supervisor se elevan.
- Respaldo persistente antes de activar: GUID de adaptador, modo automático/fijo y lista ordenada de direcciones por familia.
- netsh cambia solamente el DNS del adaptador seleccionado a loopback; se comprueba el estado guardado por Windows. El servicio escucha en 127.0.0.1 y, si el adaptador usa IPv6, también en ::1.
- Apertura del panel después de confirmar activación. Botón Detener protección y cierre normal de ventana: restauración primero, parada del servidor después.
- Supervisor elevado independiente: detecta cierre de procesos y restaura. Si la restauración falla, conserva el respaldo y no solicita detener un servidor que aún pueda estar dando resolución. Recuperación explícita tras apagado mediante Restaurar DNS.cmd.
- Exclusión mutua entre sesiones y operaciones de restauración; no se sobrescribe un respaldo pendiente ni una configuración que otra herramienta cambió mientras estaba activo.

No se instalaron servicios, tareas de inicio, reglas de firewall ni políticas de Chrome. Se conserva el modo manual con run.py. La configuración inicial de certificados, cuenta y dependencias sigue siendo necesaria.

## Validación

Se ejecutaron **60 pruebas aprobadas** con Python 3.12.14 en Linux. La evidencia es `pruebas-lanzador.txt` y `pruebas-lanzador.xml`.

Las 44 pruebas de la base verifican API, autenticación, permisos, CSRF, listas, política, logs cifrados, migración, DNS UDP/TCP, HTTPS verificable y arranque. La prueba de arranque incorpora ahora el paquete desktop que necesita run.py.

Las 16 pruebas adicionales cubren:

- respaldo durable antes del primer cambio;
- conservación de automático frente a fijo, múltiples servidores y orden;
- recuperación desde otra instancia usando el respaldo;
- activación parcial y restauración posterior;
- fallo de restauración y reintento sin perder datos;
- no sobrescribir respaldo pendiente ni otra sesión;
- conflicto con cambio externo de DNS;
- rechazo si el DNS cambia entre respaldo y activación;
- rechazo del estado manual previo en loopback;
- solo familia habilitada del adaptador seleccionado;
- fallo de escritura antes de cambiar la red;
- rechazo de direcciones inválidas en el respaldo;
- sonda real por UDP/TCP e IPv4/IPv6, sin consultar upstream ni contaminar registros;
- composición de argumentos netsh para restaurar listas, sin shell ni nombres de adaptador evaluados como código;
- recuperación del supervisor ante cierre de controlador y preservación del servidor ante fallo de restauración;
- cancelación UAC simulada y limpieza del servidor preparado;
- arranque real por sesión y parada únicamente con el token correspondiente, en un puerto de prueba disponible.

Los tests de adaptadores, UAC y supervisor utilizan dobles de prueba; **no demuestran ejecución real de UAC, netsh, registro de Windows o ACL NTFS**. No se modificó ningún adaptador en este entorno. La GUI no se verificó visualmente en Windows. La prueba de sockets usa puertos loopback disponibles, no cambia el DNS del sistema ni presupone que 53 esté disponible en todos los equipos.

Antes del uso cotidiano, en Windows se debe comprobar un ciclo completo: DNS original → activar → bloqueo real → detener → DNS original restaurado. También deben verificarse IPv6, permisos, confianza del certificado y configuración de Chrome del equipo.

## Revisión estática y secretos

Bandit 1.9.4 reportó **8 hallazgos: 7 bajos y 1 medio; 0 altos**. No se desactivaron reglas ni se usó #nosec. No son ocho CVE confirmadas.

| Hallazgo | Revisión |
|---|---|
| B404 (3) | Importación de subprocess en ventana, control y módulo Windows. Es necesaria para iniciar procesos propios y utilidades del sistema; requiere revisar la confianza de rutas y entradas. |
| B603 (4) | Invocaciones sin shell: servidor propio, supervisor propio y utilidades Windows. Se usan vectores de argumentos; los ejecutables de sistema se resuelven bajo System32; UUID, PID, puertos e IP se validan. El script PowerShell es fijo y los nombres de adaptador no se interpolan como código. Se acepta el uso revisado de procesos en una instalación local de confianza, no como API remota para ejecutar comandos. |
| B104 (1) | La cadena 0.0.0.0 se reconoce al importar archivos hosts, no se utiliza para abrir un socket. Falso positivo contextual ya documentado en 1.0. |

Las ubicaciones exactas están en `bandit-lanzador.json` y `.txt`. El total cambió respecto de 1.0 porque ahora se revisa también el código de procesos locales. El uso de `validate=no` en netsh omite únicamente la validación de alcance del DNS de esa utilidad, después de la sonda propia; no desactiva la validación HTTPS del panel.

`detect-secrets` no reportó candidatos en los archivos revisados. Se excluyeron instance, entorno virtual, cachés y evidencias. No se revisó historial de Git. La nueva funcionalidad no añade dependencias de terceros: Tkinter forma parte de la instalación de Python con Tcl/Tk, y las APIs de Windows usan la biblioteca estándar. Se conserva el resultado histórico de revisión de dependencias de 1.0; no se presenta como una auditoría nueva de Windows ni de todos sus componentes.

## Recuperación y límites

El respaldo se guarda bajo ProgramData/DNSentinel/NetworkProtection, con propietario Administradores y ACL para escritura de Administradores/SYSTEM y lectura de usuarios. Los archivos de sesión están bajo instance y no se incluyen en Git. Solo se acepta una sesión de control dentro de instance/launcher del proyecto. Los cambios DNS no se exponen en un endpoint web.

Un apagado o cierre de todos los procesos impide ejecutar recuperación en ese instante: el respaldo persistente permite restaurar al volver a iniciar. No se garantiza restauración si Windows rechaza la operación, desapareció el adaptador o se eliminó el respaldo. La recuperación no adivina direcciones originales ni convierte automáticamente una configuración fija a DHCP.

Chrome debe usar el DNS del sistema. VPN, DoH, proxy, otros adaptadores activos y conexiones/cache anteriores pueden evitar el bloqueo. No se modifican preferencias del navegador automáticamente. La protección cubre el adaptador seleccionado y debe reiniciarse al cambiar de conexión.

## Fuentes de implementación

- Microsoft, netsh interface: https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/netsh-interface
- Microsoft, Get-NetAdapter: https://learn.microsoft.com/en-us/powershell/module/netadapter/get-netadapter
- Microsoft, ShellExecuteExW: https://learn.microsoft.com/en-us/windows/win32/api/shellapi/nf-shellapi-shellexecuteexw

El alcance académico sigue siendo bloqueo DNS mediante listas; no es antivirus, prevención completa de evasión o certificación de cumplimiento.
