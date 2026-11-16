# Chrome: activar, desactivar y reactivar sin reiniciar

DNSentinel 1.2 combina el DNS del adaptador con una extensión Manifest V3. Al pulsar **Iniciar protección**, el lanzador envía las reglas activas a Chrome y espera la confirmación de que están aplicadas y de que las pestañas afectadas han sido dirigidas a la pantalla de bloqueo. Después configura el DNS mediante UAC. No anuncia protección activa si Chrome no confirma la sincronización.

Al pulsar **Detener protección**, primero restaura el DNS original. Después retira las reglas de Chrome y vuelve a cargar las pestañas bloqueadas que pasan a estar permitidas. Al volver a iniciar, bloquea otra vez aunque el navegador conserve la IP, caché o conexiones anteriores.

## Instalación única en Windows

Requiere Chrome 120 o superior y el entorno `.venv` de este proyecto ya preparado según [INICIO_AUTOMATICO.md](INICIO_AUTOMATICO.md).

1. Ejecuta **`Instalar integracion Chrome.cmd`** con tu usuario habitual. Registra el canal nativo en `HKEY_CURRENT_USER`, sin UAC. Muestra la carpeta de la extensión y su ID esperado.
2. Abre **`chrome://extensions`** en el perfil de Chrome que vas a utilizar.
3. Activa **Modo de desarrollador**, pulsa **Cargar descomprimida** y selecciona la carpeta **`chrome_extension`** de este proyecto.
4. Comprueba que **DNSentinel · Protección de Chrome** esté habilitada y que su ID coincida con el mostrado por el instalador. La clave pública del manifiesto mantiene ese ID al mover el proyecto; no es una clave privada ni un secreto.
5. Abre el lanzador y utiliza los botones habituales. Chrome debe estar abierto al iniciar la protección. La extensión no tiene un interruptor independiente.

No hace falta reiniciar Chrome. Si cargaste la extensión antes de registrar el canal, espera unos segundos o abre su icono y pulsa **Comprobar conexión**. Si Chrome está administrado y prohíbe extensiones descomprimidas o Native Messaging, el administrador debe autorizar la instalación; el lanzador no cambia esas políticas.

Conserva la carpeta del proyecto y su `.venv`: Chrome los utiliza para conectar. Si mueves la carpeta, vuelve a ejecutar el instalador desde la nueva ubicación y carga allí la extensión. Al actualizar sus archivos, pulsa **Recargar** en `chrome://extensions` una vez; el uso cotidiano conserva los mismos botones del lanzador.

## Prueba de tres ciclos

1. Con la protección detenida, abre una página que funcione, por ejemplo `https://example.com`.
2. Inicia la protección, abre el panel y añade `example.com` como **bloqueo activo con subdominios**, sin excepción de permiso. La pestaña ya abierta debe pasar a **Página bloqueada**. Las modificaciones del panel se sincronizan automáticamente.
3. Pulsa **Detener protección**. Espera la confirmación del DNS y de Chrome: la pestaña debe cargar de nuevo su dirección original.
4. Pulsa **Iniciar protección**. La misma pestaña debe volver a bloquearse.
5. Repite los pasos 3 y 4 dos veces más, conservando Chrome abierto.

Las excepciones de permiso tienen prioridad sobre cualquier bloqueo coincidente, igual que en el DNS. Una regla sin subdominios solo afecta al dominio exacto. La extensión también comprueba navegaciones y restauraciones desde el historial para cubrir páginas servidas desde caché o service workers.

## Conexión y fallos

- El mensaje **Protección activa en DNS y Chrome** requiere confirmaciones recientes de todos los perfiles conectados a esta instalación. La sincronización usa revisiones nuevas en cada cambio; una confirmación de un ciclo anterior no sirve.
- Si falta la extensión, está deshabilitada o Chrome está cerrado, el inicio falla antes de cambiar el DNS. Revisa el instalador, el perfil y el icono de la extensión.
- Si Chrome deja de confirmar durante la protección, el lanzador solicita restaurar el DNS. Si está actualizando reglas, muestra la sincronización pendiente antes de declarar protección activa.
- Si el lanzador se cierra inesperadamente, el canal nativo deja vencer su estado en aproximadamente cuatro segundos y pide retirar las reglas. Si el host nativo se desconecta, la extensión también las retira. El supervisor de red existente restaura el DNS por separado. Un navegador o un sistema operativo bloqueados pueden retrasar esas acciones.
- Si falla la restauración DNS, se conserva el respaldo y se muestra el fallo. El estado de Chrome se comunica por separado; retirar reglas de Chrome no repara una restauración de red fallida.
- Si Chrome no confirma la retirada, el lanzador lo indica expresamente. Vuelve a conectar/habilitar la extensión antes de comprobar otro ciclo.

## Alcance y privacidad

La extensión aplica reglas locales `declarativeNetRequest` a las solicitudes y cambia las pestañas HTTP/HTTPS de los dominios bloqueados por una página local. No inspecciona el contenido HTTPS ni envía datos a un servidor externo. Necesita permisos de pestañas, navegación, reglas de solicitudes, almacenamiento de sesión, alarmas de reconexión y mensajería nativa. El canal nativo recibe únicamente las confirmaciones; no recibe las URL de las pestañas.

Las reglas y confirmaciones temporales se guardan en `instance/chrome/`; la política del servidor está en `instance/launcher/<sesión>/chrome-policy.json`. Son archivos de ejecución excluidos de Git. La dirección original queda en el fragmento de la página local de bloqueo para poder recargarla; no se exporta al host.

El alcance es el perfil de Chrome donde instalas la extensión. Instálala en cada perfil que uses. El modo incógnito está deshabilitado para esta extensión. No controla otros navegadores, otras aplicaciones, extensiones deshabilitadas, IP directas ni dominios alternativos no incluidos en las reglas. La capa DNS sigue necesitando el DNS del sistema: DoH/VPN/proxy pueden eludirla, aunque no evitan por sí solos las reglas de la extensión habilitada en ese perfil.

Las consultas detenidas por Chrome pueden no llegar al DNS y no aparecer como **DNS real** en el panel. Para verificar esa capa utiliza `check_dns.py`; la pantalla de bloqueo verifica la capa de navegador. La recarga no puede garantizar que un sitio externo esté disponible, ni reproduce formularios POST o cambios sin guardar de una página apartada.

Para desinstalar, detén primero la protección, retira la extensión en `chrome://extensions` y ejecuta:

```powershell
.\.venv\Scripts\python.exe install_chrome.py --uninstall
```

Referencias de implementación: [Native Messaging](https://developer.chrome.com/docs/extensions/develop/concepts/native-messaging), [reglas de solicitudes](https://developer.chrome.com/docs/extensions/reference/api/declarativeNetRequest) y [ciclo de vida del service worker](https://developer.chrome.com/docs/extensions/develop/concepts/service-workers/lifecycle).
