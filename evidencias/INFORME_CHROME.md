# Integración Chrome 1.2 — 10 de noviembre de 2026

Se añadió una extensión Manifest V3 sincronizada con el lanzador mediante Native Messaging. Usa revisiones por ciclo, confirmaciones recientes, sustitución atómica de reglas de sesión y comprobación de pestañas abiertas y navegaciones. La desactivación restaura primero el DNS y después retira reglas y recarga las pestañas. Los fallos de Chrome se muestran sin anunciar protección activa.

## Validación

- Python/pytest en Windows: **69 pruebas aprobadas**, incluidas pruebas del protocolo nativo por tuberías reales, lecturas fragmentadas, expiración de estados, confirmaciones viejas/erróneas, exclusión de un segundo lanzador, tres ciclos del controlador y actualización de políticas. También se mantienen las pruebas del servidor, TLS y restauración DNS con adaptador simulado.
- Node: cuatro pruebas de política, prioridad de excepciones, dominios exactos/subdominios, punycode, punto final, credenciales, agrupación de 5.000 dominios y ciclo del service worker con API simulada.
- Chromium 151 de pruebas, perfil aislado: tres ciclos completos con la extensión y `declarativeNetRequest` reales. Se comprobaron páginas abiertas, caché y service worker del sitio, excepción de permiso, solicitudes bloqueadas desde otra pestaña, navegación nueva, desconexión y recarga al permitir. El canal nativo se simula **solo en esta prueba de navegador**; su protocolo real se prueba por separado en Python.
- Capturas de la pantalla local de bloqueo inspeccionadas a 1280 × 800 y 375 × 740, sin desbordamiento horizontal. Detector de interfaz sin hallazgos.
- Bandit sobre la integración, el lanzador y sus dependencias locales: cero hallazgos medios/altos; cinco avisos bajos sobre el uso ya existente de `subprocess`, sin shell y con argumentos separados.

Comandos reproducibles:

```powershell
.\.venv\Scripts\python.exe -m pytest -q
node --test tests/test_chrome_extension.mjs
# Requiere Playwright instalado y Chromium con soporte para cargar extensiones.
node tests/chrome_browser_smoke.cjs
.\.venv\Scripts\python.exe -m bandit -q -r desktop chrome_native.py install_chrome.py launcher.py run.py
```

`PLAYWRIGHT_MODULE` permite indicar la carpeta del módulo Playwright y `CHROMIUM_EXECUTABLE` un ejecutable de Chromium de pruebas. Los perfiles y capturas se crean únicamente bajo `instance/chrome-smoke-*`, excluido de Git.

No se cambió el DNS del adaptador real, no se ejecutó UAC ni se instaló la extensión en el perfil personal. El registro del host y la carga de la extensión en ese perfil se realizan una sola vez con los pasos de [CHROME.md](../CHROME.md). La prueba conjunta del registro de Windows, Native Messaging y el Chrome personal queda como comprobación de instalación.
