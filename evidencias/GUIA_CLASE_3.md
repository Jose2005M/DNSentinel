# Evidencias de DNSentinel 1.1

Para esta versión usa **INFORME_LANZADOR.md**, **pruebas-lanzador.txt/xml**, **bandit-lanzador.json/txt** y **secretos-lanzador.json**. El SAST actual tiene 8 hallazgos revisados (7 bajos, 1 medio); no reutilices el total de 1.0. Las comprobaciones de UAC y adaptador real requieren pruebas propias en Windows.

Captura selección del adaptador, solicitud de UAC sin datos sensibles, estado Protección activa, dominio bloqueado y consulta DNS real, y estado DNS original restaurado. Comprueba y documenta también el modo automático/fijo antes y después. No publiques el respaldo de red, logs de sesión, tokens, claves o base de datos.

Los siguientes puntos son una referencia histórica de la base 1.0, no el reporte SAST actual:

# Cómo documentar la entrega de DNSentinel 1.0

1. Usa CONTROLES.md para registrar cinco controles con norma, función, archivo y línea del código de esta versión. No reutilices líneas de la versión 0.2.
2. En SAST registra Bandit 1.9.4 y **1 hallazgo**, B104, media severidad. Explica el falso positivo del parser hosts como se documentó en INFORME_FINAL.md. No escribas «0 hallazgos» para esta versión.
3. En revisión de secretos registra detect-secrets y el alcance de archivos examinado. Su reporte no demuestra revisión del historial Git ni de tus datos privados de ejecución.
4. Distingue el análisis estático de la revisión de dependencias: pip-audit reportó cero avisos conocidos para las versiones resueltas; eso no significa que se hayan parchado CVE NIST en el código propio.
5. Ejecuta los comandos del README en tu equipo y captura resultados propios. Las evidencias incluidas corresponden al entorno Linux descrito, no a tu Windows.

Capturas útiles: inicio por HTTPS sin advertencias; dominio de prueba bloqueado por UDP y TCP; excepción permitida; registro con origen «DNS real»; importación con sus contadores; intento de modificación por lector rechazado; auditoría; resultado de pytest y Bandit con su interpretación.

No incluyas contraseñas, cookies, tokens, claves, contenidos de data.key/server-key.pem ni tu base de datos en capturas o GitHub. El formulario de creación de reglas muestra la interfaz; por sí solo no demuestra que la validación del servidor funcione.

Para conclusiones separa «implementado y probado en el paquete» de «configurado y probado en mi equipo». Las pruebas de red de laboratorio y el mantenimiento de listas siguen siendo parte de la operación del proyecto.
