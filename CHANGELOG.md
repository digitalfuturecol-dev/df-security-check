# Changelog

## 1.1.1 — 2026-10-21

- El código cumple los WordPress Coding Standards (revisión automática en verde).
- Corrección: si los datos incluidos en el plugin estuvieran dañados, ahora se usa correctamente el respaldo seguro.
- Correo de contacto de seguridad en SECURITY.md: develop@digitalfuture.com.co.
- La función `dfsc_t()` pasa a `includes/functions.php`.

## 1.1.0 — 2026-10-21

Primera versión pública.

- Los datos de vulnerabilidades pasan a `data/advisories.json` y se actualizan desde este repositorio (cada 12 horas, con validación estricta) sin necesidad de actualizar el plugin.
- La fecha y el origen de los datos aparecen al pie del reporte.
- Nueva opción **Datos en línea** para desactivar las consultas a php.net y a GitHub.
- Detección de PHP alt-php de CloudLinux (Hostinger y muchos hostings con cPanel).
- Detección de paquetes de Debian, Ubuntu y RHEL, que corrigen sin cambiar el número de versión, con el comando para comprobarlo.
- El adjunto del correo usa un archivo temporal con nombre aleatorio.
- La mitigación ya no deja copias de respaldo en la carpeta pública del sitio.
- Requiere WordPress 6.2 o superior.

## 1.0.0 — 2026-10-21

Versión de prueba interna (probada en producción en digitalfuture.com.co).

- Diagnóstico de PHP frente a CVE-2026-109618 y CVE-2026-109619 (php2shell) y el lanzamiento de seguridad de septiembre de 2026.
- Recomendación de actualización de PHP con pasos según el hosting.
- Verificaciones de configuración de PHP y de WordPress.
- Mitigación temporal de un clic con reversión automática.
- Reporte descargable y por correo, reportes programados, alertas, Salud del sitio y widget.
- Reporte en el idioma del sitio (español e inglés).
