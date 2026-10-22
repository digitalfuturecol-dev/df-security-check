=== DF Security Check ===
Contributors: digitalfuture
Tags: security, php, vulnerabilities, report, cve
Requires at least: 6.2
Tested up to: 7.1
Requires PHP: 7.4
Stable tag: 1.1.2
License: GPLv2 or later

Diagnóstico de seguridad del sitio con recomendación de actualización de PHP y reporte de estado en el idioma del sitio.

== Description ==

DF Security Check, de Digital Future, revisa el estado de seguridad del sitio y genera un reporte claro para el dueño del sitio o para la agencia que lo mantiene.

Qué revisa:

* Versión de PHP frente a vulnerabilidades conocidas, incluidas CVE-2026-109618 y CVE-2026-109619 (php2shell), y el lanzamiento de seguridad de septiembre de 2026.
* Soporte de la rama de PHP (fin de vida) y última versión publicada en php.net.
* Configuración de PHP: session.upload_progress, post_max_size, manejador (mod_php, FPM, LiteSpeed), allow_url_include, display_errors, expose_php.
* WordPress: núcleo, plugins y temas con actualizaciones pendientes, plugins inactivos, HTTPS, editor de archivos, WP_DEBUG, usuario "admin" y actualizaciones automáticas.

Qué entrega:

* Recomendación concreta de actualización de PHP (versión destino y pasos según el hosting detectado: Hostinger, cPanel, Plesk, WP Engine, Kinsta, SiteGround, Docker o servidor propio).
* Reporte descargable en HTML (se puede imprimir o guardar como PDF desde el navegador) y envío por correo con el reporte adjunto.
* Reportes automáticos semanales o mensuales, y alerta inmediata cuando la verificación diaria encuentra un problema crítico nuevo.
* Prueba en Herramientas > Salud del sitio, widget en el escritorio y aviso en el panel cuando PHP es vulnerable.
* Mitigación temporal de un clic recomendada por php.net (session.upload_progress.enabled = 0 y post_max_size de 32M), escrita en .user.ini o .htaccess según el servidor, con verificación automática y botón para retirarla.

Idioma: el reporte y el panel se generan en el idioma configurado en Ajustes > Generales > Idioma del sitio. Incluye español (todas las variantes: es_CO, es_ES, es_MX…) e inglés. Para agregar otro idioma, copia languages/es.php como languages/{código}.php y traduce los textos.

Datos actualizables: las vulnerabilidades están en data/advisories.json. El plugin descarga la versión publicada en el repositorio del proyecto (como máximo cada 12 horas), la valida campo por campo y la usa si es más reciente, así que los sitios reciben avisos nuevos sin actualizar el plugin. La fecha de los datos aparece al pie del reporte.

Código fuente: https://github.com/digitalfuturecol-dev/df-security-check

Importante: un plugin no puede actualizar PHP en el servidor; eso lo hace el proveedor de hosting o el administrador del servidor. El plugin diagnostica, recomienda, aplica mitigaciones temporales y verifica el resultado.

== Installation ==

1. En WordPress ve a Plugins > Añadir nuevo > Subir plugin y sube df-security-check.zip.
2. Activa el plugin.
3. Abre Herramientas > Chequeo de seguridad.

== Frequently Asked Questions ==

= ¿Envía datos del sitio a algún servidor? =

No. Solo descarga archivos públicos (ver "External services"). Los reportes se envían únicamente a los correos que configures.

= El reporte dice que PHP está afectado pero mi servidor es Ubuntu/Debian/RHEL =

Las distribuciones aplican las correcciones sin cambiar el número de versión. El reporte lo indica y muestra el comando para confirmarlo en el servidor.

= ¿La mitigación hace seguro el sitio? =

No. Reduce el riesgo mientras se actualiza PHP. La única solución completa es actualizar a 8.2.35, 8.3.36, 8.4.27 u 8.5.12 o posterior.

== External services ==

Este plugin se conecta a dos servicios externos. No envía ningún dato del sitio: solo descarga archivos públicos. Ambas conexiones se pueden desactivar en Herramientas > Chequeo de seguridad > Datos en línea.

* php.net (https://www.php.net/releases/): consulta la última versión publicada de la rama de PHP del sitio, como máximo cada 6 horas. Términos: https://www.php.net/license/ · Privacidad: https://www.php.net/privacy.php
* GitHub (https://raw.githubusercontent.com/digitalfuturecol-dev/df-security-check/main/data/advisories.json): descarga los datos de vulnerabilidades actualizados, como máximo cada 12 horas. Términos: https://docs.github.com/site-policy/github-terms/github-terms-of-service · Privacidad: https://docs.github.com/site-policy/privacy-policies/github-general-privacy-statement

== Changelog ==

= 1.1.2 =
* Cada vulnerabilidad del reporte muestra su gravedad (CVSS), la fecha de publicación y un enlace al aviso oficial.
* La mitigación temporal solo se ofrece cuando hay una vulnerabilidad abierta que la tiene.

= 1.1.1 =
* Si los datos incluidos en el plugin estuvieran dañados, ahora se usa correctamente el respaldo seguro.

= 1.1.0 =
* Primera versión pública.
