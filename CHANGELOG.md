# Changelog

## 1.1.2 — 2026-10-22

- Cada vulnerabilidad del reporte muestra su gravedad (CVSS), la fecha de publicación y un enlace al aviso oficial.
- La mitigación temporal solo se ofrece cuando hay una vulnerabilidad abierta que la tiene.

## 1.1.1 — 2026-10-21

- Si los datos incluidos en el plugin estuvieran dañados, ahora se usa correctamente el respaldo seguro.

## 1.1.0 — 2026-10-21

Primera versión pública.

- Diagnóstico de PHP frente a vulnerabilidades conocidas, incluidas CVE-2026-109618 y CVE-2026-109619 (php2shell), y frente al fin de soporte de cada rama.
- Recomendación de actualización de PHP con pasos según el hosting detectado, incluida la detección de alt-php de CloudLinux y de los paquetes de Debian, Ubuntu y RHEL.
- Verificaciones de configuración de PHP y de WordPress.
- Mitigación temporal de un clic, con verificación y reversión automática.
- Reporte descargable y por correo, reportes programados, alertas, prueba en Salud del sitio y widget del escritorio.
- Reporte en el idioma del sitio (español e inglés).
- Datos de vulnerabilidades actualizables desde este repositorio, sin necesidad de actualizar el plugin.
- Opción **Datos en línea** para desactivar las consultas a php.net y a GitHub.
