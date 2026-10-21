# Cómo contribuir

¡Gracias por ayudar! Las contribuciones más útiles son: avisos de seguridad nuevos o corregidos, traducciones y reportes de errores con el reporte generado adjunto (puedes borrar el nombre del sitio).

## Agregar o corregir un aviso de seguridad

Edita [`data/advisories.json`](data/advisories.json) y abre un pull request. Cada aviso tiene esta forma:

```json
{
	"id": "php2shell",
	"cves": [ "CVE-2026-109618", "CVE-2026-109619" ],
	"severity": "critical",
	"cvss": "CVSS v4.0 9.2",
	"date": "2026-10-21",
	"min_affected": "5.4.0",
	"fixed": { "8.2": "8.2.35", "8.3": "8.3.36", "8.4": "8.4.27", "8.5": "8.5.12" },
	"mitigation": true,
	"url": "https://www.php.net/archive/2026.php",
	"title": { "en": "…", "es": "…" },
	"summary": { "en": "…", "es": "…" }
}
```

Reglas (el plugin descarta el aviso completo si alguna no se cumple):

- `id`: minúsculas, números y guiones; único.
- `cves`: formato `CVE-AAAA-NNNN`.
- `severity`: `critical`, `high`, `medium` o `low`. Solo `critical` marca el sitio como crítico.
- `min_affected`: primera versión afectada (`X.Y.Z`).
- `fixed`: primera versión corregida **de cada rama con soporte**. Las ramas anteriores a la más antigua listada se consideran sin corrección oficial.
- `title` y `summary`: texto plano (sin HTML), con `en` obligatorio. Agrega `es` y los idiomas que puedas.
- `url`: `https://` a la fuente oficial.

Además:

- Cambia `updated` a la fecha del día. **Los sitios solo usan el archivo remoto si `updated` es igual o posterior a la de sus datos incluidos.**
- Si cambia el calendario de soporte de PHP, actualiza `eol` y, si corresponde, `recommended_branch`.
- **Fuente obligatoria:** enlaza en el pull request el aviso oficial de php.net o el GitHub Security Advisory de `php/php-src`. No se aceptan datos sin fuente oficial.

La revisión automática valida el JSON en cada pull request.

## Traducciones

Los textos del plugin están en inglés en el código. Para agregar un idioma, copia `languages/es.php` como `languages/{código de dos letras}.php` (por ejemplo `pt.php`) y traduce los valores. Respeta los marcadores `%s`, `%d`, `%1$s`…

## Código

- Sigue los [WordPress Coding Standards](https://developer.wordpress.org/coding-standards/wordpress-coding-standards/php/). La revisión automática ejecuta PHPCS con `phpcs.xml.dist`.
- Compatible con PHP 7.4 a 8.5.
- Escapa toda salida (`esc_html`, `esc_attr`, `esc_url`), verifica nonce y capacidad `manage_options` en toda acción.
- El plugin no debe enviar datos del sitio a ningún servicio.

Para probar los datos: `wp eval-file tests/data-validation-test.php` en un sitio de pruebas con el plugin activo.
