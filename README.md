# DF Security Check

**Diagnóstico de seguridad gratuito y de código abierto para WordPress.** Revisa si la versión de PHP de tu sitio está afectada por vulnerabilidades conocidas, te dice exactamente a qué versión actualizar y cómo hacerlo en tu hosting, y genera un reporte de estado en el idioma de tu sitio.

Creado por [Digital Future](https://digitalfuture.com.co) (Bogotá, Colombia) a raíz de **php2shell** ([CVE-2026-109618](https://www.php.net/archive/2026.php) y CVE-2026-109619), dos vulnerabilidades críticas de ejecución remota de código en PHP publicadas el 21 de octubre de 2026.

[English below](#english)

---

## Qué hace

- **PHP frente a vulnerabilidades conocidas:** compara la versión de PHP con los avisos de seguridad oficiales e indica si está afectada, corregida o en una rama que ya no recibe correcciones.
- **Recomendación de actualización:** versión destino concreta y pasos según el hosting detectado (Hostinger, cPanel, Plesk, WP Engine, Kinsta, SiteGround, Docker o servidor propio). Distingue los paquetes de Debian, Ubuntu y RHEL, que corrigen sin cambiar el número de versión.
- **Configuración del servidor:** `session.upload_progress`, `post_max_size`, manejador de PHP, `allow_url_include`, `display_errors` y `expose_php`.
- **WordPress:** núcleo, plugins y temas con actualizaciones pendientes, plugins inactivos, HTTPS, editor de archivos, `WP_DEBUG`, usuario `admin` y actualizaciones automáticas.
- **Mitigación temporal de un clic:** aplica la recomendación de php.net (`session.upload_progress.enabled = 0`) en `.user.ini` o `.htaccess` según el servidor. Comprueba que el sitio siga respondiendo, deshace el cambio si algo falla y se retira con otro clic. **No reemplaza la actualización de PHP.**
- **Reportes:** descarga en HTML (se puede guardar como PDF), envío por correo, reportes semanales o mensuales y alerta cuando aparece un problema crítico nuevo.
- **Integración:** prueba en *Salud del sitio*, widget en el escritorio y aviso en el panel cuando PHP es vulnerable.
- **Idiomas:** el reporte se genera en el idioma del sitio. Incluye español e inglés.

## Instalación

1. Descarga `df-security-check.zip` de la [última versión publicada](../../releases/latest).
2. En WordPress: **Plugins → Añadir nuevo → Subir plugin**, sube el .zip y actívalo.
3. Abre **Herramientas → Chequeo de seguridad**.

Requisitos: WordPress 6.2 o superior y PHP 7.4 o superior.

## Privacidad y conexiones externas

El plugin **no envía ninguna información de tu sitio a ningún servidor**. Solo descarga archivos públicos:

| Servicio | Para qué | Cuándo |
|---|---|---|
| `www.php.net/releases` | Última versión publicada de cada rama de PHP | Como máximo cada 6 horas |
| `raw.githubusercontent.com/digitalfuturecol-dev/df-security-check` | Datos de vulnerabilidades actualizados ([`data/advisories.json`](data/advisories.json)) | Como máximo cada 12 horas |

Puedes desactivar ambas consultas en **Herramientas → Chequeo de seguridad → Datos en línea**, o con código:

```php
add_filter( 'dfsc_data_url', '__return_empty_string' );
```

Los datos descargados se validan campo por campo antes de usarse. Si están dañados, son más antiguos que los incluidos en el plugin o no se pueden descargar, se usan los datos incluidos.

## Cómo se mantienen los datos

Las vulnerabilidades están en [`data/advisories.json`](data/advisories.json). Cuando PHP publica un aviso de seguridad, actualizamos ese archivo y **todos los sitios lo reciben en menos de 12 horas, sin actualizar el plugin**. La fecha de los datos aparece al pie de cada reporte.

¿Ves un aviso que falta o un dato incorrecto? [Abre un issue](../../issues/new/choose) o envía un pull request; [CONTRIBUTING.md](CONTRIBUTING.md) explica el formato.

## Lo que este plugin no hace

- **No actualiza PHP.** Eso lo hace tu proveedor de hosting o el administrador del servidor. El plugin te dice qué hacer y verifica el resultado.
- **No es una auditoría completa** ni un firewall. No analiza código malicioso ni vulnerabilidades de plugins específicos.

## Seguridad

Si encuentras una vulnerabilidad en el plugin, **no abras un issue público**. Sigue las instrucciones de [SECURITY.md](SECURITY.md).

## ¿Necesitas ayuda para actualizar?

El plugin es gratuito y lo seguirá siendo. Si prefieres que alguien actualice PHP, aplique los parches y mantenga tu sitio, en [Digital Future](https://digitalfuture.com.co) ofrecemos ese servicio.

## Licencia

[GPL-2.0-or-later](LICENSE), como WordPress. Se distribuye sin garantía de ningún tipo.

---

<a id="english"></a>

## English

**Free, open-source security check for WordPress.** It tells you whether your site's PHP version is affected by known vulnerabilities, which version to update to and how to do it on your hosting, and produces a status report in your site's language.

Built by [Digital Future](https://digitalfuture.com.co) in response to **php2shell** (CVE-2026-109618 and CVE-2026-109619), two critical remote code execution vulnerabilities in PHP published on October 21, 2026.

**Features:** PHP version vs. known advisories and branch end-of-life · concrete update recommendation with steps for the detected hosting (Hostinger, cPanel, Plesk, WP Engine, Kinsta, SiteGround, Docker, own server), aware of Debian/Ubuntu/RHEL backports · PHP configuration and WordPress hardening checks · one-click temporary mitigation recommended by php.net, with automatic rollback · downloadable/emailed reports, weekly or monthly schedule, critical alerts · Site Health test and dashboard widget · reports in the site's language (English and Spanish included).

**Install:** download `df-security-check.zip` from the [latest release](../../releases/latest), upload it in **Plugins → Add New → Upload Plugin**, activate, and open **Tools → Security Check**. Requires WordPress 6.2+ and PHP 7.4+.

**Privacy:** no data about your site is ever sent anywhere. The plugin only downloads public files from php.net (latest PHP releases) and from this repository (vulnerability data, [`data/advisories.json`](data/advisories.json)). Both can be turned off under **Online data** in the settings. Downloaded data is strictly validated; if anything looks wrong, the bundled data is used.

**Limits:** the plugin cannot upgrade PHP (your host does that) and is not a full security audit or firewall.

**Security issues:** please follow [SECURITY.md](SECURITY.md) instead of opening a public issue.

**Contributing:** see [CONTRIBUTING.md](CONTRIBUTING.md). New translations are welcome: copy `languages/es.php` to `languages/{code}.php`.

**License:** [GPL-2.0-or-later](LICENSE). Provided without warranty.
