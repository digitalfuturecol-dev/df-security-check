<?php
/**
 * Verificaciones de seguridad: PHP, configuración del servidor y WordPress.
 *
 * @package DF_Security_Check
 */

defined( 'ABSPATH' ) || exit;

/**
 * Ejecuta las verificaciones y arma la recomendación de actualización de PHP.
 */
class DFSC_Checks {

	/**
	 * Días antes del fin de soporte en los que se recomienda cambiar de rama.
	 */
	const EOL_WARNING_DAYS = 180;

	/**
	 * Ejecuta todas las verificaciones y devuelve el resultado completo.
	 *
	 * @param bool $force Ignora las cachés de datos remotos.
	 * @return array
	 */
	public static function run( $force = false ) {
		$version    = DFSC_Advisories::runtime_version();
		$advisories = DFSC_Advisories::evaluate( $version );
		$vulnerable = false;
		$mitigable  = false;
		foreach ( $advisories as $adv ) {
			if ( 'patched' === $adv['status'] ) {
				continue;
			}
			if ( 'critical' === $adv['severity'] ) {
				$vulnerable = true;
			}
			if ( $adv['mitigation'] ) {
				$mitigable = true;
			}
		}

		$checks = array_merge(
			self::php_checks( $version, $advisories, $force ),
			self::config_checks( $mitigable ),
			self::wordpress_checks()
		);

		$counts = array(
			'critical' => 0,
			'warning'  => 0,
			'good'     => 0,
			'info'     => 0,
		);
		foreach ( $checks as $c ) {
			++$counts[ $c['status'] ];
		}

		if ( $counts['critical'] > 0 ) {
			$overall = 'critical';
		} elseif ( $counts['warning'] > 0 ) {
			$overall = 'warning';
		} else {
			$overall = 'good';
		}

		return array(
			'generated'      => time(),
			'overall'        => $overall,
			'counts'         => $counts,
			'php_vulnerable' => $vulnerable,
			'mitigable'      => $mitigable,
			'recommendation' => self::php_recommendation( $version, $advisories, $force ),
			'checks'         => $checks,
			'environment'    => self::environment(),
			'mitigation'     => DFSC_Mitigation::status(),
		);
	}

	/**
	 * Verificaciones de PHP: soporte de la rama, avisos conocidos y última versión.
	 *
	 * @param string $version    Versión de PHP.
	 * @param array  $advisories Avisos evaluados.
	 * @param bool   $force      Ignora la caché de php.net.
	 * @return array
	 */
	private static function php_checks( $version, $advisories, $force ) {
		$branch = DFSC_Advisories::runtime_branch();
		$eol    = DFSC_Advisories::eol_dates();
		$checks = array();
		$distro = DFSC_Advisories::is_distro_build();
		$label  = dfsc_t( 'PHP branch support' );
		$value  = 'PHP ' . $branch;

		// Soporte de la rama.
		if ( isset( $eol[ $branch ] ) ) {
			$date = DFSC_I18n::date( $eol[ $branch ] );
			$days = (int) floor( ( strtotime( $eol[ $branch ] ) - time() ) / DAY_IN_SECONDS );
			if ( $days < 0 ) {
				$detail   = dfsc_t( 'PHP %1$s stopped receiving security updates on %2$s. It will not get fixes for new vulnerabilities.', $branch, $date );
				$checks[] = self::item( 'php_branch', 'php', $label, 'critical', $value, $detail );
			} elseif ( $days <= self::EOL_WARNING_DAYS ) {
				$detail   = dfsc_t( 'PHP %1$s stops receiving security updates on %2$s (%3$d days). Plan the move to a newer branch.', $branch, $date, $days );
				$checks[] = self::item( 'php_branch', 'php', $label, 'warning', $value, $detail );
			} else {
				$detail   = dfsc_t( 'PHP %1$s receives security updates until %2$s.', $branch, $date );
				$checks[] = self::item( 'php_branch', 'php', $label, 'good', $value, $detail );
			}
		} elseif ( version_compare( $branch, '5.6', '<' ) ) {
			$checks[] = self::item( 'php_branch', 'php', $label, 'critical', $value, dfsc_t( 'This PHP version has been unsupported for many years.' ) );
		} else {
			$checks[] = self::item( 'php_branch', 'php', $label, 'info', $value, dfsc_t( 'This branch is newer than the data in this plugin. Check php.net for its support dates.' ) );
		}

		// Vulnerabilidades conocidas.
		foreach ( $advisories as $adv ) {
			$label = DFSC_Advisories::text( $adv, 'title' ) . ' (' . implode( ', ', $adv['cves'] ) . ')';
			$facts = dfsc_t( 'Published on %s.', DFSC_I18n::date( $adv['date'] ) );
			if ( '' !== $adv['cvss'] ) {
				$facts = $adv['cvss'] . '. ' . $facts;
			}
			if ( 'patched' === $adv['status'] ) {
				$checks[] = self::item( 'adv_' . $adv['id'], 'php', $label, 'good', $version, dfsc_t( 'This PHP version includes the fix.' ) . ' ' . $facts, $adv['url'], dfsc_t( 'Official advisory' ) );
				continue;
			}
			$status = 'critical' === $adv['severity'] ? 'critical' : 'warning';
			if ( 'no_fix' === $adv['status'] ) {
				$detail = dfsc_t( 'Affected. PHP %s does not receive an official fix: you must move to a supported branch.', $branch );
			} else {
				$detail = dfsc_t( 'Affected. The fix is in PHP %s.', $adv['fixed_in'] );
			}
			$detail .= ' ' . DFSC_Advisories::text( $adv, 'summary' ) . ' ' . $facts;
			if ( 'no_fix' === $adv['status'] && DFSC_Advisories::is_cloudlinux_alt() ) {
				$detail .= ' ' . dfsc_t( 'This server uses CloudLinux alt-php: CloudLinux or TuxCare may publish their own fix for this branch. Ask your hosting provider, but plan the move to a supported branch anyway.' );
			}
			if ( $distro ) {
				$status  = 'warning';
				$detail .= ' ' . dfsc_t( 'This PHP comes from a distribution package (%s) that may include the fix without changing the version number. Confirm with your hosting provider.', PHP_VERSION );
				$detail .= ' ' . dfsc_t( 'On the server you can check it with: %s', DFSC_Advisories::distro_check_command( $adv['cves'][0] ) );
			}
			$checks[] = self::item( 'adv_' . $adv['id'], 'php', $label, $status, $version, $detail, $adv['url'], dfsc_t( 'Official advisory' ) );
		}

		// Última versión de la rama.
		$label  = dfsc_t( 'Latest PHP release' );
		$latest = DFSC_Advisories::latest_for_branch( $branch, $force );
		if ( $latest && version_compare( $version, $latest, '<' ) ) {
			$detail   = dfsc_t( 'A newer release of this branch is available on php.net (%s).', $latest );
			$checks[] = self::item( 'php_latest', 'php', $label, 'warning', $version . ' → ' . $latest, $detail );
		} elseif ( $latest ) {
			$checks[] = self::item( 'php_latest', 'php', $label, 'good', $version, dfsc_t( 'You are on the latest release of this branch.' ) );
		} else {
			$detail   = dfsc_t( 'Could not reach php.net to check the latest release. The plugin\'s built-in vulnerability data was used.' );
			$checks[] = self::item( 'php_latest', 'php', $label, 'info', $version, $detail );
		}

		return $checks;
	}

	/**
	 * Recomendación concreta de actualización de PHP con pasos según el hosting detectado.
	 *
	 * @param string $version    Versión de PHP.
	 * @param array  $advisories Avisos evaluados para esa versión.
	 * @param bool   $force      Ignora la caché de php.net.
	 * @return array
	 */
	public static function php_recommendation( $version, $advisories, $force = false ) {
		$branch      = implode( '.', array_slice( explode( '.', $version ), 0, 2 ) );
		$eol         = DFSC_Advisories::eol_dates();
		$recommended = DFSC_Advisories::recommended_branch();

		$branch_ok = isset( $eol[ $branch ] )
			&& ( strtotime( $eol[ $branch ] ) - time() ) > self::EOL_WARNING_DAYS * DAY_IN_SECONDS;
		if ( ! isset( $eol[ $branch ] ) && version_compare( $branch, $recommended, '>' ) ) {
			$branch_ok = true; // Rama más nueva que nuestros datos.
		}

		$target_branch = $branch_ok ? $branch : $recommended;
		$target        = self::min_safe_version( $target_branch );
		$latest        = DFSC_Advisories::latest_for_branch( $target_branch, $force );
		if ( $latest && ( ! $target || version_compare( $latest, $target, '>' ) ) ) {
			$target = $latest;
		}

		$needed = ! $target || version_compare( $version, $target, '<' ) || ! $branch_ok;

		if ( ! $needed ) {
			return array(
				'needed'  => false,
				'urgency' => 'none',
				'message' => dfsc_t( 'No PHP update is needed. PHP %s includes all known security fixes.', $version ),
				'steps'   => array(),
				'hosting' => self::detect_hosting(),
			);
		}

		$urgent = false;
		foreach ( $advisories as $adv ) {
			if ( 'patched' !== $adv['status'] && 'critical' === $adv['severity'] ) {
				$urgent = true;
			}
		}

		$hosting = self::detect_hosting();
		if ( $branch_ok && DFSC_Advisories::is_distro_build() ) {
			$message = dfsc_t( 'Install the latest security updates for your distribution\'s PHP %1$s packages. The version may still show %2$s, but the package must include the fixes (official equivalent: PHP %3$s).', $branch, $version, $target );
		} elseif ( $branch_ok ) {
			$message = dfsc_t( 'Update PHP from %1$s to %2$s (same branch, no compatibility changes expected).', $version, $target );
		} else {
			$message = dfsc_t( 'Move PHP from %1$s to the %2$s branch (version %3$s or later). Branch %4$s does not receive security fixes or will stop soon.', $version, $target_branch, $target, $branch );
		}

		return array(
			'needed'  => true,
			'urgency' => $urgent ? 'urgent' : 'recommended',
			'message' => $message,
			'steps'   => self::update_steps( $hosting, $target_branch, $target, $branch_ok ),
			'hosting' => $hosting,
		);
	}

	/**
	 * Versión mínima de una rama que incluye todas las correcciones conocidas.
	 *
	 * @param string $branch Rama, p. ej. 8.4.
	 * @return string|null
	 */
	private static function min_safe_version( $branch ) {
		$min = null;
		foreach ( DFSC_Advisories::list_advisories() as $adv ) {
			if ( isset( $adv['fixed'][ $branch ] ) && ( ! $min || version_compare( $adv['fixed'][ $branch ], $min, '>' ) ) ) {
				$min = $adv['fixed'][ $branch ];
			}
		}
		return $min;
	}

	/**
	 * Detecta el tipo de hosting a partir de rutas, constantes y variables del servidor.
	 *
	 * @return array Claves 'id' y 'name'.
	 */
	public static function detect_hosting() {
		$path   = wp_normalize_path( ABSPATH );
		$server = isset( $_SERVER['SERVER_SOFTWARE'] ) ? sanitize_text_field( wp_unslash( $_SERVER['SERVER_SOFTWARE'] ) ) : '';

		if ( preg_match( '#/home/u\d+/domains/#', $path ) || false !== stripos( (string) gethostname(), 'hostinger' ) ) {
			return self::host( 'hostinger', 'Hostinger (hPanel)' );
		}
		if ( defined( 'WPE_APIKEY' ) || function_exists( 'is_wpe' ) ) {
			return self::host( 'managed', 'WP Engine' );
		}
		if ( defined( 'KINSTAMU_VERSION' ) ) {
			return self::host( 'managed', 'Kinsta' );
		}
		if ( false !== strpos( $path, '/home/customer/www/' ) ) {
			return self::host( 'managed', 'SiteGround' );
		}
		if ( false !== strpos( $path, '/var/www/vhosts/' ) ) {
			return self::host( 'plesk', 'Plesk' );
		}
		if ( preg_match( '#^/home\d*/[^/]+/public_html#', $path ) || @is_dir( '/usr/local/cpanel' ) ) { // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- open_basedir puede impedir la consulta.
			return self::host( 'cpanel', 'cPanel' );
		}
		if ( file_exists( '/.dockerenv' ) ) {
			return self::host( 'docker', 'Docker' );
		}
		return self::host( 'server', $server ? $server : dfsc_t( 'Own server / VPS' ) );
	}

	/**
	 * Arma la descripción de un hosting.
	 *
	 * @param string $id   Identificador interno.
	 * @param string $name Nombre visible.
	 * @return array
	 */
	private static function host( $id, $name ) {
		return array(
			'id'   => $id,
			'name' => $name,
		);
	}

	/**
	 * Pasos para actualizar PHP según el hosting.
	 *
	 * @param array  $hosting       Hosting detectado.
	 * @param string $target_branch Rama destino.
	 * @param string $target        Versión destino.
	 * @param bool   $same_branch   Si la actualización es dentro de la misma rama.
	 * @return array
	 */
	private static function update_steps( $hosting, $target_branch, $target, $same_branch ) {
		$steps = array();
		$b     = $target_branch;
		$nodot = str_replace( '.', '', $b );

		switch ( $hosting['id'] ) {
			case 'hostinger':
				$steps[] = dfsc_t( 'Open hPanel and go to Websites → Manage for this site.' );
				$steps[] = dfsc_t( 'In the side menu open Advanced → PHP Configuration.' );
				if ( $same_branch ) {
					$steps[] = dfsc_t( 'Confirm that PHP %1$s is selected. Hostinger installs patch releases on its servers; if this report still shows an older version, contact Hostinger support and ask when PHP %2$s will be applied.', $b, $target );
				} else {
					$steps[] = dfsc_t( 'In the PHP versions tab choose PHP %s and click Update.', $b );
				}
				break;
			case 'cpanel':
				$steps[] = dfsc_t( 'Log in to cPanel and open Software → MultiPHP Manager (on CloudLinux servers: Select PHP Version).' );
				$steps[] = dfsc_t( 'Select this domain, choose ea-php%1$s (PHP %2$s) and click Apply.', $nodot, $b );
				$steps[] = dfsc_t( 'Patch releases within a branch are installed by the hosting provider. If the version shown is still lower than %s, open a ticket with your provider.', $target );
				break;
			case 'plesk':
				$steps[] = dfsc_t( 'In Plesk open Websites & Domains → this domain → PHP.' );
				$steps[] = dfsc_t( 'Choose PHP %s in "PHP version" and click Apply.', $b );
				$steps[] = dfsc_t( 'If the version shown is still lower than %s, ask the server administrator to update the PHP packages.', $target );
				break;
			case 'managed':
				$steps[] = dfsc_t( 'Open your %s control panel and go to the PHP version settings for this site.', $hosting['name'] );
				$steps[] = dfsc_t( 'Choose PHP %s. Patch releases are applied by the provider; if this report still shows an older version, contact their support.', $b );
				break;
			case 'docker':
				$steps[] = dfsc_t( 'Update the base image to php:%s (or the matching -fpm / -apache variant) and rebuild the container.', $target );
				$steps[] = dfsc_t( 'Redeploy and confirm the new version in this report.' );
				break;
			default:
				$steps[] = dfsc_t( 'Debian/Ubuntu: sudo apt update && sudo apt install --only-upgrade "php%s*" (packages from ppa:ondrej/php or packages.sury.org get new releases first).', $b );
				$steps[] = dfsc_t( 'RHEL/AlmaLinux/Rocky: sudo dnf upgrade "php*" (Remi repository: dnf module switch-to php:remi-%s).', $b );
				$steps[] = dfsc_t( 'Restart PHP-FPM and the web server (for example: sudo systemctl restart php%s-fpm).', $b );
				break;
		}

		$steps[] = dfsc_t( 'Make a full backup (files and database) before changing the version.' );
		if ( ! $same_branch ) {
			$steps[] = dfsc_t( 'After the change, review the home page, forms, checkout and the admin area. Update plugins and themes first: old versions may not be compatible with PHP %s.', $b );
		}
		$steps[] = dfsc_t( 'Run this report again to confirm the result.' );

		return $steps;
	}

	/**
	 * Verificaciones de la configuración de PHP.
	 *
	 * @param bool $vulnerable Si PHP está afectado por un aviso abierto que admite la mitigación temporal.
	 * @return array
	 */
	private static function config_checks( $vulnerable ) {
		$checks   = array();
		$sapi     = php_sapi_name();
		$progress = self::ini_bool( 'session.upload_progress.enabled' );
		$key      = 'session.upload_progress.enabled';

		if ( $vulnerable && $progress ) {
			$detail   = dfsc_t( 'Recommended temporary mitigation for CVE-2026-109619: turn it off until PHP is updated. It does not make the site safe on its own. You can apply it with the "Apply mitigation" button.' );
			$checks[] = self::item( 'upload_progress', 'config', $key, 'critical', 'On', $detail );
		} elseif ( $vulnerable ) {
			$checks[] = self::item( 'upload_progress', 'config', $key, 'good', 'Off', dfsc_t( 'The temporary mitigation is active. PHP still needs to be updated.' ) );
		} else {
			$checks[] = self::item( 'upload_progress', 'config', $key, 'info', $progress ? 'On' : 'Off', dfsc_t( 'Not a risk with the current PHP version.' ) );
		}

		$post_max = wp_convert_hr_to_bytes( (string) ini_get( 'post_max_size' ) );
		if ( $vulnerable && ( 0 === $post_max || $post_max > 32 * MB_IN_BYTES ) ) {
			$detail   = dfsc_t( 'PHP recommends 8M (or 32M if the site needs uploads) while the vulnerability is not patched.' );
			$checks[] = self::item( 'post_max_size', 'config', 'post_max_size', 'warning', (string) ini_get( 'post_max_size' ), $detail );
		}

		if ( $vulnerable && 'apache2handler' === $sapi ) {
			$detail   = dfsc_t( 'mod_php has the highest risk for CVE-2026-109618. Prioritize the update of this server.' );
			$checks[] = self::item( 'sapi', 'config', dfsc_t( 'PHP handler' ), 'warning', 'mod_php', $detail );
		} else {
			$checks[] = self::item( 'sapi', 'config', dfsc_t( 'PHP handler' ), 'info', $sapi, '' );
		}

		if ( self::ini_bool( 'allow_url_include' ) ) {
			$checks[] = self::item( 'allow_url_include', 'config', 'allow_url_include', 'critical', 'On', dfsc_t( 'Allows including remote code. It must be turned off.' ) );
		}

		if ( self::ini_bool( 'display_errors' ) ) {
			$detail   = dfsc_t( 'Errors are shown to visitors and can reveal paths and versions. Turn it off in production.' );
			$checks[] = self::item( 'display_errors', 'config', 'display_errors', 'warning', 'On', $detail );
		} else {
			$checks[] = self::item( 'display_errors', 'config', 'display_errors', 'good', 'Off', '' );
		}

		if ( self::ini_bool( 'expose_php' ) ) {
			$detail   = dfsc_t( 'The server announces the PHP version in the X-Powered-By header, which helps attackers find vulnerable sites.' );
			$checks[] = self::item( 'expose_php', 'config', 'expose_php', 'warning', 'On', $detail );
		} else {
			$checks[] = self::item( 'expose_php', 'config', 'expose_php', 'good', 'Off', '' );
		}

		return $checks;
	}

	/**
	 * Lee una directiva booleana de php.ini.
	 *
	 * @param string $key Directiva.
	 * @return bool
	 */
	private static function ini_bool( $key ) {
		$v = strtolower( (string) ini_get( $key ) );
		return in_array( $v, array( '1', 'on', 'true', 'yes' ), true );
	}

	/**
	 * Verificaciones de WordPress: actualizaciones y ajustes de seguridad.
	 *
	 * @return array
	 */
	private static function wordpress_checks() {
		require_once ABSPATH . 'wp-admin/includes/update.php';
		require_once ABSPATH . 'wp-admin/includes/plugin.php';
		require_once ABSPATH . 'wp-admin/includes/theme.php';

		$checks = array();
		$wp_ver = get_bloginfo( 'version' );

		// Núcleo.
		$core = function_exists( 'get_core_updates' ) ? get_core_updates() : array();
		$new  = null;
		if ( is_array( $core ) ) {
			foreach ( $core as $u ) {
				if ( isset( $u->response ) && 'upgrade' === $u->response ) {
					$new = $u->current;
					break;
				}
			}
		}
		$label = dfsc_t( 'WordPress core' );
		if ( $new ) {
			$checks[] = self::item( 'wp_core', 'wp', $label, 'warning', $wp_ver . ' → ' . $new, dfsc_t( 'A WordPress update is available.' ), admin_url( 'update-core.php' ) );
		} else {
			$checks[] = self::item( 'wp_core', 'wp', $label, 'good', $wp_ver, dfsc_t( 'WordPress is up to date.' ) );
		}

		// Plugins.
		$plugins     = get_plugins();
		$upd_plugins = get_site_transient( 'update_plugins' );
		$pending     = array();
		if ( isset( $upd_plugins->response ) && is_array( $upd_plugins->response ) ) {
			foreach ( $upd_plugins->response as $file => $data ) {
				if ( isset( $plugins[ $file ] ) ) {
					$pending[] = $plugins[ $file ]['Name'] . ' (' . $plugins[ $file ]['Version'] . ' → ' . $data->new_version . ')';
				}
			}
		}
		$label = dfsc_t( 'Plugin updates' );
		if ( $pending ) {
			$detail   = dfsc_t( 'Plugins with pending updates: %s.', implode( '; ', $pending ) );
			$checks[] = self::item( 'wp_plugins', 'wp', $label, 'warning', (string) count( $pending ), $detail, admin_url( 'plugins.php?plugin_status=upgrade' ) );
		} else {
			$checks[] = self::item( 'wp_plugins', 'wp', $label, 'good', '0', dfsc_t( 'All plugins are up to date.' ) );
		}

		$inactive = array();
		foreach ( $plugins as $file => $p ) {
			if ( ! is_plugin_active( $file ) ) {
				$inactive[] = $p['Name'];
			}
		}
		if ( $inactive ) {
			$detail   = dfsc_t( 'Inactive plugins still contain code that can be attacked. Delete the ones you do not use: %s.', implode( ', ', $inactive ) );
			$checks[] = self::item( 'wp_inactive', 'wp', dfsc_t( 'Inactive plugins' ), 'info', (string) count( $inactive ), $detail, admin_url( 'plugins.php?plugin_status=inactive' ) );
		}

		// Temas.
		$themes     = wp_get_themes();
		$upd_themes = get_site_transient( 'update_themes' );
		$pending_t  = array();
		if ( isset( $upd_themes->response ) && is_array( $upd_themes->response ) ) {
			foreach ( $upd_themes->response as $slug => $data ) {
				if ( isset( $themes[ $slug ] ) ) {
					$pending_t[] = $themes[ $slug ]->get( 'Name' ) . ' (' . $themes[ $slug ]->get( 'Version' ) . ' → ' . $data['new_version'] . ')';
				}
			}
		}
		$label = dfsc_t( 'Theme updates' );
		if ( $pending_t ) {
			$detail   = dfsc_t( 'Themes with pending updates: %s.', implode( '; ', $pending_t ) );
			$checks[] = self::item( 'wp_themes', 'wp', $label, 'warning', (string) count( $pending_t ), $detail, admin_url( 'themes.php' ) );
		} else {
			$checks[] = self::item( 'wp_themes', 'wp', $label, 'good', '0', dfsc_t( 'All themes are up to date.' ) );
		}

		// HTTPS.
		if ( 'https' === wp_parse_url( home_url(), PHP_URL_SCHEME ) ) {
			$checks[] = self::item( 'https', 'wp', 'HTTPS', 'good', dfsc_t( 'Active' ), '' );
		} else {
			$detail   = dfsc_t( 'The site address does not use HTTPS. Passwords and customer data travel unencrypted.' );
			$checks[] = self::item( 'https', 'wp', 'HTTPS', 'critical', dfsc_t( 'Inactive' ), $detail );
		}

		// Editor de archivos.
		$label = dfsc_t( 'Theme and plugin file editor' );
		if ( defined( 'DISALLOW_FILE_EDIT' ) && DISALLOW_FILE_EDIT ) {
			$checks[] = self::item( 'file_edit', 'wp', $label, 'good', dfsc_t( 'Disabled' ), '' );
		} else {
			$detail   = dfsc_t( 'If an administrator account is compromised, the editor lets the attacker run code. Add define( \'DISALLOW_FILE_EDIT\', true ); to wp-config.php.' );
			$checks[] = self::item( 'file_edit', 'wp', $label, 'warning', dfsc_t( 'Enabled' ), $detail );
		}

		// Depuración visible.
		if ( defined( 'WP_DEBUG' ) && WP_DEBUG && ( ! defined( 'WP_DEBUG_DISPLAY' ) || WP_DEBUG_DISPLAY ) ) {
			$checks[] = self::item( 'wp_debug', 'wp', 'WP_DEBUG', 'warning', 'On', dfsc_t( 'Debug mode shows errors to visitors. Turn it off in production.' ) );
		}

		// Usuario "admin".
		$admin_user = get_user_by( 'login', 'admin' );
		if ( $admin_user && user_can( $admin_user, 'manage_options' ) ) {
			$detail   = dfsc_t( 'It is the first username attackers try. Create a new administrator with another name and delete this one.' );
			$checks[] = self::item( 'admin_user', 'wp', dfsc_t( 'Administrator named "admin"' ), 'warning', 'admin', $detail );
		}

		// Actualizaciones automáticas del núcleo.
		if ( defined( 'AUTOMATIC_UPDATER_DISABLED' ) && AUTOMATIC_UPDATER_DISABLED ) {
			$detail   = dfsc_t( 'AUTOMATIC_UPDATER_DISABLED blocks WordPress security updates.' );
			$checks[] = self::item( 'auto_updates', 'wp', dfsc_t( 'Automatic updates' ), 'warning', dfsc_t( 'Disabled' ), $detail );
		}

		return $checks;
	}

	/**
	 * Datos del entorno para el reporte.
	 *
	 * @return array Etiqueta traducida => valor.
	 */
	public static function environment() {
		$theme   = wp_get_theme();
		$hosting = self::detect_hosting();
		$server  = isset( $_SERVER['SERVER_SOFTWARE'] ) ? sanitize_text_field( wp_unslash( $_SERVER['SERVER_SOFTWARE'] ) ) : '—';
		return array(
			dfsc_t( 'Site' )             => home_url(),
			dfsc_t( 'Site language' )    => get_locale(),
			dfsc_t( 'WordPress' )        => get_bloginfo( 'version' ),
			dfsc_t( 'PHP' )              => PHP_VERSION,
			dfsc_t( 'PHP handler' )      => php_sapi_name(),
			dfsc_t( 'Web server' )       => $server,
			dfsc_t( 'Hosting detected' ) => $hosting['name'],
			dfsc_t( 'Operating system' ) => PHP_OS . ' ' . php_uname( 'r' ),
			dfsc_t( 'Active theme' )     => $theme->get( 'Name' ) . ' ' . $theme->get( 'Version' ),
			dfsc_t( 'Active plugins' )   => (string) count( (array) get_option( 'active_plugins', array() ) ),
			dfsc_t( 'Loaded php.ini' )   => (string) php_ini_loaded_file(),
		);
	}

	/**
	 * Arma el resultado de una verificación.
	 *
	 * @param string $id         Identificador.
	 * @param string $group      Grupo: php, config o wp.
	 * @param string $label      Nombre visible.
	 * @param string $status     critical, warning, good o info.
	 * @param string $value      Valor detectado.
	 * @param string $detail     Explicación.
	 * @param string $link       Enlace opcional.
	 * @param string $link_label Texto del enlace; por defecto "Corregir".
	 * @return array
	 */
	private static function item( $id, $group, $label, $status, $value, $detail, $link = '', $link_label = '' ) {
		return array(
			'id'         => $id,
			'group'      => $group,
			'label'      => $label,
			'status'     => $status,
			'value'      => $value,
			'detail'     => $detail,
			'link'       => $link,
			'link_label' => $link_label,
		);
	}
}
