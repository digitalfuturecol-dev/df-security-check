<?php
/**
 * Avisos de seguridad de PHP y consulta de la última versión publicada.
 *
 * Los datos vienen de data/advisories.json, incluido en el plugin. Si existe una versión más
 * reciente en el repositorio público del proyecto, se descarga (cada 12 horas), se valida campo
 * por campo y se usa en su lugar. Así los sitios reciben avisos nuevos sin actualizar el plugin.
 * Para desactivar la consulta remota:
 *     add_filter( 'dfsc_data_url', '__return_empty_string' );
 *
 * @package DF_Security_Check
 */

defined( 'ABSPATH' ) || exit;

/**
 * Datos de vulnerabilidades y versiones de PHP.
 */
class DFSC_Advisories {

	const CACHE_KEY      = 'dfsc_php_latest';
	const CACHE_TTL      = 6 * HOUR_IN_SECONDS;
	const DATA_CACHE_KEY = 'dfsc_remote_data';
	const DATA_TTL       = 12 * HOUR_IN_SECONDS;
	const DATA_URL       = 'https://raw.githubusercontent.com/digitalfuturecol-dev/df-security-check/main/data/advisories.json';
	const MAX_BYTES      = 262144;

	/**
	 * Datos ya validados de la ejecución actual.
	 *
	 * @var array|null
	 */
	private static $data = null;

	/**
	 * Datos vigentes: los remotos si son válidos y más recientes, si no los incluidos en el plugin.
	 *
	 * @param bool $force Ignora la caché de los datos remotos.
	 * @return array
	 */
	public static function data( $force = false ) {
		if ( null !== self::$data && ! $force ) {
			return self::$data;
		}

		$bundled = self::validate( json_decode( (string) file_get_contents( DFSC_DIR . 'data/advisories.json' ), true ) ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents -- archivo local del plugin.
		$data    = $bundled;
		if ( $data ) {
			$data['source'] = 'bundled';
		}

		$remote = self::remote_data( $force );
		if ( $remote && ( ! $bundled || $remote['updated'] >= $bundled['updated'] ) ) {
			$data           = $remote;
			$data['source'] = 'remote';
		}

		if ( ! $data ) {
			// No debería pasar: el archivo incluido está dañado. Se evita un error fatal.
			$data = array(
				'updated'            => '1970-01-01',
				'recommended_branch' => '8.4',
				'eol'                => array(),
				'advisories'         => array(),
				'source'             => 'none',
			);
		}

		self::$data = $data;
		return $data;
	}

	/**
	 * Descarga y valida los datos publicados en el repositorio.
	 *
	 * @param bool $force Ignora la caché.
	 * @return array|null
	 */
	private static function remote_data( $force ) {
		if ( ! self::online_enabled() ) {
			return null;
		}
		$url = (string) apply_filters( 'dfsc_data_url', self::DATA_URL );
		if ( '' === $url || 0 !== strpos( $url, 'https://' ) ) {
			return null;
		}

		$cached = get_site_transient( self::DATA_CACHE_KEY );
		if ( ! $force && false !== $cached ) {
			return is_array( $cached ) ? $cached : null;
		}

		$valid    = null;
		$response = wp_remote_get(
			$url,
			array(
				'timeout'             => 8,
				'limit_response_size' => self::MAX_BYTES,
				'redirection'         => 2,
			)
		);
		if ( ! is_wp_error( $response ) && 200 === wp_remote_retrieve_response_code( $response ) ) {
			$valid = self::validate( json_decode( wp_remote_retrieve_body( $response ), true ) );
		}

		// Se guarda también el fallo ('none') para no reintentar en cada carga de página.
		set_site_transient( self::DATA_CACHE_KEY, $valid ? $valid : 'none', $valid ? self::DATA_TTL : HOUR_IN_SECONDS );
		return $valid;
	}

	/**
	 * Valida la estructura completa. Cualquier campo inválido descarta el aviso o el archivo.
	 * Los textos se tratan como texto plano y se escapan al mostrarlos.
	 *
	 * @param mixed $raw Datos decodificados.
	 * @return array|null
	 */
	public static function validate( $raw ) {
		if ( ! is_array( $raw ) || 1 !== ( isset( $raw['schema'] ) ? $raw['schema'] : 0 ) ) {
			return null;
		}
		$date    = '/^\d{4}-\d{2}-\d{2}$/';
		$branch  = '/^\d{1,2}\.\d{1,2}$/';
		$version = '/^\d{1,2}\.\d{1,2}\.\d{1,3}$/';

		if ( empty( $raw['updated'] ) || ! preg_match( $date, $raw['updated'] )
			|| empty( $raw['recommended_branch'] ) || ! preg_match( $branch, $raw['recommended_branch'] )
			|| empty( $raw['eol'] ) || ! is_array( $raw['eol'] )
			|| ! isset( $raw['advisories'] ) || ! is_array( $raw['advisories'] ) ) {
			return null;
		}

		$eol = array();
		foreach ( $raw['eol'] as $b => $d ) {
			if ( preg_match( $branch, (string) $b ) && is_string( $d ) && preg_match( $date, $d ) ) {
				$eol[ (string) $b ] = $d;
			}
		}

		$advisories = array();
		foreach ( array_slice( $raw['advisories'], 0, 100 ) as $a ) {
			$clean = self::validate_advisory( $a, $date, $branch, $version );
			if ( $clean ) {
				$advisories[] = $clean;
			}
		}

		return array(
			'updated'            => $raw['updated'],
			'recommended_branch' => $raw['recommended_branch'],
			'eol'                => $eol,
			'advisories'         => $advisories,
		);
	}

	/**
	 * Valida un aviso.
	 *
	 * @param mixed  $a       Aviso.
	 * @param string $date    Expresión de fecha.
	 * @param string $branch  Expresión de rama.
	 * @param string $version Expresión de versión.
	 * @return array|null
	 */
	private static function validate_advisory( $a, $date, $branch, $version ) {
		if ( ! is_array( $a ) ) {
			return null;
		}
		$ok = isset( $a['id'], $a['cves'], $a['severity'], $a['date'], $a['min_affected'], $a['fixed'], $a['title'], $a['summary'] )
			&& is_string( $a['id'] ) && preg_match( '/^[a-z0-9-]{1,64}$/', $a['id'] )
			&& is_array( $a['cves'] ) && $a['cves']
			&& in_array( $a['severity'], array( 'critical', 'high', 'medium', 'low' ), true )
			&& is_string( $a['date'] ) && preg_match( $date, $a['date'] )
			&& is_string( $a['min_affected'] ) && preg_match( $version, $a['min_affected'] )
			&& is_array( $a['fixed'] ) && $a['fixed']
			&& is_array( $a['title'] ) && isset( $a['title']['en'] ) && is_string( $a['title']['en'] )
			&& is_array( $a['summary'] ) && isset( $a['summary']['en'] ) && is_string( $a['summary']['en'] );
		if ( ! $ok ) {
			return null;
		}

		$cves = array();
		foreach ( array_slice( $a['cves'], 0, 20 ) as $cve ) {
			if ( ! is_string( $cve ) || ! preg_match( '/^CVE-\d{4}-\d{4,7}$/', $cve ) ) {
				return null;
			}
			$cves[] = $cve;
		}

		$fixed = array();
		foreach ( $a['fixed'] as $b => $v ) {
			if ( ! preg_match( $branch, (string) $b ) || ! is_string( $v ) || ! preg_match( $version, $v ) || 0 !== strpos( $v, $b . '.' ) ) {
				return null;
			}
			$fixed[ (string) $b ] = $v;
		}

		$texts  = array();
		$limits = array(
			'title'   => 200,
			'summary' => 1500,
		);
		foreach ( $limits as $field => $max ) {
			foreach ( $a[ $field ] as $lang => $text ) {
				if ( preg_match( '/^[a-z]{2}$/', (string) $lang ) && is_string( $text ) ) {
					$texts[ $field ][ $lang ] = mb_substr( wp_strip_all_tags( $text ), 0, $max );
				}
			}
		}

		$url = ( isset( $a['url'] ) && is_string( $a['url'] ) ) ? esc_url_raw( $a['url'], array( 'https' ) ) : '';

		return array(
			'id'           => $a['id'],
			'cves'         => $cves,
			'severity'     => $a['severity'],
			'cvss'         => isset( $a['cvss'] ) && is_string( $a['cvss'] ) ? mb_substr( wp_strip_all_tags( $a['cvss'] ), 0, 40 ) : '',
			'date'         => $a['date'],
			'min_affected' => $a['min_affected'],
			'fixed'        => $fixed,
			'mitigation'   => ! empty( $a['mitigation'] ),
			'url'          => $url,
			'title'        => $texts['title'],
			'summary'      => $texts['summary'],
		);
	}

	/**
	 * Indica si el administrador permite las consultas a php.net y al repositorio del proyecto.
	 *
	 * @return bool
	 */
	public static function online_enabled() {
		$s = get_option( 'dfsc_settings', array() );
		return ! is_array( $s ) || ! isset( $s['online'] ) || ! empty( $s['online'] );
	}

	/**
	 * Fin del soporte de seguridad de cada rama.
	 *
	 * @return array
	 */
	public static function eol_dates() {
		$d = self::data();
		return $d['eol'];
	}

	/**
	 * Rama recomendada cuando la actual no tiene soporte.
	 *
	 * @return string
	 */
	public static function recommended_branch() {
		$d = self::data();
		return $d['recommended_branch'];
	}

	/**
	 * Avisos conocidos.
	 *
	 * @return array
	 */
	public static function list_advisories() {
		$d = self::data();
		return $d['advisories'];
	}

	/**
	 * Fecha de actualización de los datos y su origen.
	 *
	 * @return array
	 */
	public static function data_info() {
		$d = self::data();
		return array(
			'updated' => $d['updated'],
			'source'  => $d['source'],
		);
	}

	/**
	 * Texto de un aviso en el idioma del sitio, con inglés como respaldo.
	 *
	 * @param array  $adv   Aviso.
	 * @param string $field 'title' o 'summary'.
	 * @return string
	 */
	public static function text( $adv, $field ) {
		$lang = DFSC_I18n::lang();
		if ( isset( $adv[ $field ][ $lang ] ) ) {
			return $adv[ $field ][ $lang ];
		}
		return isset( $adv[ $field ]['en'] ) ? $adv[ $field ]['en'] : '';
	}

	/**
	 * Versión de PHP en ejecución, sin sufijos de distribución.
	 *
	 * @return string
	 */
	public static function runtime_version() {
		return PHP_MAJOR_VERSION . '.' . PHP_MINOR_VERSION . '.' . PHP_RELEASE_VERSION;
	}

	/**
	 * Rama de PHP en ejecución.
	 *
	 * @return string
	 */
	public static function runtime_branch() {
		return PHP_MAJOR_VERSION . '.' . PHP_MINOR_VERSION;
	}

	/**
	 * Indica si PHP viene de un paquete de distribución (Debian, Ubuntu, RHEL y derivados) que
	 * aplica las correcciones sin cambiar el número de versión.
	 *
	 * @return bool
	 */
	public static function is_distro_build() {
		$extra = defined( 'PHP_EXTRA_VERSION' ) ? PHP_EXTRA_VERSION : '';
		if ( '' !== $extra ) {
			return true;
		}
		$ini = (string) php_ini_loaded_file();
		return (bool) preg_match( '#^/etc/php/\d|^/etc/php\.ini$#', $ini );
	}

	/**
	 * Indica si PHP es una compilación alt-php de CloudLinux (Hostinger, muchos hostings cPanel).
	 * Sigue las versiones oficiales; para ramas sin soporte, CloudLinux/TuxCare puede publicar
	 * correcciones propias.
	 *
	 * @return bool
	 */
	public static function is_cloudlinux_alt() {
		return 0 === strpos( (string) php_ini_loaded_file(), '/opt/alt/php' );
	}

	/**
	 * Comando para confirmar en el servidor si el paquete ya trae la corrección.
	 *
	 * @param string $cve Identificador CVE.
	 * @return string
	 */
	public static function distro_check_command( $cve ) {
		$ini = (string) php_ini_loaded_file();
		if ( 0 === strpos( $ini, '/etc/php/' ) ) {
			return 'apt changelog php' . self::runtime_branch() . '-common | grep ' . $cve;
		}
		return 'rpm -q --changelog php-common | grep ' . $cve;
	}

	/**
	 * Última versión publicada de una rama según php.net (con caché). Null si no hay conexión.
	 *
	 * @param string $branch Rama, p. ej. 8.4.
	 * @param bool   $force  Ignora la caché.
	 * @return string|null
	 */
	public static function latest_for_branch( $branch, $force = false ) {
		if ( ! self::online_enabled() ) {
			return null;
		}
		$cache = get_site_transient( self::CACHE_KEY );
		if ( ! is_array( $cache ) ) {
			$cache = array();
		}
		if ( ! $force && array_key_exists( $branch, $cache ) ) {
			return $cache[ $branch ];
		}

		$response = wp_remote_get(
			'https://www.php.net/releases/index.php?json&version=' . rawurlencode( $branch ),
			array(
				'timeout'             => 8,
				'limit_response_size' => 65536,
			)
		);

		$latest = null;
		if ( ! is_wp_error( $response ) && 200 === wp_remote_retrieve_response_code( $response ) ) {
			$json = json_decode( wp_remote_retrieve_body( $response ), true );
			if ( is_array( $json ) && ! empty( $json['version'] ) && is_string( $json['version'] )
				&& preg_match( '/^\d+\.\d+\.\d+$/', $json['version'] ) && 0 === strpos( $json['version'], $branch . '.' ) ) {
				$latest = $json['version'];
			}
		}

		$cache[ $branch ] = $latest;
		set_site_transient( self::CACHE_KEY, $cache, $latest ? self::CACHE_TTL : HOUR_IN_SECONDS );

		return $latest;
	}

	/**
	 * Avisos que afectan a una versión.
	 *
	 * @param string|null $version Versión; por defecto la que está en ejecución.
	 * @return array Avisos con 'status': 'vulnerable', 'no_fix' (rama sin soporte) o 'patched'.
	 */
	public static function evaluate( $version = null ) {
		$version = $version ? $version : self::runtime_version();
		$branch  = implode( '.', array_slice( explode( '.', $version ), 0, 2 ) );
		$out     = array();

		foreach ( self::list_advisories() as $adv ) {
			if ( version_compare( $version, $adv['min_affected'], '<' ) ) {
				continue;
			}
			if ( isset( $adv['fixed'][ $branch ] ) ) {
				$adv['fixed_in'] = $adv['fixed'][ $branch ];
				$adv['status']   = version_compare( $version, $adv['fixed'][ $branch ], '>=' ) ? 'patched' : 'vulnerable';
			} else {
				$branches = array_keys( $adv['fixed'] );
				usort( $branches, 'version_compare' );
				$max_fixed_branch = end( $branches );
				$adv['fixed_in']  = null;
				$adv['status']    = version_compare( $branch, $max_fixed_branch, '>' ) ? 'patched' : 'no_fix';
			}
			$out[] = $adv;
		}

		return $out;
	}
}
