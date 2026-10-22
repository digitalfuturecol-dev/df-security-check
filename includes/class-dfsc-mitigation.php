<?php
/**
 * Mitigación temporal recomendada por php.net para CVE-2026-109619 mientras se actualiza PHP:
 * desactivar session.upload_progress y limitar post_max_size.
 *
 * Se escribe en .user.ini (PHP-FPM / CGI / LiteSpeed) o en .htaccess (mod_php / LiteSpeed)
 * dentro de un bloque marcado, y se puede revertir. Tras escribir en .htaccess se comprueba que
 * el sitio siga respondiendo; si no, se revierte automáticamente.
 *
 * @package DF_Security_Check
 */

defined( 'ABSPATH' ) || exit;

/**
 * Aplica, verifica y retira la mitigación temporal.
 */
class DFSC_Mitigation {

	const BEGIN = 'BEGIN DF Security Check';
	const END   = 'END DF Security Check';
	const LIMIT = '32M';

	/**
	 * Métodos posibles según el manejador de PHP.
	 *
	 * @return array 'user_ini' y/o 'htaccess'.
	 */
	public static function methods() {
		$sapi    = php_sapi_name();
		$methods = array();
		if ( in_array( $sapi, array( 'fpm-fcgi', 'cgi-fcgi', 'litespeed' ), true ) && '' !== (string) ini_get( 'user_ini.filename' ) ) {
			$methods[] = 'user_ini';
		}
		if ( in_array( $sapi, array( 'apache2handler', 'litespeed' ), true ) ) {
			$methods[] = 'htaccess';
		}
		return $methods;
	}

	/**
	 * Ruta del archivo .user.ini del sitio.
	 *
	 * @return string
	 */
	private static function user_ini_path() {
		$name = (string) ini_get( 'user_ini.filename' );
		return ABSPATH . ( '' !== $name ? $name : '.user.ini' );
	}

	/**
	 * Ruta del archivo .htaccess del sitio.
	 *
	 * @return string
	 */
	private static function htaccess_path() {
		return ABSPATH . '.htaccess';
	}

	/**
	 * Directivas a aplicar. post_max_size solo se reduce si hoy es mayor que el límite.
	 *
	 * @return array Directiva => valor.
	 */
	private static function directives() {
		$d       = array( 'session.upload_progress.enabled' => '0' );
		$current = wp_convert_hr_to_bytes( (string) ini_get( 'post_max_size' ) );
		$limit   = wp_convert_hr_to_bytes( self::LIMIT );
		if ( 0 === $current || $current > $limit ) {
			$d['post_max_size'] = self::LIMIT;
			if ( wp_convert_hr_to_bytes( (string) ini_get( 'upload_max_filesize' ) ) >= $limit ) {
				$d['upload_max_filesize'] = '30M';
			}
		}
		return $d;
	}

	/**
	 * Estado actual de la mitigación.
	 *
	 * @return array
	 */
	public static function status() {
		$files = array();
		foreach ( array( self::user_ini_path(), self::htaccess_path() ) as $file ) {
			if ( is_readable( $file ) && false !== strpos( (string) file_get_contents( $file ), self::BEGIN ) ) { // phpcs:ignore WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents -- archivo local del sitio.
				$files[] = basename( $file );
			}
		}
		$effective = ! in_array( strtolower( (string) ini_get( 'session.upload_progress.enabled' ) ), array( '1', 'on' ), true );
		return array(
			'applied'   => ! empty( $files ),
			'files'     => $files,
			'effective' => $effective,
			'methods'   => self::methods(),
			'cache_ttl' => (int) ini_get( 'user_ini.cache_ttl' ),
		);
	}

	/**
	 * Aplica la mitigación con los métodos disponibles en el servidor.
	 *
	 * @return true|WP_Error
	 */
	public static function apply() {
		$methods = self::methods();
		if ( empty( $methods ) ) {
			return new WP_Error( 'dfsc_no_method', dfsc_t( 'This server does not allow changing PHP settings from the site folder. Ask your hosting provider to set session.upload_progress.enabled = 0, or update PHP.' ) );
		}

		if ( in_array( 'user_ini', $methods, true ) ) {
			$lines = array();
			foreach ( self::directives() as $k => $v ) {
				$lines[] = $k . ' = ' . $v;
			}
			$r = self::write_block( self::user_ini_path(), $lines, ';' );
			if ( is_wp_error( $r ) ) {
				return $r;
			}
		}

		if ( in_array( 'htaccess', $methods, true ) ) {
			$inner = array();
			foreach ( self::directives() as $k => $v ) {
				$inner[] = ( '0' === $v ? 'php_flag ' . $k . ' off' : 'php_value ' . $k . ' ' . $v );
			}
			// Módulos: mod_php (PHP 8), mod_php7 (PHP 7), mod_lsapi (CloudLinux) y LiteSpeed.
			$modules = array( 'mod_php.c', 'mod_php7.c', 'mod_lsapi.c' );
			if ( 'litespeed' === php_sapi_name() ) {
				$modules[] = 'LiteSpeed';
			}
			$block = array();
			foreach ( $modules as $mod ) {
				$block[] = '<IfModule ' . $mod . '>';
				foreach ( $inner as $l ) {
					$block[] = '  ' . $l;
				}
				$block[] = '</IfModule>';
			}
			$r = self::write_block( self::htaccess_path(), $block, '#' );
			if ( is_wp_error( $r ) ) {
				return $r;
			}
			if ( ! self::site_responds() ) {
				self::remove_block( self::htaccess_path(), '#' );
				return new WP_Error( 'dfsc_rollback', dfsc_t( 'The site stopped responding after changing .htaccess, so the change was undone automatically. Ask your hosting provider to apply the setting.' ) );
			}
		}

		return true;
	}

	/**
	 * Retira la mitigación de todos los archivos.
	 *
	 * @return true
	 */
	public static function revert() {
		self::remove_block( self::user_ini_path(), ';' );
		self::remove_block( self::htaccess_path(), '#' );
		return true;
	}

	/**
	 * Escribe el bloque marcado al principio del archivo, reemplazando uno anterior.
	 *
	 * @param string $file    Ruta del archivo.
	 * @param array  $lines   Líneas del bloque.
	 * @param string $comment Carácter de comentario del formato (';' o '#').
	 * @return true|WP_Error
	 */
	private static function write_block( $file, array $lines, $comment ) {
		$exists = file_exists( $file );
		if ( $exists ? ! wp_is_writable( $file ) : ! wp_is_writable( dirname( $file ) ) ) {
			return new WP_Error( 'dfsc_not_writable', dfsc_t( 'Cannot write to %s. Check the file permissions or ask your hosting provider.', basename( $file ) ) );
		}
		$content = $exists ? (string) file_get_contents( $file ) : ''; // phpcs:ignore WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents -- archivo local del sitio.
		$content = self::strip_block( $content, $comment );
		$block   = $comment . ' ' . self::BEGIN . "\n"
			. $comment . " Mitigation CVE-2026-109619 — remove after updating PHP\n"
			. implode( "\n", $lines ) . "\n"
			. $comment . ' ' . self::END . "\n";
		// El bloque va al principio para que ninguna regla posterior lo anule.
		$new = $block . ( '' !== trim( $content ) ? "\n" . ltrim( $content ) : '' );

		if ( false === file_put_contents( $file, $new, LOCK_EX ) ) { // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_file_put_contents -- WP_Filesystem puede pedir credenciales FTP; se requiere escritura directa.
			return new WP_Error( 'dfsc_write_failed', dfsc_t( 'Cannot write to %s. Check the file permissions or ask your hosting provider.', basename( $file ) ) );
		}
		return true;
	}

	/**
	 * Quita el bloque marcado de un archivo. Si el .user.ini queda vacío, lo elimina.
	 *
	 * @param string $file    Ruta del archivo.
	 * @param string $comment Carácter de comentario del formato.
	 * @return void
	 */
	private static function remove_block( $file, $comment ) {
		if ( ! file_exists( $file ) || ! wp_is_writable( $file ) ) {
			return;
		}
		$content = (string) file_get_contents( $file ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents -- archivo local del sitio.
		if ( false === strpos( $content, self::BEGIN ) ) {
			return;
		}
		$clean = self::strip_block( $content, $comment );
		if ( '' === trim( $clean ) && false !== strpos( $file, 'user.ini' ) ) {
			wp_delete_file( $file );
		} else {
			file_put_contents( $file, ltrim( $clean ), LOCK_EX ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_file_put_contents -- ver write_block().
		}
	}

	/**
	 * Elimina el bloque marcado de un texto.
	 *
	 * @param string $content Contenido del archivo.
	 * @param string $comment Carácter de comentario del formato.
	 * @return string
	 */
	private static function strip_block( $content, $comment ) {
		$c = preg_quote( $comment, '/' );
		return (string) preg_replace( '/' . $c . ' ' . preg_quote( self::BEGIN, '/' ) . '.*?' . $c . ' ' . preg_quote( self::END, '/' ) . "\r?\n?/s", '', $content );
	}

	/**
	 * Comprueba que la portada responda sin error 500 tras el cambio.
	 *
	 * @return bool
	 */
	private static function site_responds() {
		$r = wp_remote_get(
			home_url( '/' ),
			array(
				'timeout'     => 15,
				'sslverify'   => false, // Petición al propio sitio; algunos hostings no validan su certificado en loopback.
				'redirection' => 3,
			)
		);
		if ( is_wp_error( $r ) ) {
			return true; // Sin conexión de vuelta (loopback): no se puede saber, no se revierte.
		}
		return wp_remote_retrieve_response_code( $r ) < 500;
	}
}
