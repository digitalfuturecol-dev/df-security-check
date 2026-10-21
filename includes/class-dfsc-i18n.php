<?php
/**
 * Traducciones según el idioma del sitio (Ajustes > Generales > Idioma del sitio).
 *
 * Los textos fuente están en inglés. Cada idioma es un archivo languages/{código}.php que
 * devuelve un arreglo 'texto en inglés' => 'traducción'. Se usa el código de dos letras del
 * idioma del sitio (es_CO, es_ES, es_MX… usan es.php). Si falta una traducción se muestra el inglés.
 *
 * @package DF_Security_Check
 */

defined( 'ABSPATH' ) || exit;

class DFSC_I18n {

	private static $lang = null;
	private static $dict = null;

	/** Idioma del sitio, no del usuario: el reporte debe coincidir con el sitio. */
	public static function lang() {
		if ( null === self::$lang ) {
			$locale     = get_locale();
			self::$lang = strtolower( substr( $locale, 0, 2 ) );
		}
		return self::$lang;
	}

	/** Etiqueta para el atributo lang del HTML (es-CO, en-US…). */
	public static function html_lang() {
		return str_replace( '_', '-', get_locale() );
	}

	public static function t( $text ) {
		if ( null === self::$dict ) {
			self::$dict = array();
			$file       = DFSC_DIR . 'languages/' . self::lang() . '.php';
			if ( 'en' !== self::lang() && is_readable( $file ) ) {
				$loaded = include $file;
				if ( is_array( $loaded ) ) {
					self::$dict = $loaded;
				}
			}
		}
		return isset( self::$dict[ $text ] ) ? self::$dict[ $text ] : $text;
	}

	/** Fecha en el formato y el idioma del sitio. */
	public static function date( $timestamp_or_ymd ) {
		$ts    = is_numeric( $timestamp_or_ymd ) ? (int) $timestamp_or_ymd : strtotime( $timestamp_or_ymd . ' 12:00:00' );
		if ( is_numeric( $timestamp_or_ymd ) ) {
			$ts += (int) ( (float) get_option( 'gmt_offset' ) * HOUR_IN_SECONDS ); // Hora local del sitio.
		}
		// Formato propio para no depender del paquete de idioma de WordPress instalado.
		return dfsc_t( '%2$s %1$d, %3$d', (int) gmdate( 'j', $ts ), dfsc_t( gmdate( 'F', $ts ) ), (int) gmdate( 'Y', $ts ) );
	}

	public static function time( $timestamp ) {
		return wp_date( 'H:i', $timestamp );
	}
}

/**
 * Traduce un texto al idioma del sitio. Acepta argumentos estilo sprintf.
 */
function dfsc_t( $text, ...$args ) {
	$out = DFSC_I18n::t( $text );
	return $args ? vsprintf( $out, $args ) : $out;
}
