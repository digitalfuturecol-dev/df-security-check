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

/**
 * Traducción y formato de fechas en el idioma del sitio.
 */
class DFSC_I18n {

	/**
	 * Código de dos letras del idioma del sitio.
	 *
	 * @var string|null
	 */
	private static $lang = null;

	/**
	 * Traducciones cargadas: texto en inglés => traducción.
	 *
	 * @var array|null
	 */
	private static $dict = null;

	/**
	 * Idioma del sitio, no del usuario: el reporte debe coincidir con el sitio.
	 *
	 * @return string
	 */
	public static function lang() {
		if ( null === self::$lang ) {
			self::$lang = strtolower( substr( get_locale(), 0, 2 ) );
		}
		return self::$lang;
	}

	/**
	 * Etiqueta para el atributo lang del HTML (es-CO, en-US…).
	 *
	 * @return string
	 */
	public static function html_lang() {
		return str_replace( '_', '-', get_locale() );
	}

	/**
	 * Traduce un texto al idioma del sitio.
	 *
	 * @param string $text Texto en inglés.
	 * @return string
	 */
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

	/**
	 * Fecha en el idioma del sitio, sin depender del paquete de idioma de WordPress instalado.
	 *
	 * @param int|string $timestamp_or_ymd Marca de tiempo Unix o fecha AAAA-MM-DD.
	 * @return string
	 */
	public static function date( $timestamp_or_ymd ) {
		if ( is_numeric( $timestamp_or_ymd ) ) {
			// Hora local del sitio.
			$ts = (int) $timestamp_or_ymd + (int) ( (float) get_option( 'gmt_offset' ) * HOUR_IN_SECONDS );
		} else {
			$ts = strtotime( $timestamp_or_ymd . ' 12:00:00' );
		}
		return dfsc_t( '%2$s %1$d, %3$d', (int) gmdate( 'j', $ts ), dfsc_t( gmdate( 'F', $ts ) ), (int) gmdate( 'Y', $ts ) );
	}

	/**
	 * Hora en formato de 24 horas, en la zona horaria del sitio.
	 *
	 * @param int $timestamp Marca de tiempo Unix.
	 * @return string
	 */
	public static function time( $timestamp ) {
		return wp_date( 'H:i', $timestamp );
	}
}
