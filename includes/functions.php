<?php
/**
 * Funciones globales del plugin.
 *
 * @package DF_Security_Check
 */

defined( 'ABSPATH' ) || exit;

/**
 * Traduce un texto al idioma del sitio. Acepta argumentos estilo sprintf.
 *
 * @param string $text    Texto en inglés.
 * @param mixed  ...$args Valores para los marcadores %s, %d, %1$s….
 * @return string
 */
function dfsc_t( $text, ...$args ) {
	$out = DFSC_I18n::t( $text );
	return $args ? vsprintf( $out, $args ) : $out;
}
