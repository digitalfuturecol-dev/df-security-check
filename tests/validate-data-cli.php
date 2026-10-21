<?php
/**
 * Valida data/advisories.json con el mismo código que usa el plugin, sin WordPress.
 * Uso: php tests/validate-data-cli.php data/advisories.json
 *
 * @package DF_Security_Check
 */

// phpcs:disable

define( 'ABSPATH', __DIR__ . '/' );
define( 'HOUR_IN_SECONDS', 3600 );

// Equivalentes mínimos de las funciones de WordPress usadas por la validación.
function wp_strip_all_tags( $text ) {
	return trim( strip_tags( preg_replace( '@<(script|style)[^>]*?>.*?</\\1>@si', '', $text ) ) );
}
function esc_url_raw( $url, $protocols = null ) {
	return ( is_string( $url ) && preg_match( '#^https://[^\s<>"]+$#', $url ) ) ? $url : '';
}

require dirname( __DIR__ ) . '/includes/class-dfsc-advisories.php';

$file = isset( $argv[1] ) ? $argv[1] : dirname( __DIR__ ) . '/data/advisories.json';
$raw  = json_decode( (string) file_get_contents( $file ), true );
if ( null === $raw ) {
	fwrite( STDERR, "ERROR: {$file} is not valid JSON: " . json_last_error_msg() . "\n" );
	exit( 1 );
}

$valid = DFSC_Advisories::validate( $raw );
if ( ! $valid ) {
	fwrite( STDERR, "ERROR: invalid structure (schema, updated, recommended_branch, eol or advisories).\n" );
	exit( 1 );
}

$errors = 0;
if ( count( $valid['advisories'] ) !== count( $raw['advisories'] ) ) {
	$ids = array_column( $valid['advisories'], 'id' );
	foreach ( $raw['advisories'] as $i => $a ) {
		$id = is_array( $a ) && isset( $a['id'] ) ? $a['id'] : "#{$i}";
		if ( ! in_array( $id, $ids, true ) ) {
			fwrite( STDERR, "ERROR: advisory {$id} was rejected. Check CVE, dates, versions (fixed versions must belong to their branch) and title/summary.en.\n" );
			$errors++;
		}
	}
}
if ( count( $valid['eol'] ) !== count( $raw['eol'] ) ) {
	fwrite( STDERR, "ERROR: some eol entries are invalid.\n" );
	$errors++;
}
if ( ! isset( $valid['eol'][ $valid['recommended_branch'] ] ) ) {
	fwrite( STDERR, "ERROR: recommended_branch is not listed in eol.\n" );
	$errors++;
}
$ids = array_column( $valid['advisories'], 'id' );
if ( count( $ids ) !== count( array_unique( $ids ) ) ) {
	fwrite( STDERR, "ERROR: duplicated advisory id.\n" );
	$errors++;
}
foreach ( $raw['advisories'] as $a ) {
	if ( is_array( $a ) && empty( $a['title']['es'] ) ) {
		fwrite( STDERR, "WARNING: advisory {$a['id']} has no Spanish title.\n" );
	}
}

if ( $errors ) {
	exit( 1 );
}
echo 'OK: ' . count( $valid['advisories'] ) . " advisories, data updated {$valid['updated']}.\n";
