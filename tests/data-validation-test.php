<?php
/**
 * Pruebas de validación de los datos de vulnerabilidades.
 *
 * Uso, en un sitio de pruebas con el plugin activo:
 *     wp eval-file tests/data-validation-test.php
 *
 * @package DF_Security_Check
 */

// phpcs:disable WordPress.WP.AlternativeFunctions, WordPress.Security.EscapeOutput

$dfsc_base = json_decode( file_get_contents( DFSC_DIR . 'data/advisories.json' ), true );

/**
 * Muestra el resultado de una prueba y lleva la cuenta de fallos.
 *
 * @param string|null $name      Nombre de la prueba; null devuelve el número de fallos.
 * @param bool        $condition Resultado.
 * @return int Número de fallos acumulados.
 */
function dfsc_test( $name, $condition = true ) {
	static $failures = 0;
	if ( null === $name ) {
		return $failures;
	}
	if ( ! $condition ) {
		++$failures;
	}
	echo ( $condition ? 'PASS' : 'FAIL' ) . "  {$name}\n";
	return $failures;
}

/**
 * Copia de los datos con un cambio aplicado.
 *
 * @param array    $base   Datos originales.
 * @param callable $change Función que modifica el arreglo.
 * @return array
 */
function dfsc_variant( array $base, callable $change ) {
	$change( $base );
	return $base;
}

/**
 * Simula la respuesta del repositorio y reinicia la caché de datos.
 *
 * @param string $body Contenido de la respuesta.
 */
function dfsc_mock_remote( $body ) {
	remove_all_filters( 'pre_http_request' );
	add_filter(
		'pre_http_request',
		function ( $preempt, $args, $url ) use ( $body ) {
			if ( false === strpos( $url, 'raw.githubusercontent.com' ) ) {
				return $preempt;
			}
			return array(
				'headers'  => array(),
				'body'     => $body,
				'response' => array(
					'code'    => 200,
					'message' => 'OK',
				),
				'cookies'  => array(),
				'filename' => null,
			);
		},
		10,
		3
	);
	delete_site_transient( DFSC_Advisories::DATA_CACHE_KEY );
	$cache = new ReflectionProperty( 'DFSC_Advisories', 'data' );
	$cache->setAccessible( true );
	$cache->setValue( null, null );
}

$dfsc_count = count( $dfsc_base['advisories'] );

// Validación del archivo.
$valid = DFSC_Advisories::validate( $dfsc_base );
dfsc_test( 'Los datos incluidos son válidos', is_array( $valid ) && count( $valid['advisories'] ) === $dfsc_count );

dfsc_test(
	'Se rechaza un esquema desconocido',
	null === DFSC_Advisories::validate(
		dfsc_variant(
			$dfsc_base,
			function ( &$d ) {
				$d['schema'] = 2;
			}
		)
	)
);

dfsc_test(
	'Se rechaza una fecha inválida',
	null === DFSC_Advisories::validate(
		dfsc_variant(
			$dfsc_base,
			function ( &$d ) {
				$d['updated'] = '2026-10-21<script>';
			}
		)
	)
);

$cases = array(
	'Se descarta un aviso con una versión inyectada' => function ( &$d ) {
		$d['advisories'][0]['fixed']['8.4'] = '8.4.27; rm -rf';
	},
	'Se descarta un aviso con una versión de otra rama' => function ( &$d ) {
		$d['advisories'][0]['fixed']['8.4'] = '8.3.99';
	},
	'Se descarta un aviso con un CVE inválido' => function ( &$d ) {
		$d['advisories'][0]['cves'][] = 'CVE-XSS"><img>';
	},
	'Se descarta un aviso con una severidad inválida' => function ( &$d ) {
		$d['advisories'][0]['severity'] = 'none';
	},
);
foreach ( $cases as $name => $change ) {
	$result = DFSC_Advisories::validate( dfsc_variant( $dfsc_base, $change ) );
	dfsc_test( $name, is_array( $result ) && count( $result['advisories'] ) === $dfsc_count - 1 );
}

$result = DFSC_Advisories::validate(
	dfsc_variant(
		$dfsc_base,
		function ( &$d ) {
			$d['advisories'][0]['title']['es'] = '<img src=x onerror=alert(1)>Hola';
		}
	)
);
dfsc_test( 'Se elimina el HTML de los textos', is_array( $result ) && 'Hola' === $result['advisories'][0]['title']['es'] );

$result = DFSC_Advisories::validate(
	dfsc_variant(
		$dfsc_base,
		function ( &$d ) {
			$d['advisories'][0]['url'] = 'javascript:alert(1)';
		}
	)
);
dfsc_test( 'Se eliminan las URL que no son https', is_array( $result ) && '' === $result['advisories'][0]['url'] );

dfsc_test( 'Se rechazan datos que no son un arreglo', null === DFSC_Advisories::validate( 'texto' ) && null === DFSC_Advisories::validate( null ) );

// Datos remotos.
$newer                 = $dfsc_base;
$newer['updated']      = '2099-01-01';
$newer['advisories'][] = array(
	'id'           => 'test-advisory',
	'cves'         => array( 'CVE-2099-0001' ),
	'severity'     => 'critical',
	'date'         => '2099-01-01',
	'min_affected' => '8.1.0',
	'fixed'        => array(
		'8.3' => '8.3.99',
		'8.4' => '8.4.99',
	),
	'title'        => array( 'en' => 'Test advisory' ),
	'summary'      => array( 'en' => 'Test.' ),
);

dfsc_mock_remote( wp_json_encode( $newer ) );
$info = DFSC_Advisories::data_info();
dfsc_test( 'Se usan los datos remotos más recientes', 'remote' === $info['source'] && count( DFSC_Advisories::list_advisories() ) === $dfsc_count + 1 );

$evaluated = DFSC_Advisories::evaluate( '8.3.36' );
$last      = end( $evaluated );
dfsc_test( 'Un aviso remoto nuevo afecta a las versiones anteriores', 'vulnerable' === $last['status'] && '8.3.99' === $last['fixed_in'] );

$older            = $dfsc_base;
$older['updated'] = '2000-01-01';
dfsc_mock_remote( wp_json_encode( $older ) );
dfsc_test( 'Se ignoran los datos remotos más antiguos', 'bundled' === DFSC_Advisories::data_info()['source'] );

dfsc_mock_remote( '{"schema":1, roto' );
dfsc_test( 'Se ignoran los datos remotos dañados', 'bundled' === DFSC_Advisories::data_info()['source'] );

add_filter( 'dfsc_data_url', '__return_empty_string' );
dfsc_mock_remote( wp_json_encode( $newer ) );
dfsc_test( 'La consulta remota se puede desactivar', 'bundled' === DFSC_Advisories::data_info()['source'] );

remove_all_filters( 'dfsc_data_url' );
remove_all_filters( 'pre_http_request' );
delete_site_transient( DFSC_Advisories::DATA_CACHE_KEY );

$dfsc_failures = dfsc_test( null );
echo $dfsc_failures ? "\n{$dfsc_failures} prueba(s) fallaron.\n" : "\nTodas las pruebas pasaron.\n";
