<?php
/**
 * Limpieza al desinstalar: ajustes, último resultado, caché y la mitigación si quedó aplicada.
 *
 * @package DF_Security_Check
 */

defined( 'WP_UNINSTALL_PLUGIN' ) || exit;

delete_option( 'dfsc_last_result' );
delete_option( 'dfsc_settings' );
delete_site_transient( 'dfsc_php_latest' );
delete_site_transient( 'dfsc_remote_data' );
wp_clear_scheduled_hook( 'dfsc_daily_check' );
wp_clear_scheduled_hook( 'dfsc_scheduled_report' );

require_once __DIR__ . '/includes/class-dfsc-mitigation.php';
DFSC_Mitigation::revert();
