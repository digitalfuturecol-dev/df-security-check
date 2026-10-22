<?php
/**
 * Plugin Name:       DF Security Check
 * Plugin URI:        https://github.com/digitalfuturecol-dev/df-security-check
 * Description:       Diagnóstico de seguridad del sitio: versión de PHP frente a vulnerabilidades conocidas (incluye CVE-2026-109618 y CVE-2026-109619), configuración del servidor, actualizaciones de WordPress, plugins y temas, mitigaciones de un clic y reporte de estado descargable.
 * Version:           1.1.2
 * Requires at least: 6.2
 * Requires PHP:      7.4
 * Author:            Digital Future
 * Author URI:        https://digitalfuture.com.co
 * License:           GPL-2.0-or-later
 * Text Domain:       df-security-check
 *
 * @package DF_Security_Check
 */

defined( 'ABSPATH' ) || exit;

define( 'DFSC_VERSION', '1.1.2' );
define( 'DFSC_FILE', __FILE__ );
define( 'DFSC_DIR', plugin_dir_path( __FILE__ ) );

require_once DFSC_DIR . 'includes/class-dfsc-i18n.php';
require_once DFSC_DIR . 'includes/functions.php';
require_once DFSC_DIR . 'includes/class-dfsc-advisories.php';
require_once DFSC_DIR . 'includes/class-dfsc-checks.php';
require_once DFSC_DIR . 'includes/class-dfsc-mitigation.php';
require_once DFSC_DIR . 'includes/class-dfsc-report.php';
require_once DFSC_DIR . 'includes/class-dfsc-admin.php';

add_action( 'plugins_loaded', array( 'DFSC_Admin', 'init' ) );

register_deactivation_hook( __FILE__, array( 'DFSC_Admin', 'on_deactivate' ) );
