<?php
/**
 * Panel de administración, acciones, widget del escritorio, Salud del sitio y tareas programadas.
 *
 * @package DF_Security_Check
 */

defined( 'ABSPATH' ) || exit;

/**
 * Integración con el panel de WordPress.
 */
class DFSC_Admin {

	const SLUG       = 'df-security-check';
	const OPT_LAST   = 'dfsc_last_result';
	const OPT_CONFIG = 'dfsc_settings';
	const CRON_DAILY = 'dfsc_daily_check';
	const CRON_SEND  = 'dfsc_scheduled_report';

	/**
	 * Registra ganchos, menú y tareas programadas.
	 *
	 * @return void
	 */
	public static function init() {
		add_action( 'admin_menu', array( __CLASS__, 'menu' ) );
		add_action( 'admin_post_dfsc_action', array( __CLASS__, 'handle' ) );
		add_action( 'wp_dashboard_setup', array( __CLASS__, 'dashboard_widget' ) );
		add_action( 'admin_notices', array( __CLASS__, 'notice' ) );
		add_filter( 'site_status_tests', array( __CLASS__, 'site_health' ) );
		add_filter( 'cron_schedules', array( __CLASS__, 'cron_schedules' ) );
		add_filter( 'plugin_action_links_' . plugin_basename( DFSC_FILE ), array( __CLASS__, 'action_links' ) );

		add_action( self::CRON_DAILY, array( __CLASS__, 'cron_daily' ) );
		add_action( self::CRON_SEND, array( __CLASS__, 'cron_send' ) );
		if ( ! wp_next_scheduled( self::CRON_DAILY ) ) {
			wp_schedule_event( time() + HOUR_IN_SECONDS, 'daily', self::CRON_DAILY );
		}
	}

	/**
	 * Limpia las tareas programadas al desactivar el plugin.
	 *
	 * @return void
	 */
	public static function on_deactivate() {
		wp_clear_scheduled_hook( self::CRON_DAILY );
		wp_clear_scheduled_hook( self::CRON_SEND );
	}

	/**
	 * Ajustes del plugin con sus valores por defecto.
	 *
	 * @return array
	 */
	public static function settings() {
		$s = get_option( self::OPT_CONFIG, array() );
		return wp_parse_args(
			is_array( $s ) ? $s : array(),
			array(
				'recipients' => get_option( 'admin_email' ),
				'schedule'   => 'none',
				'alerts'     => 1,
				'online'     => 1,
			)
		);
	}

	/**
	 * Ejecuta las verificaciones y guarda el resultado.
	 *
	 * @param bool $force Ignora las cachés de datos remotos.
	 * @return array
	 */
	public static function run( $force = false ) {
		$r = DFSC_Checks::run( $force );
		update_option( self::OPT_LAST, $r, false );
		return $r;
	}

	/**
	 * Último resultado guardado.
	 *
	 * @return array|null
	 */
	public static function last() {
		$r = get_option( self::OPT_LAST );
		return is_array( $r ) ? $r : null;
	}

	/**
	 * Agrega la página en Herramientas.
	 *
	 * @return void
	 */
	public static function menu() {
		add_management_page(
			dfsc_t( 'Security Check' ),
			dfsc_t( 'Security Check' ),
			'manage_options',
			self::SLUG,
			array( __CLASS__, 'page' )
		);
	}

	/**
	 * Enlace al reporte en la lista de plugins.
	 *
	 * @param array $links Enlaces existentes.
	 * @return array
	 */
	public static function action_links( $links ) {
		array_unshift( $links, '<a href="' . esc_url( self::page_url() ) . '">' . esc_html( dfsc_t( 'View report' ) ) . '</a>' );
		return $links;
	}

	/**
	 * URL de la página del plugin.
	 *
	 * @param array $args Parámetros adicionales.
	 * @return string
	 */
	public static function page_url( $args = array() ) {
		return add_query_arg( array_merge( array( 'page' => self::SLUG ), $args ), admin_url( 'tools.php' ) );
	}

	/**
	 * URL protegida con nonce para una acción del panel.
	 *
	 * @param string $task Acción.
	 * @return string
	 */
	private static function action_url( $task ) {
		return wp_nonce_url( admin_url( 'admin-post.php?action=dfsc_action&do=' . $task ), 'dfsc_' . $task );
	}

	/**
	 * Página del reporte y ajustes.
	 *
	 * @return void
	 */
	public static function page() {
		if ( ! current_user_can( 'manage_options' ) ) {
			return;
		}
		$r   = self::run( false );
		$s   = self::settings();
		$mit = $r['mitigation'];
		$msg = isset( $_GET['dfsc_msg'] ) ? sanitize_key( $_GET['dfsc_msg'] ) : ''; // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- solo elige un mensaje de una lista fija.
		$err = get_transient( 'dfsc_error_' . get_current_user_id() );
		delete_transient( 'dfsc_error_' . get_current_user_id() );

		$messages = array(
			'refreshed' => dfsc_t( 'Checks run again with fresh data from php.net.' ),
			'applied'   => dfsc_t( 'Mitigation applied. PHP may take a few minutes to pick it up.' ),
			'reverted'  => dfsc_t( 'Mitigation removed.' ),
			'sent'      => dfsc_t( 'Report sent.' ),
			'saved'     => dfsc_t( 'Settings saved.' ),
		);
		?>
		<div class="wrap">
			<style><?php echo DFSC_Report::css(); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- CSS fijo del plugin. ?>
				.dfsc-actions{display:flex;flex-wrap:wrap;gap:8px;margin:16px 0}
				.dfsc-box{background:#fff;border:1px solid #dcdcde;border-radius:8px;padding:12px 20px;margin-top:28px;max-width:1100px}
			</style>
			<h1><?php echo esc_html( dfsc_t( 'Security Check' ) ); ?></h1>

			<?php if ( $msg && isset( $messages[ $msg ] ) ) : ?>
				<div class="notice notice-success is-dismissible"><p><?php echo esc_html( $messages[ $msg ] ); ?></p></div>
			<?php endif; ?>
			<?php if ( $err ) : ?>
				<div class="notice notice-error"><p><?php echo esc_html( $err ); ?></p></div>
			<?php endif; ?>

			<div class="dfsc-actions">
				<a class="button button-primary" href="<?php echo esc_url( self::action_url( 'download' ) ); ?>"><?php echo esc_html( dfsc_t( 'Download report' ) ); ?></a>
				<a class="button" href="<?php echo esc_url( self::action_url( 'email' ) ); ?>"><?php echo esc_html( dfsc_t( 'Email report' ) ); ?></a>
				<a class="button" href="<?php echo esc_url( self::action_url( 'refresh' ) ); ?>"><?php echo esc_html( dfsc_t( 'Run checks again' ) ); ?></a>
				<?php if ( $r['php_vulnerable'] && ! $mit['applied'] && $mit['methods'] ) : ?>
					<a class="button" href="<?php echo esc_url( self::action_url( 'apply' ) ); ?>"><?php echo esc_html( dfsc_t( 'Apply mitigation' ) ); ?></a>
				<?php endif; ?>
				<?php if ( $mit['applied'] ) : ?>
					<a class="button" href="<?php echo esc_url( self::action_url( 'revert' ) ); ?>"><?php echo esc_html( dfsc_t( 'Remove mitigation' ) ); ?></a>
				<?php endif; ?>
			</div>

			<?php echo DFSC_Report::body( $r ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- escapado en body(). ?>

			<div class="dfsc-box">
				<h2><?php echo esc_html( dfsc_t( 'Automatic reports' ) ); ?></h2>
				<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>">
					<input type="hidden" name="action" value="dfsc_action">
					<input type="hidden" name="do" value="save">
					<?php wp_nonce_field( 'dfsc_save' ); ?>
					<table class="form-table" role="presentation">
						<tr>
							<th scope="row"><label for="dfsc-recipients"><?php echo esc_html( dfsc_t( 'Send reports to' ) ); ?></label></th>
							<td><input type="text" class="regular-text" id="dfsc-recipients" name="recipients" value="<?php echo esc_attr( $s['recipients'] ); ?>">
							<p class="description"><?php echo esc_html( dfsc_t( 'One or more email addresses separated by commas.' ) ); ?></p></td>
						</tr>
						<tr>
							<th scope="row"><label for="dfsc-schedule"><?php echo esc_html( dfsc_t( 'Send report' ) ); ?></label></th>
							<td><select id="dfsc-schedule" name="schedule">
								<option value="none" <?php selected( $s['schedule'], 'none' ); ?>><?php echo esc_html( dfsc_t( 'Never' ) ); ?></option>
								<option value="weekly" <?php selected( $s['schedule'], 'weekly' ); ?>><?php echo esc_html( dfsc_t( 'Weekly' ) ); ?></option>
								<option value="monthly" <?php selected( $s['schedule'], 'monthly' ); ?>><?php echo esc_html( dfsc_t( 'Monthly' ) ); ?></option>
							</select></td>
						</tr>
						<tr>
							<th scope="row"><?php echo esc_html( dfsc_t( 'Alerts' ) ); ?></th>
							<td><label><input type="checkbox" name="alerts" value="1" <?php checked( $s['alerts'], 1 ); ?>> <?php echo esc_html( dfsc_t( 'Email right away when the daily check finds a new critical issue.' ) ); ?></label></td>
						</tr>
						<tr>
							<th scope="row"><?php echo esc_html( dfsc_t( 'Online data' ) ); ?></th>
							<td><label><input type="checkbox" name="online" value="1" <?php checked( $s['online'], 1 ); ?>> <?php echo esc_html( dfsc_t( 'Check php.net for the latest PHP releases and the project repository on GitHub for new vulnerability data.' ) ); ?></label>
							<p class="description"><?php echo esc_html( dfsc_t( 'Only public files are downloaded. No information about this site is sent.' ) ); ?></p></td>
						</tr>
					</table>
					<?php submit_button( dfsc_t( 'Save' ) ); ?>
				</form>
			</div>
		</div>
		<?php
	}

	/**
	 * Procesa las acciones del panel (admin-post.php).
	 *
	 * @return void
	 */
	public static function handle() {
		$do = isset( $_REQUEST['do'] ) ? sanitize_key( $_REQUEST['do'] ) : ''; // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- el nonce se verifica justo después con check_admin_referer().
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( esc_html( dfsc_t( 'You do not have permission to do this.' ) ), 403 );
		}
		check_admin_referer( 'dfsc_' . $do );

		$uid = get_current_user_id();
		switch ( $do ) {
			case 'refresh':
				delete_site_transient( DFSC_Advisories::CACHE_KEY );
				DFSC_Advisories::data( true );
				if ( function_exists( 'wp_version_check' ) ) {
					wp_version_check();
				}
				wp_update_plugins();
				wp_update_themes();
				self::run( true );
				self::back( 'refreshed' );
				break;

			case 'apply':
				$res = DFSC_Mitigation::apply();
				if ( is_wp_error( $res ) ) {
					set_transient( 'dfsc_error_' . $uid, $res->get_error_message(), 120 );
					self::back();
				}
				self::back( 'applied' );
				break;

			case 'revert':
				DFSC_Mitigation::revert();
				self::back( 'reverted' );
				break;

			case 'download':
				$r = self::run( false );
				nocache_headers();
				header( 'Content-Type: text/html; charset=utf-8' );
				header( 'Content-Disposition: attachment; filename="' . DFSC_Report::filename() . '"' );
				echo DFSC_Report::document( $r ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- escapado en document().
				exit;

			case 'email':
				$r  = self::run( false );
				$to = self::recipients();
				if ( ! $to || ! DFSC_Report::email( $r, $to ) ) {
					set_transient( 'dfsc_error_' . $uid, dfsc_t( 'The email could not be sent. Check that the site can send mail (an SMTP plugin may be needed).' ), 120 );
					self::back();
				}
				self::back( 'sent' );
				break;

			case 'save':
				$schedule = isset( $_POST['schedule'] ) ? sanitize_key( $_POST['schedule'] ) : 'none';
				$schedule = in_array( $schedule, array( 'none', 'weekly', 'monthly' ), true ) ? $schedule : 'none';
				$raw      = isset( $_POST['recipients'] ) ? sanitize_text_field( wp_unslash( $_POST['recipients'] ) ) : '';
				$emails   = array_filter( array_map( 'sanitize_email', array_map( 'trim', explode( ',', $raw ) ) ), 'is_email' );
				update_option(
					self::OPT_CONFIG,
					array(
						'recipients' => implode( ', ', $emails ),
						'schedule'   => $schedule,
						'alerts'     => empty( $_POST['alerts'] ) ? 0 : 1,
						'online'     => empty( $_POST['online'] ) ? 0 : 1,
					)
				);
				wp_clear_scheduled_hook( self::CRON_SEND );
				if ( 'none' !== $schedule ) {
					wp_schedule_event( time() + DAY_IN_SECONDS, 'weekly' === $schedule ? 'weekly' : 'dfsc_monthly', self::CRON_SEND );
				}
				self::back( 'saved' );
				break;
		}
		self::back();
	}

	/**
	 * Vuelve a la página del plugin con un mensaje.
	 *
	 * @param string $msg Clave del mensaje.
	 * @return void
	 */
	private static function back( $msg = '' ) {
		wp_safe_redirect( self::page_url( $msg ? array( 'dfsc_msg' => $msg ) : array() ) );
		exit;
	}

	/**
	 * Correos configurados para los reportes.
	 *
	 * @return array
	 */
	private static function recipients() {
		$s = self::settings();
		$e = array_filter( array_map( 'trim', explode( ',', (string) $s['recipients'] ) ), 'is_email' );
		return $e ? $e : array( get_option( 'admin_email' ) );
	}

	/**
	 * Verificación diaria: avisa por correo si aparece un problema crítico nuevo.
	 *
	 * @return void
	 */
	public static function cron_daily() {
		$prev = self::last();
		$r    = self::run( true );
		$s    = self::settings();
		if ( $s['alerts'] && 'critical' === $r['overall'] ) {
			$prev_ids = array();
			if ( $prev ) {
				foreach ( $prev['checks'] as $c ) {
					if ( 'critical' === $c['status'] ) {
						$prev_ids[] = $c['id'];
					}
				}
			}
			foreach ( $r['checks'] as $c ) {
				if ( 'critical' === $c['status'] && ! in_array( $c['id'], $prev_ids, true ) ) {
					DFSC_Report::email( $r, self::recipients() );
					break;
				}
			}
		}
	}

	/**
	 * Envío programado del reporte.
	 *
	 * @return void
	 */
	public static function cron_send() {
		DFSC_Report::email( self::run( true ), self::recipients() );
	}

	/**
	 * Registra el widget del escritorio.
	 *
	 * @return void
	 */
	public static function dashboard_widget() {
		if ( current_user_can( 'manage_options' ) ) {
			wp_add_dashboard_widget( 'dfsc_widget', dfsc_t( 'Security Check' ), array( __CLASS__, 'render_widget' ) );
		}
	}

	/**
	 * Contenido del widget del escritorio.
	 *
	 * @return void
	 */
	public static function render_widget() {
		$r = self::last();
		if ( ! $r ) {
			$r = self::run( false );
		}
		$colors = array(
			'critical' => '#d63638',
			'warning'  => '#dba617',
			'good'     => '#00a32a',
		);
		echo '<p style="font-size:15px"><span style="display:inline-block;width:10px;height:10px;border-radius:50%;background:' . esc_attr( $colors[ $r['overall'] ] ) . ';margin-right:6px"></span><strong>'
			. esc_html( DFSC_Report::status_label( $r['overall'] ) ) . '</strong> — ' . esc_html( DFSC_Report::overall_text( $r['overall'] ) ) . '</p>';
		if ( $r['recommendation']['needed'] ) {
			echo '<p>' . esc_html( $r['recommendation']['message'] ) . '</p>';
		}
		echo '<p><a class="button" href="' . esc_url( self::page_url() ) . '">' . esc_html( dfsc_t( 'View report' ) ) . '</a></p>';
	}

	/**
	 * Aviso en el panel cuando PHP es vulnerable.
	 *
	 * @return void
	 */
	public static function notice() {
		if ( ! current_user_can( 'manage_options' ) ) {
			return;
		}
		$screen = get_current_screen();
		if ( ! $screen || ! in_array( $screen->id, array( 'dashboard', 'plugins', 'update-core' ), true ) ) {
			return;
		}
		$r = self::last();
		if ( ! $r || ! $r['php_vulnerable'] ) {
			return;
		}
		echo '<div class="notice notice-error"><p><strong>' . esc_html( dfsc_t( 'PHP security' ) ) . ':</strong> '
			. esc_html( $r['recommendation']['message'] ) . ' <a href="' . esc_url( self::page_url() ) . '">' . esc_html( dfsc_t( 'View report' ) ) . '</a></p></div>';
	}

	/**
	 * Agrega la prueba a Salud del sitio.
	 *
	 * @param array $tests Pruebas registradas.
	 * @return array
	 */
	public static function site_health( $tests ) {
		$tests['direct']['dfsc_php_vulns'] = array(
			'label' => dfsc_t( 'PHP known vulnerabilities' ),
			'test'  => array( __CLASS__, 'site_health_test' ),
		);
		return $tests;
	}

	/**
	 * Prueba de Salud del sitio.
	 *
	 * @return array
	 */
	public static function site_health_test() {
		$version = DFSC_Advisories::runtime_version();
		$adv     = DFSC_Advisories::evaluate( $version );
		$open    = array();
		foreach ( $adv as $a ) {
			if ( 'patched' !== $a['status'] ) {
				$open = array_merge( $open, $a['cves'] );
			}
		}
		$rec = DFSC_Checks::php_recommendation( $version, $adv );

		if ( $open ) {
			$label = dfsc_t( 'PHP %1$s is affected by %2$s', $version, implode( ', ', $open ) );
		} else {
			$label = dfsc_t( 'PHP %s has no known unpatched vulnerabilities', $version );
		}

		return array(
			'label'       => $label,
			'status'      => $open ? 'critical' : 'good',
			'badge'       => array(
				'label' => dfsc_t( 'Security' ),
				'color' => $open ? 'red' : 'blue',
			),
			'description' => '<p>' . esc_html( $rec['message'] ) . '</p>',
			'actions'     => '<p><a href="' . esc_url( self::page_url() ) . '">' . esc_html( dfsc_t( 'View report' ) ) . '</a></p>',
			'test'        => 'dfsc_php_vulns',
		);
	}

	/**
	 * Intervalo mensual para el reporte automático.
	 *
	 * @param array $schedules Intervalos registrados.
	 * @return array
	 */
	public static function cron_schedules( $schedules ) {
		$schedules['dfsc_monthly'] = array(
			'interval' => 30 * DAY_IN_SECONDS,
			'display'  => 'Monthly (DF Security Check)',
		);
		return $schedules;
	}
}
