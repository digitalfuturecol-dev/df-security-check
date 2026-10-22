<?php
/**
 * Generación del reporte de estado en el idioma del sitio.
 *
 * @package DF_Security_Check
 */

defined( 'ABSPATH' ) || exit;

/**
 * Arma el reporte en HTML para el panel, la descarga y el correo.
 */
class DFSC_Report {

	/**
	 * Nombre visible de un estado.
	 *
	 * @param string $status critical, warning, good o info.
	 * @return string
	 */
	public static function status_label( $status ) {
		$map = array(
			'critical' => dfsc_t( 'Critical' ),
			'warning'  => dfsc_t( 'Needs attention' ),
			'good'     => dfsc_t( 'OK' ),
			'info'     => dfsc_t( 'Info' ),
		);
		return isset( $map[ $status ] ) ? $map[ $status ] : $status;
	}

	/**
	 * Resumen del estado general.
	 *
	 * @param string $overall critical, warning o good.
	 * @return string
	 */
	public static function overall_text( $overall ) {
		$map = array(
			'critical' => dfsc_t( 'The site has critical issues that must be fixed now.' ),
			'warning'  => dfsc_t( 'The site has no critical issues, but some points need attention.' ),
			'good'     => dfsc_t( 'The site passed all checks.' ),
		);
		return $map[ $overall ];
	}

	/**
	 * Cuerpo del reporte, usado en el panel y dentro del documento descargable.
	 *
	 * @param array $r Resultado de DFSC_Checks::run().
	 * @return string HTML escapado.
	 */
	public static function body( array $r ) {
		$groups = array(
			'php'    => dfsc_t( 'PHP and known vulnerabilities' ),
			'config' => dfsc_t( 'Server configuration' ),
			'wp'     => dfsc_t( 'WordPress' ),
		);
		$rec    = $r['recommendation'];
		$mit    = $r['mitigation'];

		ob_start();
		?>
		<div class="dfsc-report">
			<div class="dfsc-summary dfsc-<?php echo esc_attr( $r['overall'] ); ?>">
				<div class="dfsc-summary-status"><?php echo esc_html( self::status_label( $r['overall'] ) ); ?></div>
				<div class="dfsc-summary-text">
					<strong><?php echo esc_html( self::overall_text( $r['overall'] ) ); ?></strong><br>
					<?php
					echo esc_html(
						dfsc_t( '%1$d critical · %2$d need attention · %3$d OK', $r['counts']['critical'], $r['counts']['warning'], $r['counts']['good'] )
					);
					?>
				</div>
			</div>

			<h2><?php echo esc_html( dfsc_t( 'PHP update recommendation' ) ); ?></h2>
			<div class="dfsc-rec dfsc-rec-<?php echo esc_attr( $rec['urgency'] ); ?>">
				<?php if ( $rec['needed'] ) : ?>
					<p class="dfsc-rec-badge">
						<?php echo esc_html( 'urgent' === $rec['urgency'] ? dfsc_t( 'Urgent: update today' ) : dfsc_t( 'Recommended' ) ); ?>
					</p>
				<?php endif; ?>
				<p class="dfsc-rec-msg"><?php echo esc_html( $rec['message'] ); ?></p>
				<?php if ( $rec['needed'] ) : ?>
					<p><?php echo esc_html( dfsc_t( 'Hosting detected: %s. Steps:', $rec['hosting']['name'] ) ); ?></p>
					<ol>
						<?php foreach ( $rec['steps'] as $step ) : ?>
							<li><?php echo esc_html( $step ); ?></li>
						<?php endforeach; ?>
					</ol>
					<?php if ( $r['php_vulnerable'] ) : ?>
						<p class="dfsc-note">
							<?php
							if ( $mit['applied'] && $mit['effective'] ) {
								echo esc_html( dfsc_t( 'The temporary mitigation is active on this site. It reduces the risk but does not replace the PHP update.' ) );
							} elseif ( $mit['applied'] ) {
								echo esc_html( dfsc_t( 'The temporary mitigation was written to %1$s but PHP has not picked it up yet. It can take up to %2$d seconds, or require restarting PHP.', implode( ', ', $mit['files'] ), max( 300, $mit['cache_ttl'] ) ) );
							} else {
								echo esc_html( dfsc_t( 'While you update, you can apply the temporary mitigation recommended by php.net. It reduces the risk but does not make the site safe.' ) );
							}
							?>
						</p>
					<?php endif; ?>
				<?php endif; ?>
			</div>

			<?php foreach ( $groups as $gid => $gname ) : ?>
				<h2><?php echo esc_html( $gname ); ?></h2>
				<table class="dfsc-table">
					<thead>
						<tr>
							<th><?php echo esc_html( dfsc_t( 'Check' ) ); ?></th>
							<th><?php echo esc_html( dfsc_t( 'Status' ) ); ?></th>
							<th><?php echo esc_html( dfsc_t( 'Value' ) ); ?></th>
							<th><?php echo esc_html( dfsc_t( 'Details' ) ); ?></th>
						</tr>
					</thead>
					<tbody>
					<?php foreach ( $r['checks'] as $c ) : ?>
						<?php
						if ( $c['group'] !== $gid ) {
							continue;
						}
						?>
						<tr>
							<td><?php echo esc_html( $c['label'] ); ?></td>
							<td><span class="dfsc-pill dfsc-<?php echo esc_attr( $c['status'] ); ?>"><?php echo esc_html( self::status_label( $c['status'] ) ); ?></span></td>
							<td><code><?php echo esc_html( $c['value'] ); ?></code></td>
							<td>
								<?php echo esc_html( $c['detail'] ); ?>
								<?php if ( ! empty( $c['link'] ) ) : ?>
									<a class="dfsc-link" href="<?php echo esc_url( $c['link'] ); ?>"><?php echo esc_html( dfsc_t( 'Fix' ) ); ?> →</a>
								<?php endif; ?>
							</td>
						</tr>
					<?php endforeach; ?>
					</tbody>
				</table>
			<?php endforeach; ?>

			<h2><?php echo esc_html( dfsc_t( 'Environment' ) ); ?></h2>
			<table class="dfsc-table dfsc-env">
				<?php foreach ( $r['environment'] as $k => $v ) : ?>
					<tr><th><?php echo esc_html( $k ); ?></th><td><code><?php echo esc_html( $v ); ?></code></td></tr>
				<?php endforeach; ?>
			</table>

			<p class="dfsc-footer">
				<?php
				echo esc_html(
					dfsc_t( 'Report generated on %1$s at %2$s by DF Security Check %3$s — Digital Future.', DFSC_I18n::date( $r['generated'] ), DFSC_I18n::time( $r['generated'] ), DFSC_VERSION )
				);
				?>
				<br>
				<?php
				$info = DFSC_Advisories::data_info();
				echo esc_html(
					dfsc_t(
						'Vulnerability data updated on %1$s (%2$s).',
						DFSC_I18n::date( $info['updated'] ),
						'remote' === $info['source'] ? dfsc_t( 'project repository' ) : dfsc_t( 'included in the plugin' )
					)
				);
				?>
				<br>
				<?php echo esc_html( dfsc_t( 'Sources: php.net security announcements. This report checks the PHP version and configuration; it does not replace a full security audit.' ) ); ?>
			</p>
		</div>
		<?php
		return ob_get_clean();
	}

	/**
	 * Estilos del reporte.
	 *
	 * @return string
	 */
	public static function css() {
		return '
.dfsc-report{font:14px/1.5 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;color:#1d2327;max-width:1100px}
.dfsc-report h2{font-size:17px;margin:28px 0 10px}
.dfsc-summary{display:flex;gap:16px;align-items:center;padding:16px 20px;border-radius:8px;border:1px solid #dcdcde;background:#fff}
.dfsc-summary-status{font-size:20px;font-weight:700;padding:8px 14px;border-radius:6px;white-space:nowrap}
.dfsc-summary.dfsc-critical .dfsc-summary-status{background:#fcf0f1;color:#8a1f11}
.dfsc-summary.dfsc-warning .dfsc-summary-status{background:#fcf9e8;color:#7a5b00}
.dfsc-summary.dfsc-good .dfsc-summary-status{background:#edfaef;color:#00631f}
.dfsc-rec{padding:14px 20px;border-radius:8px;border:1px solid #dcdcde;background:#fff}
.dfsc-rec-urgent{border-left:5px solid #d63638}
.dfsc-rec-recommended{border-left:5px solid #dba617}
.dfsc-rec-none{border-left:5px solid #00a32a}
.dfsc-rec-badge{display:inline-block;margin:0 0 6px;padding:2px 10px;border-radius:12px;background:#d63638;color:#fff;font-weight:600;font-size:12px}
.dfsc-rec-recommended .dfsc-rec-badge{background:#dba617}
.dfsc-rec-msg{font-size:15px;font-weight:600;margin:4px 0 10px}
.dfsc-rec ol{margin:0 0 10px 20px}
.dfsc-note{background:#f0f6fc;padding:8px 12px;border-radius:6px}
.dfsc-table{width:100%;border-collapse:collapse;background:#fff;border:1px solid #dcdcde}
.dfsc-table th,.dfsc-table td{text-align:left;vertical-align:top;padding:8px 10px;border-bottom:1px solid #f0f0f1}
.dfsc-table thead th{background:#f6f7f7;font-weight:600}
.dfsc-table td:first-child{width:24%;font-weight:500}
.dfsc-table td:nth-child(2){width:120px}
.dfsc-table td:nth-child(3){white-space:nowrap}
.dfsc-env th{width:24%;font-weight:500}
.dfsc-table code{word-break:break-all;background:none;padding:0}
.dfsc-pill{display:inline-block;padding:2px 8px;border-radius:10px;font-size:12px;font-weight:600;white-space:nowrap}
.dfsc-pill.dfsc-critical{background:#fcf0f1;color:#8a1f11}
.dfsc-pill.dfsc-warning{background:#fcf9e8;color:#7a5b00}
.dfsc-pill.dfsc-good{background:#edfaef;color:#00631f}
.dfsc-pill.dfsc-info{background:#f0f6fc;color:#0a4b78}
.dfsc-link{white-space:nowrap;margin-left:4px}
.dfsc-footer{color:#646970;font-size:12px;margin-top:24px}
@media (max-width:782px){
.dfsc-summary{flex-direction:column;align-items:flex-start}
.dfsc-table thead{display:none}
.dfsc-table,.dfsc-table tbody,.dfsc-table tr,.dfsc-table td,.dfsc-table th{display:block;width:auto!important}
.dfsc-table tr{padding:10px 12px;border-bottom:1px solid #f0f0f1}
.dfsc-table td,.dfsc-table th{border:0;padding:2px 0}
.dfsc-table td:nth-child(3){white-space:normal}
.dfsc-env th{color:#646970;font-size:12px}
}
@media print{.dfsc-link{display:none}}
';
	}

	/**
	 * Documento HTML completo, independiente del panel, en el idioma del sitio.
	 *
	 * @param array $r Resultado de DFSC_Checks::run().
	 * @return string
	 */
	public static function document( array $r ) {
		$title = dfsc_t( 'Security status report' ) . ' — ' . wp_parse_url( home_url(), PHP_URL_HOST );
		return '<!doctype html><html lang="' . esc_attr( DFSC_I18n::html_lang() ) . '"><head><meta charset="utf-8">'
			. '<meta name="viewport" content="width=device-width,initial-scale=1"><title>' . esc_html( $title ) . '</title>'
			. '<style>body{margin:0;padding:24px 16px;background:#f6f7f7}' . self::css() . '.dfsc-report{margin:0 auto}h1{font:600 22px/1.3 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;max-width:1100px;margin:0 auto 16px}</style></head><body>'
			. '<h1>' . esc_html( $title ) . '</h1>'
			. self::body( $r )
			. '</body></html>';
	}

	/**
	 * Nombre del archivo del reporte.
	 *
	 * @return string
	 */
	public static function filename() {
		$host = sanitize_file_name( (string) wp_parse_url( home_url(), PHP_URL_HOST ) );
		return sanitize_file_name( dfsc_t( 'security-report' ) ) . '-' . $host . '-' . wp_date( 'Y-m-d' ) . '.html';
	}

	/**
	 * Envía el reporte por correo (cuerpo HTML y archivo adjunto).
	 *
	 * @param array        $r  Resultado de DFSC_Checks::run().
	 * @param string|array $to Destinatarios.
	 * @return bool
	 */
	public static function email( array $r, $to ) {
		$host    = wp_parse_url( home_url(), PHP_URL_HOST );
		$subject = sprintf( '[%s] %s: %s', $host, dfsc_t( 'Security status report' ), self::status_label( $r['overall'] ) );
		$doc     = self::document( $r );

		// Archivo temporal con nombre aleatorio (wp_tempnam lo crea de forma exclusiva); el adjunto
		// conserva un nombre legible gracias a las claves del arreglo de adjuntos (WordPress 6.2+).
		require_once ABSPATH . 'wp-admin/includes/file.php';
		$tmp = wp_tempnam( 'dfsc-report' );
		if ( ! $tmp || false === file_put_contents( $tmp, $doc ) ) { // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_file_put_contents
			return wp_mail( $to, $subject, $doc, array( 'Content-Type: text/html; charset=UTF-8' ) );
		}

		$sent = wp_mail( $to, $subject, $doc, array( 'Content-Type: text/html; charset=UTF-8' ), array( self::filename() => $tmp ) );
		wp_delete_file( $tmp );
		return $sent;
	}
}
