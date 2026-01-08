<?php
/**
 * Malware Scanner Page View
 *
 * @package AtomicEdge
 */

// Prevent direct access.
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

$scanner      = AtomicEdge::get_instance()->scanner;
$last_scan    = $scanner->get_last_scan_time();
$last_results = $scanner->get_last_results();
?>
<div class="wrap atomicedge-wrap">
	<h1><img src="<?php echo esc_url( ATOMICEDGE_PLUGIN_URL . 'assets/images/logo.svg' ); ?>" alt="<?php esc_attr_e( 'Atomic Edge', 'atomicedge' ); ?>" class="atomicedge-logo" /></h1>

	<div class="atomicedge-scanner">
		<!-- Scanner Controls -->
		<div class="atomicedge-scanner-controls">
			<div class="atomicedge-scanner-info">
				<?php if ( $last_scan ) : ?>
					<p>
						<?php
						printf(
							/* translators: %s: last scan time */
							esc_html__( 'Last scan: %s', 'atomicedge' ),
							esc_html( $last_scan )
						);
						?>
					</p>
				<?php else : ?>
					<p><?php esc_html_e( 'No scans have been run yet.', 'atomicedge' ); ?></p>
				<?php endif; ?>
			</div>

			<div class="atomicedge-scanner-actions">
				<div class="atomicedge-scan-controls" style="display: flex; align-items: flex-start; gap: 12px;">
					<div class="atomicedge-scan-controls-left" style="display: flex; flex-direction: column;">
						<label for="atomicedge-scan-mode" class="screen-reader-text"><?php esc_html_e( 'Scan mode', 'atomicedge' ); ?></label>
						<select id="atomicedge-scan-mode" class="atomicedge-scan-mode">
							<option value="php" selected><?php esc_html_e( 'Quick scan (PHP only)', 'atomicedge' ); ?></option>
							<option value="all"><?php esc_html_e( 'Thorough scan (all files)', 'atomicedge' ); ?></option>
						</select>

						<label for="atomicedge-verify-integrity" style="margin-top: 8px;">
							<input type="checkbox" id="atomicedge-verify-integrity" value="1" />
							<?php esc_html_e( 'Verify AtomicEdge plugin integrity', 'atomicedge' ); ?>
						</label>
					</div>

					<div class="atomicedge-scan-controls-right">
						<button type="button" id="atomicedge-run-scan" class="button button-primary button-hero">
							<span class="dashicons dashicons-search"></span>
							<?php esc_html_e( 'Run Scan', 'atomicedge' ); ?>
						</button>

						<button type="button" id="atomicedge-cancel-scan" class="button" style="margin-left: 8px;">
							<?php esc_html_e( 'Cancel Scan', 'atomicedge' ); ?>
						</button>

						<button type="button" id="atomicedge-reset-scan" class="button" style="margin-left: 8px;">
							<?php esc_html_e( 'Reset Scan', 'atomicedge' ); ?>
						</button>
					</div>
				</div>
			</div>
		</div>

		<!-- Scan Progress -->
		<div id="atomicedge-scan-progress" class="atomicedge-scan-progress" style="display: none;">
			<div class="atomicedge-progress-bar">
				<div class="atomicedge-progress-fill"></div>
			</div>
			<p class="atomicedge-progress-text"><?php esc_html_e( 'Scanning files...', 'atomicedge' ); ?></p>
		</div>

		<!-- Live Scan Log -->
		<div id="atomicedge-scan-log" class="atomicedge-results-section" style="display: none;">
			<h3><?php esc_html_e( 'Live Scan Activity', 'atomicedge' ); ?></h3>
			<p class="description"><?php esc_html_e( 'Shows what the scanner is working on right now. If progress stalls, this should still update as files are processed.', 'atomicedge' ); ?></p>
			<div class="atomicedge-scan-log" style="max-height: 240px; overflow: auto; background: #fff; border: 1px solid #ccd0d4; padding: 10px;">
				<pre class="atomicedge-scan-log-lines" style="margin: 0; white-space: pre-wrap;"></pre>
			</div>
		</div>

		<!-- Scan Results -->
		<div id="atomicedge-scan-results" class="atomicedge-scan-results">
			<?php if ( ! empty( $last_results ) ) : ?>
				<!-- Summary -->
				<div class="atomicedge-results-summary">
					<h2><?php esc_html_e( 'Scan Results', 'atomicedge' ); ?></h2>

					<div class="atomicedge-summary-grid">
						<div class="atomicedge-summary-item <?php echo empty( $last_results['core_files'] ) ? 'atomicedge-ok' : 'atomicedge-warning'; ?>">
							<span class="dashicons <?php echo empty( $last_results['core_files'] ) ? 'dashicons-yes-alt' : 'dashicons-warning'; ?>"></span>
							<span class="atomicedge-summary-count"><?php echo esc_html( count( $last_results['core_files'] ?? array() ) ); ?></span>
							<span class="atomicedge-summary-label"><?php esc_html_e( 'Modified Core Files', 'atomicedge' ); ?></span>
						</div>
						<div class="atomicedge-summary-item <?php echo empty( $last_results['suspicious'] ) ? 'atomicedge-ok' : 'atomicedge-critical'; ?>">
							<span class="dashicons <?php echo empty( $last_results['suspicious'] ) ? 'dashicons-yes-alt' : 'dashicons-dismiss'; ?>"></span>
							<span class="atomicedge-summary-count"><?php echo esc_html( count( $last_results['suspicious'] ?? array() ) ); ?></span>
							<span class="atomicedge-summary-label"><?php esc_html_e( 'Suspicious Files', 'atomicedge' ); ?></span>
						</div>
						<?php if ( array_key_exists( 'integrity_issues', $last_results ) ) : ?>
							<?php $integrity_issues = is_array( $last_results['integrity_issues'] ?? null ) ? $last_results['integrity_issues'] : array(); ?>
							<div class="atomicedge-summary-item <?php echo empty( $integrity_issues ) ? 'atomicedge-ok' : 'atomicedge-warning'; ?>">
								<span class="dashicons <?php echo empty( $integrity_issues ) ? 'dashicons-yes-alt' : 'dashicons-warning'; ?>"></span>
								<span class="atomicedge-summary-count"><?php echo esc_html( count( $integrity_issues ) ); ?></span>
								<span class="atomicedge-summary-label"><?php esc_html_e( 'Integrity Issues', 'atomicedge' ); ?></span>
							</div>
						<?php endif; ?>
					</div>
				</div>

				<?php
				$scan_diagnostics = isset( $last_results['scan_diagnostics'] ) && is_array( $last_results['scan_diagnostics'] ) ? $last_results['scan_diagnostics'] : array();
				$diag_warnings = isset( $scan_diagnostics['warnings'] ) && is_array( $scan_diagnostics['warnings'] ) ? $scan_diagnostics['warnings'] : array();
				$diag_counts = isset( $scan_diagnostics['counts'] ) && is_array( $scan_diagnostics['counts'] ) ? $scan_diagnostics['counts'] : array();
				$diag_samples = isset( $scan_diagnostics['samples'] ) && is_array( $scan_diagnostics['samples'] ) ? $scan_diagnostics['samples'] : array();
				$diag_areas = isset( $scan_diagnostics['areas'] ) && is_array( $scan_diagnostics['areas'] ) ? $scan_diagnostics['areas'] : array();
				?>

				<?php if ( ! empty( $scan_diagnostics ) ) : ?>
					<div class="atomicedge-results-section">
						<h3><?php esc_html_e( 'Scan Coverage & Warnings', 'atomicedge' ); ?></h3>

						<?php
						$stopped_early        = ! empty( $scan_diagnostics['stopped_early'] );
						$stopped_early_reason = isset( $scan_diagnostics['stopped_early_reason'] ) ? (string) $scan_diagnostics['stopped_early_reason'] : '';
						$stopped_early_reason_label = '';
						switch ( $stopped_early_reason ) {
							case 'memory_limit':
								$stopped_early_reason_label = __( 'Memory limit reached', 'atomicedge' );
								break;
							case 'timeout':
								$stopped_early_reason_label = __( 'Execution time limit reached', 'atomicedge' );
								break;
							default:
								$stopped_early_reason_label = '';
								break;
						}
						?>

						<?php if ( $stopped_early ) : ?>
							<p><strong><?php esc_html_e( 'Stopped early:', 'atomicedge' ); ?></strong> <?php echo esc_html( $stopped_early_reason_label ? $stopped_early_reason_label : __( 'Scan did not complete', 'atomicedge' ) ); ?><?php echo esc_html( $stopped_early_reason ? ' (' . $stopped_early_reason . ')' : '' ); ?></p>
						<?php endif; ?>

						<?php if ( ! empty( $diag_warnings ) ) : ?>
							<div class="notice notice-warning inline">
								<p><strong><?php esc_html_e( 'This scan may be incomplete.', 'atomicedge' ); ?></strong></p>
								<ul>
									<?php foreach ( array_slice( $diag_warnings, 0, 10 ) as $warning ) : ?>
										<li><?php echo esc_html( $warning ); ?></li>
									<?php endforeach; ?>
								</ul>
							</div>
						<?php endif; ?>

						<?php
						$counts_line = array();
						if ( ! empty( $diag_counts['dirs_unreadable'] ) ) {
							$counts_line[] = sprintf( __( 'Unreadable dirs: %d', 'atomicedge' ), (int) $diag_counts['dirs_unreadable'] );
						}
						if ( ! empty( $diag_counts['dirs_missing'] ) ) {
							$counts_line[] = sprintf( __( 'Missing dirs: %d', 'atomicedge' ), (int) $diag_counts['dirs_missing'] );
						}
						if ( ! empty( $diag_counts['files_read_failed'] ) ) {
							$counts_line[] = sprintf( __( 'Read failures: %d', 'atomicedge' ), (int) $diag_counts['files_read_failed'] );
						}
						if ( ! empty( $diag_counts['files_partially_scanned'] ) ) {
							$counts_line[] = sprintf( __( 'Oversized partially scanned: %d', 'atomicedge' ), (int) $diag_counts['files_partially_scanned'] );
						}
						if ( ! empty( $diag_counts['files_skipped_whitelist'] ) ) {
							$counts_line[] = sprintf( __( 'Whitelisted skipped: %d', 'atomicedge' ), (int) $diag_counts['files_skipped_whitelist'] );
						}
						?>

						<?php if ( ! empty( $counts_line ) ) : ?>
							<p><?php echo esc_html( implode( ' · ', $counts_line ) ); ?></p>
						<?php endif; ?>

						<?php if ( ! empty( $diag_areas ) ) : ?>
							<table class="wp-list-table widefat fixed striped">
								<thead>
									<tr>
										<th><?php esc_html_e( 'Area', 'atomicedge' ); ?></th>
										<th><?php esc_html_e( 'PHP found', 'atomicedge' ); ?></th>
										<th><?php esc_html_e( 'PHP scanned', 'atomicedge' ); ?></th>
									</tr>
								</thead>
								<tbody>
									<?php foreach ( $diag_areas as $area_key => $area_stats ) : ?>
										<tr>
											<td><?php echo esc_html( (string) $area_key ); ?></td>
											<td><?php echo esc_html( isset( $area_stats['php_files_found'] ) ? (string) (int) $area_stats['php_files_found'] : '0' ); ?></td>
											<td><?php echo esc_html( isset( $area_stats['php_files_scanned'] ) ? (string) (int) $area_stats['php_files_scanned'] : '0' ); ?></td>
										</tr>
									<?php endforeach; ?>
								</tbody>
							</table>
						<?php endif; ?>

						<?php if ( ! empty( $diag_samples['unreadable_dirs'] ) || ! empty( $diag_samples['read_failed_files'] ) || ! empty( $diag_samples['oversized_files'] ) ) : ?>
							<p class="description"><em><?php esc_html_e( 'Examples (first 5):', 'atomicedge' ); ?></em></p>
							<ul>
								<?php if ( ! empty( $diag_samples['unreadable_dirs'] ) ) : ?>
									<li><?php echo esc_html__( 'Unreadable dirs:', 'atomicedge' ) . ' ' . esc_html( implode( ', ', $diag_samples['unreadable_dirs'] ) ); ?></li>
								<?php endif; ?>
								<?php if ( ! empty( $diag_samples['read_failed_files'] ) ) : ?>
									<li><?php echo esc_html__( 'Read failures:', 'atomicedge' ) . ' ' . esc_html( implode( ', ', $diag_samples['read_failed_files'] ) ); ?></li>
								<?php endif; ?>
								<?php if ( ! empty( $diag_samples['oversized_files'] ) ) : ?>
									<li><?php echo esc_html__( 'Oversized partially scanned:', 'atomicedge' ) . ' ' . esc_html( implode( ', ', $diag_samples['oversized_files'] ) ); ?></li>
								<?php endif; ?>
							</ul>
						<?php endif; ?>
					</div>
				<?php endif; ?>

				<?php if ( ! empty( $last_results['integrity_issues'] ) && is_array( $last_results['integrity_issues'] ) ) : ?>
					<div class="atomicedge-results-section" data-paginate="true" data-per-page="10">
						<h3>
							<?php esc_html_e( 'AtomicEdge Plugin Integrity Issues', 'atomicedge' ); ?>
							<span class="atomicedge-results-count">(<?php echo esc_html( count( $last_results['integrity_issues'] ) ); ?>)</span>
						</h3>
						<p class="description"><?php esc_html_e( 'These files did not match the expected release manifest. This can indicate tampering or a partial/failed update.', 'atomicedge' ); ?></p>
						<table class="wp-list-table widefat fixed striped atomicedge-paginated-table">
							<thead>
								<tr>
									<th><?php esc_html_e( 'File', 'atomicedge' ); ?></th>
									<th><?php esc_html_e( 'Issue', 'atomicedge' ); ?></th>
								</tr>
							</thead>
							<tbody>
								<?php foreach ( $last_results['integrity_issues'] as $issue ) : ?>
									<tr>
										<td><code><?php echo esc_html( $issue['file'] ?? '' ); ?></code></td>
										<td><?php echo esc_html( $issue['reason'] ?? ( $issue['type'] ?? '' ) ); ?></td>
									</tr>
								<?php endforeach; ?>
							</tbody>
						</table>
						<div class="atomicedge-pagination"></div>
					</div>
				<?php endif; ?>

				<!-- Modified Core Files -->
				<?php if ( ! empty( $last_results['core_files'] ) ) : ?>
					<div class="atomicedge-results-section" data-paginate="true" data-per-page="10">
						<h3>
							<?php esc_html_e( 'Modified Core Files', 'atomicedge' ); ?>
							<span class="atomicedge-results-count">(<?php echo esc_html( count( $last_results['core_files'] ) ); ?>)</span>
						</h3>
						<p class="description"><?php esc_html_e( 'These WordPress core files have been modified from their original versions.', 'atomicedge' ); ?></p>
						<table class="wp-list-table widefat fixed striped atomicedge-paginated-table">
							<thead>
								<tr>
									<th><?php esc_html_e( 'File', 'atomicedge' ); ?></th>
									<th><?php esc_html_e( 'Severity', 'atomicedge' ); ?></th>
								</tr>
							</thead>
							<tbody>
								<?php foreach ( $last_results['core_files'] as $issue ) : ?>
									<tr>
										<td><code><?php echo esc_html( $issue['file_path'] ?? $issue['file'] ); ?></code></td>
										<td>
											<span class="atomicedge-severity atomicedge-severity-<?php echo esc_attr( $issue['severity'] ); ?>">
												<?php echo esc_html( ucfirst( $issue['severity'] ) ); ?>
											</span>
										</td>
									</tr>
								<?php endforeach; ?>
							</tbody>
						</table>
						<div class="atomicedge-pagination"></div>
					</div>
				<?php endif; ?>

				<!-- Suspicious Files -->
				<?php if ( ! empty( $last_results['suspicious'] ) ) : ?>
					<div class="atomicedge-results-section" data-paginate="true" data-per-page="10">
						<h3>
							<?php esc_html_e( 'Suspicious Files', 'atomicedge' ); ?>
							<span class="atomicedge-results-count">(<?php echo esc_html( count( $last_results['suspicious'] ) ); ?>)</span>
						</h3>
						<p class="description"><?php esc_html_e( 'These files contain potentially malicious code patterns.', 'atomicedge' ); ?></p>
						<table class="wp-list-table widefat fixed striped atomicedge-paginated-table">
							<thead>
								<tr>
									<th><?php esc_html_e( 'File', 'atomicedge' ); ?></th>
									<th><?php esc_html_e( 'Issue', 'atomicedge' ); ?></th>
									<th><?php esc_html_e( 'Severity', 'atomicedge' ); ?></th>
								</tr>
							</thead>
							<tbody>
								<?php foreach ( $last_results['suspicious'] as $issue ) : ?>
									<tr>
										<td><code><?php echo esc_html( $issue['file_path'] ?? $issue['file'] ); ?></code></td>
										<td>
											<?php
											if ( isset( $issue['pattern'] ) ) {
												echo esc_html( $issue['pattern'] );
											} elseif ( isset( $issue['reason'] ) ) {
												echo esc_html( $issue['reason'] );
											}
											?>
										</td>
										<td>
											<span class="atomicedge-severity atomicedge-severity-<?php echo esc_attr( $issue['severity'] ); ?>">
												<?php echo esc_html( ucfirst( $issue['severity'] ) ); ?>
											</span>
										</td>
									</tr>
								<?php endforeach; ?>
							</tbody>
						</table>
						<div class="atomicedge-pagination"></div>
					</div>
				<?php endif; ?>

				<!-- All Clear -->
				<?php if ( empty( $last_results['core_files'] ) && empty( $last_results['suspicious'] ) ) : ?>
					<div class="atomicedge-all-clear">
						<span class="dashicons dashicons-yes-alt"></span>
						<h3><?php esc_html_e( 'All Clear!', 'atomicedge' ); ?></h3>
						<p><?php esc_html_e( 'No security issues were found in the last scan.', 'atomicedge' ); ?></p>
					</div>
				<?php endif; ?>

			<?php else : ?>
				<div class="atomicedge-no-results">
					<span class="dashicons dashicons-search"></span>
					<h3><?php esc_html_e( 'No Scan Results', 'atomicedge' ); ?></h3>
					<p><?php esc_html_e( 'Run a scan to check your WordPress files for security issues.', 'atomicedge' ); ?></p>
				</div>
			<?php endif; ?>
		</div>

		<!-- What We Check -->
		<div class="atomicedge-scanner-info-box">
			<h3><?php esc_html_e( 'What We Check', 'atomicedge' ); ?></h3>
			<ul>
				<li>
					<span class="dashicons dashicons-yes"></span>
					<?php esc_html_e( 'WordPress core files against official checksums', 'atomicedge' ); ?>
				</li>
				<li>
					<span class="dashicons dashicons-yes"></span>
					<?php esc_html_e( 'WordPress root directory for unknown PHP files', 'atomicedge' ); ?>
				</li>
				<li>
					<span class="dashicons dashicons-yes"></span>
					<?php esc_html_e( 'wp-admin and wp-includes for malware patterns', 'atomicedge' ); ?>
				</li>
				<li>
					<span class="dashicons dashicons-yes"></span>
					<?php esc_html_e( 'PHP files in uploads directory (should not exist)', 'atomicedge' ); ?>
				</li>
				<li>
					<span class="dashicons dashicons-yes"></span>
					<?php esc_html_e( 'Suspicious code patterns (eval, base64_decode, etc.)', 'atomicedge' ); ?>
				</li>
				<li>
					<span class="dashicons dashicons-yes"></span>
					<?php esc_html_e( 'Obfuscated code and known webshell signatures', 'atomicedge' ); ?>
				</li>
			</ul>
		</div>

		<!-- PHP Environment Info -->
		<div class="atomicedge-scanner-info-box atomicedge-environment-info">
			<h3><?php esc_html_e( 'Environment', 'atomicedge' ); ?></h3>
			<ul>
				<li>
					<strong><?php esc_html_e( 'Memory Limit:', 'atomicedge' ); ?></strong>
					<?php echo esc_html( ini_get( 'memory_limit' ) ); ?>
				</li>
				<li>
					<strong><?php esc_html_e( 'Max Execution Time:', 'atomicedge' ); ?></strong>
					<?php echo esc_html( ini_get( 'max_execution_time' ) ); ?>s
				</li>
				<li>
					<strong><?php esc_html_e( 'PHP Version:', 'atomicedge' ); ?></strong>
					<?php echo esc_html( PHP_VERSION ); ?>
				</li>
			</ul>
		</div>
	</div>
</div>
