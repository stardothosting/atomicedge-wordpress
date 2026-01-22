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

$atomicedge_scanner      = AtomicEdge::get_instance()->scanner;
$atomicedge_last_scan    = $atomicedge_scanner->get_last_scan_time();
$atomicedge_last_results = $atomicedge_scanner->get_last_results();
?>
<div class="wrap atomicedge-wrap">
	<h1><img src="<?php echo esc_url( ATOMICEDGE_PLUGIN_URL . 'assets/images/logo.svg' ); ?>" alt="<?php esc_attr_e( 'Atomic Edge', 'atomic-edge-security' ); ?>" class="atomicedge-logo" /></h1>

	<div class="atomicedge-scanner">
		<!-- Scanner Controls -->
		<div class="atomicedge-scanner-controls">
			<div class="atomicedge-scanner-info">
				<?php if ( $atomicedge_last_scan ) : ?>
					<p>
						<?php
						printf(
							/* translators: %s: last scan time */
							esc_html__( 'Last scan: %s', 'atomic-edge-security' ),
							esc_html( $atomicedge_last_scan )
						);
						?>
					</p>
				<?php else : ?>
					<p><?php esc_html_e( 'No scans have been run yet.', 'atomic-edge-security' ); ?></p>
				<?php endif; ?>
			</div>

			<div class="atomicedge-scanner-actions">
				<div class="atomicedge-scan-controls" style="display: flex; align-items: flex-start; gap: 12px;">
					<div class="atomicedge-scan-controls-left" style="display: flex; flex-direction: column;">
						<label for="atomicedge-scan-mode" class="screen-reader-text"><?php esc_html_e( 'Scan mode', 'atomic-edge-security' ); ?></label>
						<select id="atomicedge-scan-mode" class="atomicedge-scan-mode">
							<option value="php" selected><?php esc_html_e( 'Quick scan (PHP only)', 'atomic-edge-security' ); ?></option>
							<option value="all"><?php esc_html_e( 'Thorough scan (all files)', 'atomic-edge-security' ); ?></option>
						</select>

						<label for="atomicedge-verify-integrity" style="margin-top: 8px;">
							<input type="checkbox" id="atomicedge-verify-integrity" value="1" />
							<?php esc_html_e( 'Verify AtomicEdge plugin integrity', 'atomic-edge-security' ); ?>
						</label>
					</div>

					<div class="atomicedge-scan-controls-right">
						<button type="button" id="atomicedge-run-scan" class="button button-primary button-hero">
							<span class="dashicons dashicons-search"></span>
							<?php esc_html_e( 'Run Scan', 'atomic-edge-security' ); ?>
						</button>

						<button type="button" id="atomicedge-cancel-scan" class="button button-hero atomicedge-secondary-button">
							<span class="dashicons dashicons-no-alt"></span>
							<?php esc_html_e( 'Cancel Scan', 'atomic-edge-security' ); ?>
						</button>

						<button type="button" id="atomicedge-reset-scan" class="button button-hero atomicedge-secondary-button">
							<span class="dashicons dashicons-trash"></span>
							<?php esc_html_e( 'Reset Scan', 'atomic-edge-security' ); ?>
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
			<p class="atomicedge-progress-text"><?php esc_html_e( 'Scanning files...', 'atomic-edge-security' ); ?></p>
		</div>

		<!-- Live Scan Log -->
		<div id="atomicedge-scan-log" class="atomicedge-results-section" style="display: none;">
			<h3><?php esc_html_e( 'Live Scan Activity', 'atomic-edge-security' ); ?></h3>
			<p class="description"><?php esc_html_e( 'Shows what the scanner is working on right now. If progress stalls, this should still update as files are processed.', 'atomic-edge-security' ); ?></p>
			<div class="atomicedge-scan-log" style="max-height: 240px; overflow: auto; background: #fff; border: 1px solid #ccd0d4; padding: 10px;">
				<pre class="atomicedge-scan-log-lines" style="margin: 0; white-space: pre-wrap;"></pre>
			</div>
		</div>

		<!-- Scan Results -->
		<div id="atomicedge-scan-results" class="atomicedge-scan-results">
			<?php if ( ! empty( $atomicedge_last_results ) ) : ?>
				<!-- Summary -->
				<div class="atomicedge-results-summary">
					<h2><?php esc_html_e( 'Scan Results', 'atomic-edge-security' ); ?></h2>

					<div class="atomicedge-summary-grid">
						<div class="atomicedge-summary-item <?php echo empty( $atomicedge_last_results['core_files'] ) ? 'atomicedge-ok' : 'atomicedge-warning'; ?>">
							<span class="dashicons <?php echo empty( $atomicedge_last_results['core_files'] ) ? 'dashicons-yes-alt' : 'dashicons-warning'; ?>"></span>
							<span class="atomicedge-summary-count"><?php echo esc_html( count( $atomicedge_last_results['core_files'] ?? array() ) ); ?></span>
							<span class="atomicedge-summary-label"><?php esc_html_e( 'Modified Core Files', 'atomic-edge-security' ); ?></span>
						</div>
						<div class="atomicedge-summary-item <?php echo empty( $atomicedge_last_results['suspicious'] ) ? 'atomicedge-ok' : 'atomicedge-critical'; ?>">
							<span class="dashicons <?php echo empty( $atomicedge_last_results['suspicious'] ) ? 'dashicons-yes-alt' : 'dashicons-dismiss'; ?>"></span>
							<span class="atomicedge-summary-count"><?php echo esc_html( count( $atomicedge_last_results['suspicious'] ?? array() ) ); ?></span>
							<span class="atomicedge-summary-label"><?php esc_html_e( 'Suspicious Files', 'atomic-edge-security' ); ?></span>
						</div>
						<?php if ( array_key_exists( 'integrity_issues', $atomicedge_last_results ) ) : ?>
							<?php $atomicedge_integrity_issues = is_array( $atomicedge_last_results['integrity_issues'] ?? null ) ? $atomicedge_last_results['integrity_issues'] : array(); ?>
							<div class="atomicedge-summary-item <?php echo empty( $atomicedge_integrity_issues ) ? 'atomicedge-ok' : 'atomicedge-warning'; ?>">
								<span class="dashicons <?php echo empty( $atomicedge_integrity_issues ) ? 'dashicons-yes-alt' : 'dashicons-warning'; ?>"></span>
								<span class="atomicedge-summary-count"><?php echo esc_html( count( $atomicedge_integrity_issues ) ); ?></span>
								<span class="atomicedge-summary-label"><?php esc_html_e( 'Integrity Issues', 'atomic-edge-security' ); ?></span>
							</div>
						<?php endif; ?>
					</div>
				</div>

				<?php
				$atomicedge_scan_diagnostics = isset( $atomicedge_last_results['scan_diagnostics'] ) && is_array( $atomicedge_last_results['scan_diagnostics'] ) ? $atomicedge_last_results['scan_diagnostics'] : array();
				$atomicedge_diag_warnings    = isset( $atomicedge_scan_diagnostics['warnings'] ) && is_array( $atomicedge_scan_diagnostics['warnings'] ) ? $atomicedge_scan_diagnostics['warnings'] : array();
				$atomicedge_diag_counts      = isset( $atomicedge_scan_diagnostics['counts'] ) && is_array( $atomicedge_scan_diagnostics['counts'] ) ? $atomicedge_scan_diagnostics['counts'] : array();
				$atomicedge_diag_samples     = isset( $atomicedge_scan_diagnostics['samples'] ) && is_array( $atomicedge_scan_diagnostics['samples'] ) ? $atomicedge_scan_diagnostics['samples'] : array();
				$atomicedge_diag_areas       = isset( $atomicedge_scan_diagnostics['areas'] ) && is_array( $atomicedge_scan_diagnostics['areas'] ) ? $atomicedge_scan_diagnostics['areas'] : array();
				?>

				<?php if ( ! empty( $atomicedge_scan_diagnostics ) ) : ?>
					<div class="atomicedge-results-section">
						<h3><?php esc_html_e( 'Scan Coverage & Warnings', 'atomic-edge-security' ); ?></h3>

						<?php
						$atomicedge_stopped_early              = ! empty( $atomicedge_scan_diagnostics['stopped_early'] );
						$atomicedge_stopped_early_reason       = isset( $atomicedge_scan_diagnostics['stopped_early_reason'] ) ? (string) $atomicedge_scan_diagnostics['stopped_early_reason'] : '';
						$atomicedge_stopped_early_reason_label = '';
						switch ( $atomicedge_stopped_early_reason ) {
							case 'memory_limit':
								$atomicedge_stopped_early_reason_label = __( 'Memory limit reached', 'atomic-edge-security' );
								break;
							case 'timeout':
								$atomicedge_stopped_early_reason_label = __( 'Execution time limit reached', 'atomic-edge-security' );
								break;
							default:
								$atomicedge_stopped_early_reason_label = '';
								break;
						}
						?>

						<?php if ( $atomicedge_stopped_early ) : ?>
							<p><strong><?php esc_html_e( 'Stopped early:', 'atomic-edge-security' ); ?></strong> <?php echo esc_html( $atomicedge_stopped_early_reason_label ? $atomicedge_stopped_early_reason_label : __( 'Scan did not complete', 'atomic-edge-security' ) ); ?><?php echo esc_html( $atomicedge_stopped_early_reason ? ' (' . $atomicedge_stopped_early_reason . ')' : '' ); ?></p>
						<?php endif; ?>

						<?php if ( ! empty( $atomicedge_diag_warnings ) ) : ?>
							<div class="notice notice-warning inline">
								<p><strong><?php esc_html_e( 'This scan may be incomplete.', 'atomic-edge-security' ); ?></strong></p>
								<ul>
									<?php foreach ( array_slice( $atomicedge_diag_warnings, 0, 10 ) as $atomicedge_warning ) : ?>
										<li><?php echo esc_html( $atomicedge_warning ); ?></li>
									<?php endforeach; ?>
								</ul>
							</div>
						<?php endif; ?>

						<?php
						$atomicedge_counts_line = array();
						if ( ! empty( $atomicedge_diag_counts['dirs_unreadable'] ) ) {
							/* translators: %d: number of unreadable directories */
							$atomicedge_counts_line[] = sprintf( __( 'Unreadable dirs: %d', 'atomic-edge-security' ), (int) $atomicedge_diag_counts['dirs_unreadable'] );
						}
						if ( ! empty( $atomicedge_diag_counts['dirs_missing'] ) ) {
							/* translators: %d: number of missing directories */
							$atomicedge_counts_line[] = sprintf( __( 'Missing dirs: %d', 'atomic-edge-security' ), (int) $atomicedge_diag_counts['dirs_missing'] );
						}
						if ( ! empty( $atomicedge_diag_counts['files_read_failed'] ) ) {
							/* translators: %d: number of file read failures */
							$atomicedge_counts_line[] = sprintf( __( 'Read failures: %d', 'atomic-edge-security' ), (int) $atomicedge_diag_counts['files_read_failed'] );
						}
						if ( ! empty( $atomicedge_diag_counts['files_partially_scanned'] ) ) {
							/* translators: %d: number of oversized files partially scanned */
							$atomicedge_counts_line[] = sprintf( __( 'Oversized partially scanned: %d', 'atomic-edge-security' ), (int) $atomicedge_diag_counts['files_partially_scanned'] );
						}
						if ( ! empty( $atomicedge_diag_counts['files_skipped_whitelist'] ) ) {
							/* translators: %d: number of whitelisted files skipped */
							$atomicedge_counts_line[] = sprintf( __( 'Whitelisted skipped: %d', 'atomic-edge-security' ), (int) $atomicedge_diag_counts['files_skipped_whitelist'] );
						}
						?>

						<?php if ( ! empty( $atomicedge_counts_line ) ) : ?>
							<p><?php echo esc_html( implode( ' · ', $atomicedge_counts_line ) ); ?></p>
						<?php endif; ?>

						<?php if ( ! empty( $atomicedge_diag_areas ) ) : ?>
							<table class="wp-list-table widefat fixed striped">
								<thead>
									<tr>
										<th><?php esc_html_e( 'Area', 'atomic-edge-security' ); ?></th>
										<th><?php esc_html_e( 'PHP found', 'atomic-edge-security' ); ?></th>
										<th><?php esc_html_e( 'PHP scanned', 'atomic-edge-security' ); ?></th>
									</tr>
								</thead>
								<tbody>
									<?php foreach ( $atomicedge_diag_areas as $atomicedge_area_key => $atomicedge_area_stats ) : ?>
										<tr>
											<td><?php echo esc_html( (string) $atomicedge_area_key ); ?></td>
											<td><?php echo esc_html( isset( $atomicedge_area_stats['php_files_found'] ) ? (string) (int) $atomicedge_area_stats['php_files_found'] : '0' ); ?></td>
											<td><?php echo esc_html( isset( $atomicedge_area_stats['php_files_scanned'] ) ? (string) (int) $atomicedge_area_stats['php_files_scanned'] : '0' ); ?></td>
										</tr>
									<?php endforeach; ?>
								</tbody>
							</table>
						<?php endif; ?>

						<?php if ( ! empty( $atomicedge_diag_samples['unreadable_dirs'] ) || ! empty( $atomicedge_diag_samples['read_failed_files'] ) || ! empty( $atomicedge_diag_samples['oversized_files'] ) ) : ?>
							<p class="description"><em><?php esc_html_e( 'Examples (first 5):', 'atomic-edge-security' ); ?></em></p>
							<ul>
								<?php if ( ! empty( $atomicedge_diag_samples['unreadable_dirs'] ) ) : ?>
									<li><?php echo esc_html__( 'Unreadable dirs:', 'atomic-edge-security' ) . ' ' . esc_html( implode( ', ', $atomicedge_diag_samples['unreadable_dirs'] ) ); ?></li>
								<?php endif; ?>
								<?php if ( ! empty( $atomicedge_diag_samples['read_failed_files'] ) ) : ?>
									<li><?php echo esc_html__( 'Read failures:', 'atomic-edge-security' ) . ' ' . esc_html( implode( ', ', $atomicedge_diag_samples['read_failed_files'] ) ); ?></li>
								<?php endif; ?>
								<?php if ( ! empty( $atomicedge_diag_samples['oversized_files'] ) ) : ?>
									<li><?php echo esc_html__( 'Oversized partially scanned:', 'atomic-edge-security' ) . ' ' . esc_html( implode( ', ', $atomicedge_diag_samples['oversized_files'] ) ); ?></li>
								<?php endif; ?>
							</ul>
						<?php endif; ?>
					</div>
				<?php endif; ?>

				<?php if ( ! empty( $atomicedge_last_results['integrity_issues'] ) && is_array( $atomicedge_last_results['integrity_issues'] ) ) : ?>
					<div class="atomicedge-results-section" data-paginate="true" data-per-page="10">
						<h3>
							<?php esc_html_e( 'AtomicEdge Plugin Integrity Issues', 'atomic-edge-security' ); ?>
							<span class="atomicedge-results-count">(<?php echo esc_html( count( $atomicedge_last_results['integrity_issues'] ) ); ?>)</span>
						</h3>
						<p class="description"><?php esc_html_e( 'These files did not match the expected release manifest. This can indicate tampering or a partial/failed update.', 'atomic-edge-security' ); ?></p>
							<table class="wp-list-table widefat fixed striped">
							<thead>
								<tr>
									<th><?php esc_html_e( 'File', 'atomic-edge-security' ); ?></th>
									<th><?php esc_html_e( 'Issue', 'atomic-edge-security' ); ?></th>
								</tr>
							</thead>
							<tbody>
								<?php foreach ( $atomicedge_last_results['integrity_issues'] as $atomicedge_issue ) : ?>
									<tr>
										<td><code><?php echo esc_html( $atomicedge_issue['file'] ?? '' ); ?></code></td>
										<td><?php echo esc_html( $atomicedge_issue['reason'] ?? ( $atomicedge_issue['type'] ?? '' ) ); ?></td>
									</tr>
								<?php endforeach; ?>
							</tbody>
						</table>
						<div class="atomicedge-pagination"></div>
					</div>
				<?php endif; ?>

				<!-- Modified Core Files -->
				<?php if ( ! empty( $atomicedge_last_results['core_files'] ) ) : ?>
					<div class="atomicedge-results-section" data-paginate="true" data-per-page="10">
						<h3>
							<?php esc_html_e( 'Modified Core Files', 'atomic-edge-security' ); ?>
							<span class="atomicedge-results-count">(<?php echo esc_html( count( $atomicedge_last_results['core_files'] ) ); ?>)</span>
						</h3>
						<p class="description"><?php esc_html_e( 'These WordPress core files have been modified from their original versions.', 'atomic-edge-security' ); ?></p>
							<table class="wp-list-table widefat fixed striped atomicedge-paginated-table">
							<thead>
								<tr>
									<th><?php esc_html_e( 'File', 'atomic-edge-security' ); ?></th>
									<th><?php esc_html_e( 'Severity', 'atomic-edge-security' ); ?></th>
								</tr>
							</thead>
							<tbody>
								<?php foreach ( $atomicedge_last_results['core_files'] as $atomicedge_issue ) : ?>
									<tr>
										<td><code><?php echo esc_html( $atomicedge_issue['file_path'] ?? $atomicedge_issue['file'] ); ?></code></td>
										<td>
											<span class="atomicedge-severity atomicedge-severity-<?php echo esc_attr( $atomicedge_issue['severity'] ); ?>">
												<?php echo esc_html( ucfirst( $atomicedge_issue['severity'] ) ); ?>
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
				<?php if ( ! empty( $atomicedge_last_results['suspicious'] ) ) : ?>
					<div class="atomicedge-results-section" data-paginate="true" data-per-page="10">
						<h3>
							<?php esc_html_e( 'Suspicious Files', 'atomic-edge-security' ); ?>
							<span class="atomicedge-results-count">(<?php echo esc_html( count( $atomicedge_last_results['suspicious'] ) ); ?>)</span>
						</h3>
						<p class="description"><?php esc_html_e( 'These files contain potentially malicious code patterns.', 'atomic-edge-security' ); ?></p>
							<table class="wp-list-table widefat fixed striped atomicedge-paginated-table">
							<thead>
								<tr>
									<th><?php esc_html_e( 'File', 'atomic-edge-security' ); ?></th>
									<th><?php esc_html_e( 'Issue', 'atomic-edge-security' ); ?></th>
									<th><?php esc_html_e( 'Severity', 'atomic-edge-security' ); ?></th>
								</tr>
							</thead>
							<tbody>
								<?php foreach ( $atomicedge_last_results['suspicious'] as $atomicedge_issue ) : ?>
									<tr>
										<td><code><?php echo esc_html( $atomicedge_issue['file_path'] ?? $atomicedge_issue['file'] ); ?></code></td>
										<td>
											<?php
											if ( isset( $atomicedge_issue['pattern'] ) ) {
												echo esc_html( $atomicedge_issue['pattern'] );
											} elseif ( isset( $atomicedge_issue['reason'] ) ) {
												echo esc_html( $atomicedge_issue['reason'] );
											}
											?>
										</td>
										<td>
											<span class="atomicedge-severity atomicedge-severity-<?php echo esc_attr( $atomicedge_issue['severity'] ); ?>">
												<?php echo esc_html( ucfirst( $atomicedge_issue['severity'] ) ); ?>
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
				<?php if ( empty( $atomicedge_last_results['core_files'] ) && empty( $atomicedge_last_results['suspicious'] ) ) : ?>
					<div class="atomicedge-all-clear">
						<span class="dashicons dashicons-yes-alt"></span>
						<h3><?php esc_html_e( 'All Clear!', 'atomic-edge-security' ); ?></h3>
						<p><?php esc_html_e( 'No security issues were found in the last scan.', 'atomic-edge-security' ); ?></p>
					</div>
				<?php endif; ?>

			<?php else : ?>
				<div class="atomicedge-no-results">
					<span class="dashicons dashicons-search"></span>
					<h3><?php esc_html_e( 'No Scan Results', 'atomic-edge-security' ); ?></h3>
					<p><?php esc_html_e( 'Run a scan to check your WordPress files for security issues.', 'atomic-edge-security' ); ?></p>
				</div>
			<?php endif; ?>
		</div>

		<!-- What We Check -->
		<div class="atomicedge-scanner-info-box">
			<h3><?php esc_html_e( 'What We Check', 'atomic-edge-security' ); ?></h3>
			<ul>
				<li>
					<span class="dashicons dashicons-yes"></span>
					<?php esc_html_e( 'WordPress core files against official checksums', 'atomic-edge-security' ); ?>
				</li>
				<li>
					<span class="dashicons dashicons-yes"></span>
					<?php esc_html_e( 'WordPress root directory for unknown PHP files', 'atomic-edge-security' ); ?>
				</li>
				<li>
					<span class="dashicons dashicons-yes"></span>
					<?php esc_html_e( 'wp-admin and wp-includes for malware patterns', 'atomic-edge-security' ); ?>
				</li>
				<li>
					<span class="dashicons dashicons-yes"></span>
					<?php esc_html_e( 'PHP files in uploads directory (should not exist)', 'atomic-edge-security' ); ?>
				</li>
				<li>
					<span class="dashicons dashicons-yes"></span>
					<?php esc_html_e( 'Suspicious code patterns (eval, base64_decode, etc.)', 'atomic-edge-security' ); ?>
				</li>
				<li>
					<span class="dashicons dashicons-yes"></span>
					<?php esc_html_e( 'Obfuscated code and known webshell signatures', 'atomic-edge-security' ); ?>
				</li>
			</ul>
		</div>

		<!-- PHP Environment Info -->
		<div class="atomicedge-scanner-info-box atomicedge-environment-info">
			<h3><?php esc_html_e( 'Environment', 'atomic-edge-security' ); ?></h3>
			<ul>
				<li>
					<strong><?php esc_html_e( 'Memory Limit:', 'atomic-edge-security' ); ?></strong>
					<?php echo esc_html( ini_get( 'memory_limit' ) ); ?>
				</li>
				<li>
					<strong><?php esc_html_e( 'Max Execution Time:', 'atomic-edge-security' ); ?></strong>
					<?php echo esc_html( ini_get( 'max_execution_time' ) ); ?>s
				</li>
				<li>
					<strong><?php esc_html_e( 'PHP Version:', 'atomic-edge-security' ); ?></strong>
					<?php echo esc_html( PHP_VERSION ); ?>
				</li>
			</ul>
		</div>
	</div>
</div>
