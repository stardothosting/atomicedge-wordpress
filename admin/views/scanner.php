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
	<h1><?php esc_html_e( 'Malware Scanner', 'atomicedge' ); ?></h1>

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
				<button type="button" id="atomicedge-run-scan" class="button button-primary button-hero">
					<span class="dashicons dashicons-search"></span>
					<?php esc_html_e( 'Run Full Scan', 'atomicedge' ); ?>
				</button>
				<button type="button" id="atomicedge-create-baseline" class="button">
					<?php esc_html_e( 'Create Baseline', 'atomicedge' ); ?>
				</button>
			</div>
		</div>

		<!-- Scan Progress -->
		<div id="atomicedge-scan-progress" class="atomicedge-scan-progress" style="display: none;">
			<div class="atomicedge-progress-bar">
				<div class="atomicedge-progress-fill"></div>
			</div>
			<p class="atomicedge-progress-text"><?php esc_html_e( 'Scanning files...', 'atomicedge' ); ?></p>
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
					</div>
				</div>

				<!-- Modified Core Files -->
				<?php if ( ! empty( $last_results['core_files'] ) ) : ?>
					<div class="atomicedge-results-section">
						<h3><?php esc_html_e( 'Modified Core Files', 'atomicedge' ); ?></h3>
						<p class="description"><?php esc_html_e( 'These WordPress core files have been modified from their original versions.', 'atomicedge' ); ?></p>
						<table class="wp-list-table widefat fixed striped">
							<thead>
								<tr>
									<th><?php esc_html_e( 'File', 'atomicedge' ); ?></th>
									<th><?php esc_html_e( 'Severity', 'atomicedge' ); ?></th>
								</tr>
							</thead>
							<tbody>
								<?php foreach ( $last_results['core_files'] as $issue ) : ?>
									<tr>
										<td><code><?php echo esc_html( $issue['file'] ); ?></code></td>
										<td>
											<span class="atomicedge-severity atomicedge-severity-<?php echo esc_attr( $issue['severity'] ); ?>">
												<?php echo esc_html( ucfirst( $issue['severity'] ) ); ?>
											</span>
										</td>
									</tr>
								<?php endforeach; ?>
							</tbody>
						</table>
					</div>
				<?php endif; ?>

				<!-- Suspicious Files -->
				<?php if ( ! empty( $last_results['suspicious'] ) ) : ?>
					<div class="atomicedge-results-section">
						<h3><?php esc_html_e( 'Suspicious Files', 'atomicedge' ); ?></h3>
						<p class="description"><?php esc_html_e( 'These files contain potentially malicious code patterns.', 'atomicedge' ); ?></p>
						<table class="wp-list-table widefat fixed striped">
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
										<td><code><?php echo esc_html( $issue['file'] ); ?></code></td>
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
					<?php esc_html_e( 'PHP files in uploads directory (should not exist)', 'atomicedge' ); ?>
				</li>
				<li>
					<span class="dashicons dashicons-yes"></span>
					<?php esc_html_e( 'Suspicious code patterns (eval, base64_decode, etc.)', 'atomicedge' ); ?>
				</li>
				<li>
					<span class="dashicons dashicons-yes"></span>
					<?php esc_html_e( 'Obfuscated code detection', 'atomicedge' ); ?>
				</li>
			</ul>
		</div>
	</div>
</div>
