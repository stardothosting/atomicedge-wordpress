<?php
/**
 * 2FA Audit Log Admin View
 *
 * @package AtomicEdge
 * @since   1.8.0
 */

// Prevent direct access.
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

// Get current page and filters.
$current_page = isset( $_GET['paged'] ) ? max( 1, absint( $_GET['paged'] ) ) : 1;
$user_filter  = isset( $_GET['user_id'] ) ? absint( $_GET['user_id'] ) : 0;
$event_filter = isset( $_GET['event'] ) ? sanitize_text_field( wp_unslash( $_GET['event'] ) ) : '';
$per_page     = 25;

// Get audit entries.
$result = AtomicEdge_2FA_Audit::get_entries( array(
	'user_id' => $user_filter,
	'event'   => $event_filter,
	'limit'   => $per_page,
	'offset'  => ( $current_page - 1 ) * $per_page,
) );

$entries     = $result['entries'];
$total       = $result['total'];
$total_pages = ceil( $total / $per_page );

// Get statistics.
$stats = AtomicEdge_2FA_Audit::get_statistics( 30 );

// Event types for filter dropdown.
$event_types = array(
	''                         => __( 'All Events', 'atomic-edge-security' ),
	'enrollment_started'       => __( 'Enrollment Started', 'atomic-edge-security' ),
	'enrollment_completed'     => __( 'Enrollment Completed', 'atomic-edge-security' ),
	'enrollment_cancelled'     => __( 'Enrollment Cancelled', 'atomic-edge-security' ),
	'2fa_disabled'             => __( '2FA Disabled', 'atomic-edge-security' ),
	'backup_codes_regenerated' => __( 'Backup Codes Regenerated', 'atomic-edge-security' ),
	'backup_code_used'         => __( 'Backup Code Used', 'atomic-edge-security' ),
	'login_success'            => __( 'Login Success', 'atomic-edge-security' ),
	'login_failed'             => __( 'Login Failed', 'atomic-edge-security' ),
	'rate_limited'             => __( 'Rate Limited', 'atomic-edge-security' ),
	'admin_reset'              => __( 'Admin Reset', 'atomic-edge-security' ),
);
?>
<div class="wrap">
	<h1><?php echo esc_html__( '2FA Audit Log', 'atomic-edge-security' ); ?></h1>
	
	<p class="description">
		<?php echo esc_html__( 'Security audit log showing all 2FA-related events. Logs are retained for 90 days.', 'atomic-edge-security' ); ?>
	</p>

	<!-- Statistics Cards -->
	<div class="atomicedge-stats-grid" style="display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 15px; margin: 20px 0;">
		<div class="atomicedge-stat-card" style="background: #fff; padding: 20px; border-left: 4px solid #0073aa; box-shadow: 0 1px 1px rgba(0,0,0,.04);">
			<div class="stat-value" style="font-size: 28px; font-weight: 600; color: #23282d;"><?php echo esc_html( number_format( $stats['total_events'] ) ); ?></div>
			<div class="stat-label" style="color: #666; font-size: 13px;"><?php echo esc_html__( 'Events (30 days)', 'atomic-edge-security' ); ?></div>
		</div>
		<div class="atomicedge-stat-card" style="background: #fff; padding: 20px; border-left: 4px solid #46b450; box-shadow: 0 1px 1px rgba(0,0,0,.04);">
			<div class="stat-value" style="font-size: 28px; font-weight: 600; color: #46b450;"><?php echo esc_html( number_format( $stats['login_success'] ) ); ?></div>
			<div class="stat-label" style="color: #666; font-size: 13px;"><?php echo esc_html__( 'Successful Logins', 'atomic-edge-security' ); ?></div>
		</div>
		<div class="atomicedge-stat-card" style="background: #fff; padding: 20px; border-left: 4px solid #dc3232; box-shadow: 0 1px 1px rgba(0,0,0,.04);">
			<div class="stat-value" style="font-size: 28px; font-weight: 600; color: #dc3232;"><?php echo esc_html( number_format( $stats['login_failed'] ) ); ?></div>
			<div class="stat-label" style="color: #666; font-size: 13px;"><?php echo esc_html__( 'Failed Attempts', 'atomic-edge-security' ); ?></div>
		</div>
		<div class="atomicedge-stat-card" style="background: #fff; padding: 20px; border-left: 4px solid #f0ad4e; box-shadow: 0 1px 1px rgba(0,0,0,.04);">
			<div class="stat-value" style="font-size: 28px; font-weight: 600; color: #f0ad4e;"><?php echo esc_html( number_format( $stats['backup_code_used'] ) ); ?></div>
			<div class="stat-label" style="color: #666; font-size: 13px;"><?php echo esc_html__( 'Backup Codes Used', 'atomic-edge-security' ); ?></div>
		</div>
	</div>

	<!-- Filters -->
	<form method="get" action="" style="margin-bottom: 20px;">
		<input type="hidden" name="page" value="atomicedge-2fa-audit" />
		
		<select name="event" style="min-width: 200px;">
			<?php foreach ( $event_types as $value => $label ) : ?>
				<option value="<?php echo esc_attr( $value ); ?>" <?php selected( $event_filter, $value ); ?>>
					<?php echo esc_html( $label ); ?>
				</option>
			<?php endforeach; ?>
		</select>
		
		<input type="number" name="user_id" value="<?php echo $user_filter ? esc_attr( $user_filter ) : ''; ?>" 
			placeholder="<?php echo esc_attr__( 'Filter by User ID', 'atomic-edge-security' ); ?>" style="width: 150px;" />
		
		<button type="submit" class="button"><?php echo esc_html__( 'Filter', 'atomic-edge-security' ); ?></button>
		
		<?php if ( $user_filter || $event_filter ) : ?>
			<a href="<?php echo esc_url( admin_url( 'admin.php?page=atomicedge-2fa-audit' ) ); ?>" class="button">
				<?php echo esc_html__( 'Clear Filters', 'atomic-edge-security' ); ?>
			</a>
		<?php endif; ?>
		
		<!-- Export Button -->
		<a href="<?php echo esc_url( wp_nonce_url( admin_url( 'admin.php?page=atomicedge-2fa-audit&action=export' ), 'atomicedge_export_audit' ) ); ?>" 
			class="button" style="float: right;">
			<span class="dashicons dashicons-download" style="vertical-align: middle; margin-top: 3px;"></span>
			<?php echo esc_html__( 'Export CSV', 'atomic-edge-security' ); ?>
		</a>
	</form>

	<!-- Log Table -->
	<table class="wp-list-table widefat fixed striped">
		<thead>
			<tr>
				<th scope="col" style="width: 160px;"><?php echo esc_html__( 'Date/Time', 'atomic-edge-security' ); ?></th>
				<th scope="col" style="width: 150px;"><?php echo esc_html__( 'User', 'atomic-edge-security' ); ?></th>
				<th scope="col"><?php echo esc_html__( 'Event', 'atomic-edge-security' ); ?></th>
				<th scope="col" style="width: 130px;"><?php echo esc_html__( 'IP Address', 'atomic-edge-security' ); ?></th>
				<th scope="col" style="width: 130px;"><?php echo esc_html__( 'Admin', 'atomic-edge-security' ); ?></th>
			</tr>
		</thead>
		<tbody>
			<?php if ( empty( $entries ) ) : ?>
				<tr>
					<td colspan="5" style="text-align: center; padding: 20px;">
						<?php echo esc_html__( 'No audit log entries found.', 'atomic-edge-security' ); ?>
					</td>
				</tr>
			<?php else : ?>
				<?php foreach ( $entries as $entry ) : ?>
					<?php
					$severity = AtomicEdge_2FA_Audit::get_event_severity( $entry['event'] );
					$color    = '#0073aa'; // info.
					if ( 'success' === $severity ) {
						$color = '#46b450';
					} elseif ( 'warning' === $severity ) {
						$color = '#f0ad4e';
					} elseif ( 'danger' === $severity ) {
						$color = '#dc3232';
					}
					?>
					<tr>
						<td>
							<span title="<?php echo esc_attr( wp_date( 'Y-m-d H:i:s', $entry['timestamp'] ) ); ?>">
								<?php echo esc_html( wp_date( 'M j, Y g:i a', $entry['timestamp'] ) ); ?>
							</span>
						</td>
						<td>
							<?php if ( $entry['user_id'] ) : ?>
								<a href="<?php echo esc_url( admin_url( 'user-edit.php?user_id=' . $entry['user_id'] ) ); ?>">
									<?php echo esc_html( $entry['user_login'] ); ?>
								</a>
							<?php else : ?>
								<?php echo esc_html( $entry['user_login'] ); ?>
							<?php endif; ?>
						</td>
						<td>
							<span style="display: inline-block; width: 8px; height: 8px; border-radius: 50%; background: <?php echo esc_attr( $color ); ?>; margin-right: 8px;"></span>
							<?php echo esc_html( AtomicEdge_2FA_Audit::get_event_label( $entry['event'] ) ); ?>
							<?php if ( ! empty( $entry['context']['reason'] ) ) : ?>
								<br><small style="color: #666; margin-left: 16px;"><?php echo esc_html( $entry['context']['reason'] ); ?></small>
							<?php endif; ?>
						</td>
						<td>
							<code style="font-size: 12px;"><?php echo esc_html( $entry['ip_address'] ); ?></code>
						</td>
						<td>
							<?php if ( ! empty( $entry['admin_login'] ) ) : ?>
								<span title="<?php echo esc_attr( sprintf( __( 'Action performed by %s', 'atomic-edge-security' ), $entry['admin_login'] ) ); ?>">
									<?php echo esc_html( $entry['admin_login'] ); ?>
								</span>
							<?php else : ?>
								<span style="color: #999;">—</span>
							<?php endif; ?>
						</td>
					</tr>
				<?php endforeach; ?>
			<?php endif; ?>
		</tbody>
	</table>

	<!-- Pagination -->
	<?php if ( $total_pages > 1 ) : ?>
		<div class="tablenav bottom">
			<div class="tablenav-pages">
				<span class="displaying-num">
					<?php
					printf(
						/* translators: %s: number of items */
						esc_html( _n( '%s item', '%s items', $total, 'atomic-edge-security' ) ),
						esc_html( number_format_i18n( $total ) )
					);
					?>
				</span>
				<span class="pagination-links">
					<?php
					$base_url = add_query_arg(
						array(
							'page'    => 'atomicedge-2fa-audit',
							'user_id' => $user_filter ?: false,
							'event'   => $event_filter ?: false,
						),
						admin_url( 'admin.php' )
					);
					
					// First page.
					if ( $current_page > 1 ) {
						printf(
							'<a class="first-page button" href="%s"><span class="screen-reader-text">%s</span><span aria-hidden="true">&laquo;</span></a>',
							esc_url( add_query_arg( 'paged', 1, $base_url ) ),
							esc_html__( 'First page', 'atomic-edge-security' )
						);
						printf(
							'<a class="prev-page button" href="%s"><span class="screen-reader-text">%s</span><span aria-hidden="true">&lsaquo;</span></a>',
							esc_url( add_query_arg( 'paged', $current_page - 1, $base_url ) ),
							esc_html__( 'Previous page', 'atomic-edge-security' )
						);
					} else {
						echo '<span class="tablenav-pages-navspan button disabled" aria-hidden="true">&laquo;</span>';
						echo '<span class="tablenav-pages-navspan button disabled" aria-hidden="true">&lsaquo;</span>';
					}
					?>
					
					<span class="paging-input">
						<span class="tablenav-paging-text">
							<?php echo esc_html( $current_page ); ?>
							<?php echo esc_html__( 'of', 'atomic-edge-security' ); ?>
							<span class="total-pages"><?php echo esc_html( $total_pages ); ?></span>
						</span>
					</span>
					
					<?php
					// Last page.
					if ( $current_page < $total_pages ) {
						printf(
							'<a class="next-page button" href="%s"><span class="screen-reader-text">%s</span><span aria-hidden="true">&rsaquo;</span></a>',
							esc_url( add_query_arg( 'paged', $current_page + 1, $base_url ) ),
							esc_html__( 'Next page', 'atomic-edge-security' )
						);
						printf(
							'<a class="last-page button" href="%s"><span class="screen-reader-text">%s</span><span aria-hidden="true">&raquo;</span></a>',
							esc_url( add_query_arg( 'paged', $total_pages, $base_url ) ),
							esc_html__( 'Last page', 'atomic-edge-security' )
						);
					} else {
						echo '<span class="tablenav-pages-navspan button disabled" aria-hidden="true">&rsaquo;</span>';
						echo '<span class="tablenav-pages-navspan button disabled" aria-hidden="true">&raquo;</span>';
					}
					?>
				</span>
			</div>
		</div>
	<?php endif; ?>

	<!-- Security Alerts -->
	<?php
	$security_events = AtomicEdge_2FA_Audit::get_security_events( 10 );
	if ( ! empty( $security_events ) ) :
	?>
		<h2 style="margin-top: 30px;"><?php echo esc_html__( 'Recent Security Events', 'atomic-edge-security' ); ?></h2>
		<p class="description"><?php echo esc_html__( 'Failed logins, rate limits, and admin actions.', 'atomic-edge-security' ); ?></p>
		
		<table class="wp-list-table widefat fixed striped" style="margin-top: 10px;">
			<thead>
				<tr>
					<th scope="col" style="width: 160px;"><?php echo esc_html__( 'Date/Time', 'atomic-edge-security' ); ?></th>
					<th scope="col" style="width: 150px;"><?php echo esc_html__( 'User', 'atomic-edge-security' ); ?></th>
					<th scope="col"><?php echo esc_html__( 'Event', 'atomic-edge-security' ); ?></th>
					<th scope="col" style="width: 130px;"><?php echo esc_html__( 'IP Address', 'atomic-edge-security' ); ?></th>
				</tr>
			</thead>
			<tbody>
				<?php foreach ( $security_events as $entry ) : ?>
					<tr>
						<td><?php echo esc_html( wp_date( 'M j, Y g:i a', $entry['timestamp'] ) ); ?></td>
						<td>
							<?php if ( $entry['user_id'] ) : ?>
								<a href="<?php echo esc_url( admin_url( 'user-edit.php?user_id=' . $entry['user_id'] ) ); ?>">
									<?php echo esc_html( $entry['user_login'] ); ?>
								</a>
							<?php else : ?>
								<?php echo esc_html( $entry['user_login'] ); ?>
							<?php endif; ?>
						</td>
						<td>
							<span style="color: #dc3232; font-weight: 500;">
								<?php echo esc_html( AtomicEdge_2FA_Audit::get_event_label( $entry['event'] ) ); ?>
							</span>
						</td>
						<td><code style="font-size: 12px;"><?php echo esc_html( $entry['ip_address'] ); ?></code></td>
					</tr>
				<?php endforeach; ?>
			</tbody>
		</table>
	<?php endif; ?>
</div>
