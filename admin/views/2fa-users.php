<?php
/**
 * 2FA User Management Admin View
 *
 * Allows admins to view and manage user 2FA status.
 *
 * @package AtomicEdge
 * @since   1.8.0
 */

// Prevent direct access.
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

// Handle admin reset action.
if ( isset( $_POST['atomicedge_reset_2fa'] ) && isset( $_POST['reset_user_id'] ) ) {
	// Verify nonce.
	if ( ! wp_verify_nonce( sanitize_text_field( wp_unslash( $_POST['_wpnonce'] ?? '' ) ), 'atomicedge_reset_2fa' ) ) {
		wp_die( esc_html__( 'Security check failed.', 'atomic-edge-security' ) );
	}
	
	// Check capability.
	if ( ! current_user_can( 'manage_options' ) ) {
		wp_die( esc_html__( 'You do not have permission to perform this action.', 'atomic-edge-security' ) );
	}
	
	$reset_user_id = absint( $_POST['reset_user_id'] );
	$reset_user    = get_userdata( $reset_user_id );
	
	if ( $reset_user && AtomicEdge_2FA::is_enabled_for_user( $reset_user_id ) ) {
		// Disable 2FA for the user.
		AtomicEdge_2FA::disable( $reset_user_id );
		
		// Clear policy grace period.
		AtomicEdge_2FA_Policy::end_grace_period( $reset_user_id );
		
		// Log the admin reset.
		do_action( 'atomicedge_2fa_event', $reset_user_id, 'admin_reset', array(
			'admin_id' => get_current_user_id(),
			'reason'   => 'Admin manually reset 2FA',
		) );
		
		$success_message = sprintf(
			/* translators: %s: username */
			__( '2FA has been disabled for user "%s". They will need to set up 2FA again.', 'atomic-edge-security' ),
			$reset_user->user_login
		);
	}
}

// Get search/filter.
$search = isset( $_GET['s'] ) ? sanitize_text_field( wp_unslash( $_GET['s'] ) ) : '';
$filter = isset( $_GET['filter'] ) ? sanitize_text_field( wp_unslash( $_GET['filter'] ) ) : '';

// Build user query.
$args = array(
	'number'  => 50,
	'orderby' => 'display_name',
	'order'   => 'ASC',
);

if ( $search ) {
	$args['search']         = '*' . $search . '*';
	$args['search_columns'] = array( 'user_login', 'user_email', 'display_name' );
}

$users = get_users( $args );

// Filter users.
$filtered_users = array();
foreach ( $users as $user ) {
	$has_2fa = AtomicEdge_2FA::is_enabled_for_user( $user->ID );
	
	if ( 'enabled' === $filter && ! $has_2fa ) {
		continue;
	}
	if ( 'disabled' === $filter && $has_2fa ) {
		continue;
	}
	
	$filtered_users[] = $user;
}

// Count 2FA stats.
$total_users      = count_users();
$users_with_2fa   = 0;
$all_user_ids     = get_users( array( 'fields' => 'ID' ) );
foreach ( $all_user_ids as $uid ) {
	if ( AtomicEdge_2FA::is_enabled_for_user( $uid ) ) {
		$users_with_2fa++;
	}
}
$users_without_2fa = $total_users['total_users'] - $users_with_2fa;
?>
<div class="wrap">
	<h1><?php echo esc_html__( '2FA User Management', 'atomic-edge-security' ); ?></h1>
	
	<p class="description">
		<?php echo esc_html__( 'View and manage Two-Factor Authentication status for all users.', 'atomic-edge-security' ); ?>
	</p>

	<?php if ( ! empty( $success_message ) ) : ?>
		<div class="notice notice-success is-dismissible">
			<p><?php echo esc_html( $success_message ); ?></p>
		</div>
	<?php endif; ?>

	<!-- Statistics -->
	<div class="atomicedge-stats-grid" style="display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 15px; margin: 20px 0; max-width: 600px;">
		<div class="atomicedge-stat-card" style="background: #fff; padding: 20px; border-left: 4px solid #0073aa; box-shadow: 0 1px 1px rgba(0,0,0,.04);">
			<div class="stat-value" style="font-size: 28px; font-weight: 600; color: #23282d;">
				<?php echo esc_html( $total_users['total_users'] ); ?>
			</div>
			<div class="stat-label" style="color: #666; font-size: 13px;"><?php echo esc_html__( 'Total Users', 'atomic-edge-security' ); ?></div>
		</div>
		<div class="atomicedge-stat-card" style="background: #fff; padding: 20px; border-left: 4px solid #46b450; box-shadow: 0 1px 1px rgba(0,0,0,.04);">
			<div class="stat-value" style="font-size: 28px; font-weight: 600; color: #46b450;">
				<?php echo esc_html( $users_with_2fa ); ?>
			</div>
			<div class="stat-label" style="color: #666; font-size: 13px;"><?php echo esc_html__( '2FA Enabled', 'atomic-edge-security' ); ?></div>
		</div>
		<div class="atomicedge-stat-card" style="background: #fff; padding: 20px; border-left: 4px solid #f0ad4e; box-shadow: 0 1px 1px rgba(0,0,0,.04);">
			<div class="stat-value" style="font-size: 28px; font-weight: 600; color: #f0ad4e;">
				<?php echo esc_html( $users_without_2fa ); ?>
			</div>
			<div class="stat-label" style="color: #666; font-size: 13px;"><?php echo esc_html__( 'No 2FA', 'atomic-edge-security' ); ?></div>
		</div>
	</div>

	<!-- Search and Filter -->
	<form method="get" action="" style="margin-bottom: 20px;">
		<input type="hidden" name="page" value="atomicedge-2fa-users" />
		
		<input type="search" name="s" value="<?php echo esc_attr( $search ); ?>" 
			placeholder="<?php echo esc_attr__( 'Search users...', 'atomic-edge-security' ); ?>" style="min-width: 200px;" />
		
		<select name="filter">
			<option value=""><?php echo esc_html__( 'All Users', 'atomic-edge-security' ); ?></option>
			<option value="enabled" <?php selected( $filter, 'enabled' ); ?>><?php echo esc_html__( '2FA Enabled', 'atomic-edge-security' ); ?></option>
			<option value="disabled" <?php selected( $filter, 'disabled' ); ?>><?php echo esc_html__( '2FA Disabled', 'atomic-edge-security' ); ?></option>
		</select>
		
		<button type="submit" class="button"><?php echo esc_html__( 'Search', 'atomic-edge-security' ); ?></button>
		
		<?php if ( $search || $filter ) : ?>
			<a href="<?php echo esc_url( admin_url( 'admin.php?page=atomicedge-2fa-users' ) ); ?>" class="button">
				<?php echo esc_html__( 'Clear', 'atomic-edge-security' ); ?>
			</a>
		<?php endif; ?>
	</form>

	<!-- Users Table -->
	<table class="wp-list-table widefat fixed striped users">
		<thead>
			<tr>
				<th scope="col" class="manage-column column-username column-primary" style="width: 200px;">
					<?php echo esc_html__( 'Username', 'atomic-edge-security' ); ?>
				</th>
				<th scope="col" class="manage-column"><?php echo esc_html__( 'Name', 'atomic-edge-security' ); ?></th>
				<th scope="col" class="manage-column" style="width: 200px;"><?php echo esc_html__( 'Email', 'atomic-edge-security' ); ?></th>
				<th scope="col" class="manage-column" style="width: 120px;"><?php echo esc_html__( 'Role', 'atomic-edge-security' ); ?></th>
				<th scope="col" class="manage-column" style="width: 120px;"><?php echo esc_html__( '2FA Status', 'atomic-edge-security' ); ?></th>
				<th scope="col" class="manage-column" style="width: 120px;"><?php echo esc_html__( 'Actions', 'atomic-edge-security' ); ?></th>
			</tr>
		</thead>
		<tbody>
			<?php if ( empty( $filtered_users ) ) : ?>
				<tr>
					<td colspan="6" style="text-align: center; padding: 20px;">
						<?php echo esc_html__( 'No users found.', 'atomic-edge-security' ); ?>
					</td>
				</tr>
			<?php else : ?>
				<?php foreach ( $filtered_users as $user ) : ?>
					<?php
					$has_2fa       = AtomicEdge_2FA::is_enabled_for_user( $user->ID );
					$backup_count  = 0;
					$policy_status = AtomicEdge_2FA_Policy::get_user_enforcement_status( $user );
					
					if ( $has_2fa ) {
						$backup_codes = get_user_meta( $user->ID, AtomicEdge_2FA_Backup::META_KEY, true );
						if ( is_array( $backup_codes ) ) {
							$backup_count = count( $backup_codes );
						}
					}
					?>
					<tr>
						<td class="column-username column-primary" data-colname="<?php echo esc_attr__( 'Username', 'atomic-edge-security' ); ?>">
							<strong>
								<a href="<?php echo esc_url( admin_url( 'user-edit.php?user_id=' . $user->ID ) ); ?>">
									<?php echo esc_html( $user->user_login ); ?>
								</a>
							</strong>
						</td>
						<td data-colname="<?php echo esc_attr__( 'Name', 'atomic-edge-security' ); ?>">
							<?php echo esc_html( $user->display_name ); ?>
						</td>
						<td data-colname="<?php echo esc_attr__( 'Email', 'atomic-edge-security' ); ?>">
							<a href="mailto:<?php echo esc_attr( $user->user_email ); ?>">
								<?php echo esc_html( $user->user_email ); ?>
							</a>
						</td>
						<td data-colname="<?php echo esc_attr__( 'Role', 'atomic-edge-security' ); ?>">
							<?php
							$roles = array_map( function ( $role ) {
								$role_obj = get_role( $role );
								return $role_obj ? translate_user_role( ucfirst( $role ) ) : ucfirst( $role );
							}, $user->roles );
							echo esc_html( implode( ', ', $roles ) );
							?>
						</td>
						<td data-colname="<?php echo esc_attr__( '2FA Status', 'atomic-edge-security' ); ?>">
							<?php if ( $has_2fa ) : ?>
								<span style="color: #46b450; font-weight: 500;">
									<span class="dashicons dashicons-shield-alt" style="font-size: 16px; width: 16px; height: 16px; vertical-align: text-bottom;"></span>
									<?php echo esc_html__( 'Enabled', 'atomic-edge-security' ); ?>
								</span>
								<?php if ( $backup_count > 0 ) : ?>
									<br>
									<small style="color: #666;">
										<?php
										printf(
											/* translators: %d: number of backup codes */
											esc_html( _n( '%d backup code', '%d backup codes', $backup_count, 'atomic-edge-security' ) ),
											esc_html( $backup_count )
										);
										?>
									</small>
								<?php endif; ?>
							<?php else : ?>
								<span style="color: #999;">
									<?php echo esc_html__( 'Disabled', 'atomic-edge-security' ); ?>
								</span>
								<?php if ( 'required' === $policy_status['status'] || 'grace_period' === $policy_status['status'] ) : ?>
									<br>
									<small style="color: #dc3232;">
										<?php
										if ( 'grace_period' === $policy_status['status'] ) {
											printf(
												/* translators: %d: number of days remaining */
												esc_html( _n( '%d day to set up', '%d days to set up', $policy_status['days_remaining'], 'atomic-edge-security' ) ),
												esc_html( $policy_status['days_remaining'] )
											);
										} else {
											echo esc_html__( 'Required by policy', 'atomic-edge-security' );
										}
										?>
									</small>
								<?php endif; ?>
							<?php endif; ?>
						</td>
						<td data-colname="<?php echo esc_attr__( 'Actions', 'atomic-edge-security' ); ?>">
							<?php if ( $has_2fa ) : ?>
								<button type="button" class="button button-small atomicedge-reset-2fa" 
									data-user-id="<?php echo esc_attr( $user->ID ); ?>"
									data-username="<?php echo esc_attr( $user->user_login ); ?>">
									<?php echo esc_html__( 'Reset', 'atomic-edge-security' ); ?>
								</button>
							<?php else : ?>
								<span style="color: #999;">—</span>
							<?php endif; ?>
						</td>
					</tr>
				<?php endforeach; ?>
			<?php endif; ?>
		</tbody>
	</table>

	<!-- Reset Confirmation Modal -->
	<div id="atomicedge-reset-modal" style="display: none; position: fixed; top: 0; left: 0; width: 100%; height: 100%; background: rgba(0,0,0,0.5); z-index: 100000;">
		<div style="position: absolute; top: 50%; left: 50%; transform: translate(-50%, -50%); background: #fff; padding: 30px; border-radius: 4px; max-width: 400px; box-shadow: 0 3px 30px rgba(0,0,0,0.3);">
			<h2 style="margin-top: 0;"><?php echo esc_html__( 'Reset 2FA?', 'atomic-edge-security' ); ?></h2>
			<p>
				<?php echo esc_html__( 'Are you sure you want to reset Two-Factor Authentication for', 'atomic-edge-security' ); ?>
				<strong id="reset-username"></strong>?
			</p>
			<p style="color: #dc3232;">
				<?php echo esc_html__( 'This will disable their 2FA and they will need to set it up again. Use this only if the user is locked out.', 'atomic-edge-security' ); ?>
			</p>
			<form method="post" action="" id="reset-2fa-form">
				<?php wp_nonce_field( 'atomicedge_reset_2fa' ); ?>
				<input type="hidden" name="reset_user_id" id="reset-user-id" value="" />
				<input type="hidden" name="atomicedge_reset_2fa" value="1" />
				<p style="margin-bottom: 0;">
					<button type="submit" class="button button-primary" style="background: #dc3232; border-color: #dc3232;">
						<?php echo esc_html__( 'Yes, Reset 2FA', 'atomic-edge-security' ); ?>
					</button>
					<button type="button" class="button" id="cancel-reset">
						<?php echo esc_html__( 'Cancel', 'atomic-edge-security' ); ?>
					</button>
				</p>
			</form>
		</div>
	</div>

	<script type="text/javascript">
	(function($) {
		$('.atomicedge-reset-2fa').on('click', function() {
			var userId = $(this).data('user-id');
			var username = $(this).data('username');
			$('#reset-user-id').val(userId);
			$('#reset-username').text(username);
			$('#atomicedge-reset-modal').show();
		});
		
		$('#cancel-reset, #atomicedge-reset-modal').on('click', function(e) {
			if (e.target === this) {
				$('#atomicedge-reset-modal').hide();
			}
		});
		
		// Prevent modal close when clicking inside modal content.
		$('#atomicedge-reset-modal > div').on('click', function(e) {
			e.stopPropagation();
		});
	})(jQuery);
	</script>
</div>
