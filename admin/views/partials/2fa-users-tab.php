<?php
/**
 * 2FA Users Tab Content
 *
 * @package AtomicEdge
 * @since   1.9.1
 */

// Prevent direct access.
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

// Handle admin reset action.
if ( isset( $_POST['atomicedge_reset_2fa'] ) && isset( $_POST['reset_user_id'] ) ) {
	// Verify nonce.
	if ( ! wp_verify_nonce( sanitize_text_field( wp_unslash( $_POST['_wpnonce'] ?? '' ) ), 'atomicedge_reset_2fa' ) ) {
		wp_die( esc_html__( 'Security check failed.', 'atomicedge' ) );
	}
	
	// Check capability.
	if ( ! current_user_can( 'manage_options' ) ) {
		wp_die( esc_html__( 'You do not have permission to perform this action.', 'atomicedge' ) );
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
			__( '2FA has been disabled for user "%s". They will need to set up 2FA again.', 'atomicedge' ),
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

<?php if ( ! empty( $success_message ) ) : ?>
	<div class="notice notice-success is-dismissible" style="margin: 0 0 20px;">
		<p><?php echo esc_html( $success_message ); ?></p>
	</div>
<?php endif; ?>

<!-- Statistics -->
<div class="atomicedge-stats-grid" style="max-width: 600px;">
	<div class="atomicedge-stat-card" style="border-left-color: #0073aa;">
		<div class="stat-value"><?php echo esc_html( $total_users['total_users'] ); ?></div>
		<div class="stat-label"><?php echo esc_html__( 'Total Users', 'atomicedge' ); ?></div>
	</div>
	<div class="atomicedge-stat-card" style="border-left-color: #46b450;">
		<div class="stat-value" style="color: #46b450;"><?php echo esc_html( $users_with_2fa ); ?></div>
		<div class="stat-label"><?php echo esc_html__( '2FA Enabled', 'atomicedge' ); ?></div>
	</div>
	<div class="atomicedge-stat-card" style="border-left-color: #f0ad4e;">
		<div class="stat-value" style="color: #f0ad4e;"><?php echo esc_html( $users_without_2fa ); ?></div>
		<div class="stat-label"><?php echo esc_html__( 'No 2FA', 'atomicedge' ); ?></div>
	</div>
</div>

<!-- Search and Filter -->
<form method="get" action="" style="margin-bottom: 20px;">
	<input type="hidden" name="page" value="atomicedge-2fa" />
	<input type="hidden" name="tab" value="users" />
	
	<input type="search" name="s" value="<?php echo esc_attr( $search ); ?>" 
		placeholder="<?php echo esc_attr__( 'Search users...', 'atomicedge' ); ?>" style="min-width: 200px;" />
	
	<select name="filter">
		<option value=""><?php echo esc_html__( 'All Users', 'atomicedge' ); ?></option>
		<option value="enabled" <?php selected( $filter, 'enabled' ); ?>><?php echo esc_html__( '2FA Enabled', 'atomicedge' ); ?></option>
		<option value="disabled" <?php selected( $filter, 'disabled' ); ?>><?php echo esc_html__( '2FA Disabled', 'atomicedge' ); ?></option>
	</select>
	
	<button type="submit" class="button"><?php echo esc_html__( 'Search', 'atomicedge' ); ?></button>
	
	<?php if ( $search || $filter ) : ?>
		<a href="<?php echo esc_url( admin_url( 'admin.php?page=atomicedge-2fa&tab=users' ) ); ?>" class="button">
			<?php echo esc_html__( 'Clear', 'atomicedge' ); ?>
		</a>
	<?php endif; ?>
</form>

<!-- Users Table -->
<table class="wp-list-table widefat fixed striped users">
	<thead>
		<tr>
			<th scope="col" class="manage-column column-username column-primary" style="width: 180px;">
				<?php echo esc_html__( 'Username', 'atomicedge' ); ?>
			</th>
			<th scope="col" class="manage-column"><?php echo esc_html__( 'Name', 'atomicedge' ); ?></th>
			<th scope="col" class="manage-column" style="width: 200px;"><?php echo esc_html__( 'Email', 'atomicedge' ); ?></th>
			<th scope="col" class="manage-column" style="width: 100px;"><?php echo esc_html__( 'Role', 'atomicedge' ); ?></th>
			<th scope="col" class="manage-column" style="width: 120px;"><?php echo esc_html__( '2FA Status', 'atomicedge' ); ?></th>
			<th scope="col" class="manage-column" style="width: 100px;"><?php echo esc_html__( 'Actions', 'atomicedge' ); ?></th>
		</tr>
	</thead>
	<tbody>
		<?php if ( empty( $filtered_users ) ) : ?>
			<tr>
				<td colspan="6" style="text-align: center; padding: 20px;">
					<?php echo esc_html__( 'No users found.', 'atomicedge' ); ?>
				</td>
			</tr>
		<?php else : ?>
			<?php foreach ( $filtered_users as $user ) : ?>
				<?php
				$has_2fa       = AtomicEdge_2FA::is_enabled_for_user( $user->ID );
				$backup_count  = 0;
				$policy_status = AtomicEdge_2FA_Policy::get_user_enforcement_status( $user );
				
				if ( $has_2fa ) {
					$backup_codes = get_user_meta( $user->ID, AtomicEdge_2FA::META_BACKUP_CODES, true );
					if ( is_array( $backup_codes ) ) {
						// Count only unused backup codes.
						$backup_count = count( array_filter( $backup_codes, function( $code ) {
							return empty( $code['used'] );
						} ) );
					}
				}
				?>
				<tr>
					<td class="column-username column-primary">
						<strong>
							<a href="<?php echo esc_url( admin_url( 'user-edit.php?user_id=' . $user->ID ) ); ?>">
								<?php echo esc_html( $user->user_login ); ?>
							</a>
						</strong>
					</td>
					<td><?php echo esc_html( $user->display_name ); ?></td>
					<td>
						<a href="mailto:<?php echo esc_attr( $user->user_email ); ?>">
							<?php echo esc_html( $user->user_email ); ?>
						</a>
					</td>
					<td>
						<?php
						$roles = array_map( function ( $role ) {
							$role_obj = get_role( $role );
							return $role_obj ? translate_user_role( ucfirst( $role ) ) : ucfirst( $role );
						}, $user->roles );
						echo esc_html( implode( ', ', $roles ) );
						?>
					</td>
					<td>
						<?php if ( $has_2fa ) : ?>
							<span style="color: #46b450; font-weight: 500;">
								<span class="dashicons dashicons-shield-alt" style="font-size: 16px; width: 16px; height: 16px; vertical-align: text-bottom;"></span>
								<?php echo esc_html__( 'Enabled', 'atomicedge' ); ?>
							</span>
							<?php if ( $backup_count > 0 ) : ?>
								<br>
								<small style="color: #666;">
									<?php
									printf(
										/* translators: %d: number of backup codes */
										esc_html( _n( '%d backup code', '%d backup codes', $backup_count, 'atomicedge' ) ),
										esc_html( $backup_count )
									);
									?>
								</small>
							<?php endif; ?>
						<?php else : ?>
							<span style="color: #999;">
								<?php echo esc_html__( 'Disabled', 'atomicedge' ); ?>
							</span>
							<?php if ( $policy_status['required'] && ! $policy_status['has_2fa'] ) : ?>
								<br>
								<small style="color: #dc3232;">
									<?php
									if ( $policy_status['in_grace_period'] && $policy_status['grace_days_left'] > 0 ) {
										printf(
											/* translators: %d: number of days remaining */
											esc_html( _n( '%d day left', '%d days left', $policy_status['grace_days_left'], 'atomicedge' ) ),
											esc_html( $policy_status['grace_days_left'] )
										);
									} elseif ( $policy_status['required'] ) {
										echo esc_html__( 'Required', 'atomicedge' );
									}
									?>
								</small>
							<?php endif; ?>
						<?php endif; ?>
					</td>
					<td>
						<?php if ( $has_2fa ) : ?>
							<button type="button" class="button button-small atomicedge-reset-2fa" 
								data-user-id="<?php echo esc_attr( $user->ID ); ?>"
								data-username="<?php echo esc_attr( $user->user_login ); ?>">
								<?php echo esc_html__( 'Reset', 'atomicedge' ); ?>
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
		<h2 style="margin-top: 0;"><?php echo esc_html__( 'Reset 2FA?', 'atomicedge' ); ?></h2>
		<p>
			<?php echo esc_html__( 'Are you sure you want to reset Two-Factor Authentication for', 'atomicedge' ); ?>
			<strong id="reset-username"></strong>?
		</p>
		<p style="color: #dc3232;">
			<?php echo esc_html__( 'This will disable their 2FA and they will need to set it up again. Use this only if the user is locked out.', 'atomicedge' ); ?>
		</p>
		<form method="post" action="" id="reset-2fa-form">
			<?php wp_nonce_field( 'atomicedge_reset_2fa' ); ?>
			<input type="hidden" name="reset_user_id" id="reset-user-id" value="" />
			<input type="hidden" name="atomicedge_reset_2fa" value="1" />
			<p style="margin-bottom: 0;">
				<button type="submit" class="button button-primary" style="background: #dc3232; border-color: #dc3232;">
					<?php echo esc_html__( 'Yes, Reset 2FA', 'atomicedge' ); ?>
				</button>
				<button type="button" class="button" id="cancel-reset">
					<?php echo esc_html__( 'Cancel', 'atomicedge' ); ?>
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
	
	$('#atomicedge-reset-modal > div').on('click', function(e) {
		e.stopPropagation();
	});
})(jQuery);
</script>
