<?php
/**
 * Unified Admin Dashboard View (Bootstrap 5).
 *
 * Merges Settings and Token Manager into a single, comprehensive admin interface
 * with tabbed views for Dashboard overview, All Tokens, Settings, wp-config & JWT Configuration,
 * Usage Statistics, Token Tools, and Live API Explorer.
 *
 * @package    Jwt_Authenticator
 * @subpackage Jwt_Authenticator/admin/partials
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

global $wpdb;

// Current user and REST authentication credentials.
$current_user = wp_get_current_user();
$rest_nonce   = wp_create_nonce( 'wp_rest' );
$secret_set   = defined( 'JWT_AUTH_SECRET_KEY' ) && ! empty( JWT_AUTH_SECRET_KEY );
$cors_enabled = defined( 'JWT_AUTH_CORS_ENABLE' ) && JWT_AUTH_CORS_ENABLE;

// REST API Endpoints.
$api_settings = esc_url_raw( rest_url( 'jwt-auth/v1/admin/settings' ) );
$api_token    = esc_url_raw( rest_url( 'jwt-auth/v1/token' ) );
$api_base     = esc_url_raw( rest_url( 'jwt-auth/v1/admin/tokens' ) );

// System environment status.
$php_version   = PHP_VERSION;
$wp_version    = get_bloginfo( 'version' );
$mysql_version = $wpdb->get_var( 'SELECT VERSION()' ) ?: 'Unknown';

// Fetch top 50 users for the Generate Token dropdown.
$wp_users = get_users( [
	'number'  => 50,
	'orderby' => 'display_name',
	'order'   => 'ASC',
	'fields'  => [ 'ID', 'user_login', 'display_name', 'user_email' ],
] );

// --- General / JWT Core ------------------------------------------------
$access_exp  = (int) get_option( 'jwt_auth_access_token_expiry', 3600 );
$refresh_exp = (int) get_option( 'jwt_auth_refresh_token_expiry', 2592000 );
$custom_hdr  = get_option( 'jwt_auth_custom_header', 'Authorization' );
$allow_email = (bool) get_option( 'jwt_auth_allow_email_login', true );

// --- API Protection ----------------------------------------------------
$protection_mode = get_option( 'jwt_auth_protection_mode', 'disabled' );
$disable_guests  = (bool) get_option( 'jwt_auth_disable_rest_for_guests', false );
$disable_rest    = (bool) get_option( 'jwt_auth_disable_rest_api', false );

$whitelist_arr = json_decode( (string) get_option( 'jwt_auth_whitelisted_routes', '' ), true );
if ( ! is_array( $whitelist_arr ) ) {
	$whitelist_arr = [];
}
$protected_arr = json_decode( (string) get_option( 'jwt_auth_protected_routes', '' ), true );
if ( ! is_array( $protected_arr ) ) {
	$protected_arr = [];
}
$disabled_arr = json_decode( (string) get_option( 'jwt_auth_disabled_endpoints', '' ), true );
if ( ! is_array( $disabled_arr ) ) {
	$disabled_arr = [];
}

// --- Rate Limiting & Geo-IP --------------------------------------------
$rl_enabled     = (bool) get_option( 'jwt_auth_rate_limit_enabled', false );
$rl_requests    = (int) get_option( 'jwt_auth_rate_limit_requests', 100 );
$rl_window      = (int) get_option( 'jwt_auth_rate_limit_window', 3600 );
$rl_per_user    = (bool) get_option( 'jwt_auth_rate_limit_per_user', false );
$geoip_provider = get_option( 'jwt_auth_geoip_provider', 'ip-api' );
$geoip_key      = get_option( 'jwt_auth_geoip_api_key', '' );

// --- API Keys & OAuth --------------------------------------------------
$api_key_header  = get_option( 'jwt_auth_api_key_header', 'X-API-Key' );
$api_key_user_id = (int) get_option( 'jwt_auth_api_key_user_id', 1 );
$oauth_enabled   = (bool) get_option( 'jwt_auth_oauth_enabled', true );

// --- Firebase ----------------------------------------------------------
$fb_enabled     = (bool) get_option( 'jwt_auth_firebase_enabled', false );
$fb_project     = get_option( 'jwt_auth_firebase_project_id', '' );
$fb_web_key     = get_option( 'jwt_auth_firebase_web_api_key', '' );
$fb_providers   = json_decode( (string) get_option( 'jwt_auth_firebase_enabled_providers', '[]' ), true );
if ( ! is_array( $fb_providers ) ) {
	$fb_providers = [];
}
$fb_login_mode  = get_option( 'jwt_auth_firebase_login_mode', 'both' );
$fb_auto_create = (bool) get_option( 'jwt_auth_firebase_auto_create_users', true );

$fb_provider_list = [ 'google', 'facebook', 'apple', 'twitter', 'github', 'yahoo', 'microsoft', 'phone' ];

// --- WooCommerce & Firestore ------------------------------------------
$woo_checkout   = (bool) get_option( 'jwt_auth_woo_firebase_checkout', false );
$woo_myaccount  = (bool) get_option( 'jwt_auth_woo_firebase_myaccount', false );
$woo_sync       = (bool) get_option( 'jwt_auth_woo_sync_to_firebase', false );
$firestore_on   = (bool) get_option( 'jwt_auth_firestore_enabled', false );
$firestore_meta = (bool) get_option( 'jwt_auth_firestore_sync_user_meta', false );
?>

<div class="jwt-bootstrap-wrap">
	<!-- Top Banner -->
	<div class="jwt-header-banner d-flex justify-content-between align-items-center flex-wrap gap-3">
		<div class="d-flex align-items-center gap-3">
			<a href="<?php echo esc_url( admin_url( 'options-general.php?page=jwt_authenticator' ) ); ?>" class="d-inline-flex align-items-center text-decoration-none">
				<img src="<?php echo esc_url( plugins_url( 'jwt-logo.svg', dirname( dirname( __FILE__ ) ) ) ); ?>" alt="JWT Authenticator" height="34" class="jwt-brand-logo">
			</a>
			<div class="border-start ps-3 ms-1 d-none d-md-block" style="border-color: var(--bs-border-color) !important;">
				<p class="text-secondary mb-0 small"><?php esc_html_e( 'REST API authentication, route protection, rate limits, API keys, Firebase, and OAuth 2.0.', 'jwt-authenticator' ); ?></p>
			</div>
		</div>
		<div class="d-flex gap-2 align-items-center flex-wrap">
			<button type="button" class="btn btn-primary d-inline-flex align-items-center gap-1" id="jwt-btn-save-settings">
				<span class="dashicons dashicons-saved"></span> <?php esc_html_e( 'Save All Settings', 'jwt-authenticator' ); ?>
			</button>
		</div>
	</div>

	<?php if ( ! $secret_set ) : ?>
		<div class="alert alert-danger d-flex align-items-center gap-2 mb-4" role="alert">
			<span class="dashicons dashicons-warning" style="font-size: 20px;"></span>
			<div>
				<strong><?php esc_html_e( 'JWT Secret Key is not configured!', 'jwt-authenticator' ); ?></strong>
				<?php esc_html_e( 'Please add define(\'JWT_AUTH_SECRET_KEY\', \'your-secret-key-here\'); to your wp-config.php file to generate and validate tokens.', 'jwt-authenticator' ); ?>
				<a href="#pane-config" class="alert-link ms-2" onclick="switchToTab('tab-config-btn')"><?php esc_html_e( 'View wp-config Setup →', 'jwt-authenticator' ); ?></a>
			</div>
		</div>
	<?php endif; ?>

	<!-- Navigation Tabs -->
	<ul class="nav nav-tabs mb-4" id="jwtUnifiedTabs" role="tablist">
		<li class="nav-item" role="presentation">
			<button class="nav-link active" id="tab-dashboard-btn" data-bs-toggle="tab" data-bs-target="#pane-dashboard" type="button" role="tab" aria-controls="pane-dashboard" aria-selected="true">
				<span class="dashicons dashicons-dashboard"></span> <?php esc_html_e( 'Dashboard', 'jwt-authenticator' ); ?>
			</button>
		</li>
		<li class="nav-item" role="presentation">
			<button class="nav-link" id="tab-tools-btn" data-bs-toggle="tab" data-bs-target="#pane-tools" type="button" role="tab" aria-controls="pane-tools" aria-selected="false">
				<span class="dashicons dashicons-plus-alt2"></span> <?php esc_html_e( 'Generate Token', 'jwt-authenticator' ); ?>
			</button>
		</li>
		<li class="nav-item" role="presentation">
			<button class="nav-link" id="tab-tokens-btn" data-bs-toggle="tab" data-bs-target="#pane-tokens" type="button" role="tab" aria-controls="pane-tokens" aria-selected="false">
				<span class="dashicons dashicons-list-view"></span> <?php esc_html_e( 'All Tokens', 'jwt-authenticator' ); ?>
			</button>
		</li>
		<li class="nav-item" role="presentation">
			<button class="nav-link" id="tab-settings-btn" data-bs-toggle="tab" data-bs-target="#pane-settings" type="button" role="tab" aria-controls="pane-settings" aria-selected="false">
				<span class="dashicons dashicons-admin-generic"></span> <?php esc_html_e( 'Settings', 'jwt-authenticator' ); ?>
			</button>
		</li>
		<li class="nav-item" role="presentation">
			<button class="nav-link" id="tab-config-btn" data-bs-toggle="tab" data-bs-target="#pane-config" type="button" role="tab" aria-controls="pane-config" aria-selected="false">
				<span class="dashicons dashicons-admin-settings"></span> <?php esc_html_e( 'wp-config & JWT Configuration', 'jwt-authenticator' ); ?>
			</button>
		</li>
		<li class="nav-item" role="presentation">
			<button class="nav-link" id="tab-stats-btn" data-bs-toggle="tab" data-bs-target="#pane-stats" type="button" role="tab" aria-controls="pane-stats" aria-selected="false">
				<span class="dashicons dashicons-chart-bar"></span> <?php esc_html_e( 'Usage Statistics', 'jwt-authenticator' ); ?>
			</button>
		</li>
		<li class="nav-item" role="presentation">
			<button class="nav-link" id="tab-explorer-btn" data-bs-toggle="tab" data-bs-target="#pane-explorer" type="button" role="tab" aria-controls="pane-explorer" aria-selected="false">
				<span class="dashicons dashicons-visibility"></span> <?php esc_html_e( 'Live API Explorer', 'jwt-authenticator' ); ?>
			</button>
		</li>
	</ul>

	<!-- Tab Panes Content -->
	<div class="tab-content" id="jwtUnifiedTabContent">

		<!-- =================================================================== -->
		<!-- TAB 1: DASHBOARD (DEFAULT / ACTIVE) -->
		<!-- =================================================================== -->
		<div class="tab-pane fade show active" id="pane-dashboard" role="tabpanel" aria-labelledby="tab-dashboard-btn">
			<!-- 4 Stat Cards Row -->
			<div class="row g-3 mb-4">
				<div class="col-sm-6 col-xl-3">
					<div class="jwt-stat-card d-flex align-items-center gap-3" data-filter="all" style="cursor: pointer;" title="<?php esc_attr_e( 'Click to view all tokens', 'jwt-authenticator' ); ?>">
						<div class="jwt-stat-icon-wrap bg-primary-subtle text-primary">
							<span class="dashicons dashicons-database"></span>
						</div>
						<div>
							<div class="text-uppercase text-secondary fw-semibold" style="font-size: 11px;"><?php esc_html_e( 'Total Tokens', 'jwt-authenticator' ); ?></div>
							<div class="h4 fw-bold mb-0 text-dark" id="jwt-stat-total">—</div>
						</div>
					</div>
				</div>
				<div class="col-sm-6 col-xl-3">
					<div class="jwt-stat-card d-flex align-items-center gap-3" data-filter="active" style="cursor: pointer;" title="<?php esc_attr_e( 'Click to filter active tokens', 'jwt-authenticator' ); ?>">
						<div class="jwt-stat-icon-wrap bg-success-subtle text-success">
							<span class="dashicons dashicons-yes-alt"></span>
						</div>
						<div>
							<div class="text-uppercase text-secondary fw-semibold" style="font-size: 11px;"><?php esc_html_e( 'Active Tokens', 'jwt-authenticator' ); ?></div>
							<div class="h4 fw-bold mb-0 text-dark" id="jwt-stat-active">—</div>
						</div>
					</div>
				</div>
				<div class="col-sm-6 col-xl-3">
					<div class="jwt-stat-card d-flex align-items-center gap-3" data-filter="expired" style="cursor: pointer;" title="<?php esc_attr_e( 'Click to filter expired tokens', 'jwt-authenticator' ); ?>">
						<div class="jwt-stat-icon-wrap bg-warning-subtle text-warning">
							<span class="dashicons dashicons-clock"></span>
						</div>
						<div>
							<div class="text-uppercase text-secondary fw-semibold" style="font-size: 11px;"><?php esc_html_e( 'Expired Tokens', 'jwt-authenticator' ); ?></div>
							<div class="h4 fw-bold mb-0 text-dark" id="jwt-stat-expired">—</div>
						</div>
					</div>
				</div>
				<div class="col-sm-6 col-xl-3">
					<div class="jwt-stat-card d-flex align-items-center gap-3" data-filter="revoked" style="cursor: pointer;" title="<?php esc_attr_e( 'Click to filter revoked tokens', 'jwt-authenticator' ); ?>">
						<div class="jwt-stat-icon-wrap bg-danger-subtle text-danger">
							<span class="dashicons dashicons-dismiss"></span>
						</div>
						<div>
							<div class="text-uppercase text-secondary fw-semibold" style="font-size: 11px;"><?php esc_html_e( 'Revoked Tokens', 'jwt-authenticator' ); ?></div>
							<div class="h4 fw-bold mb-0 text-dark" id="jwt-stat-revoked">—</div>
						</div>
					</div>
				</div>
			</div>

			<!-- System & Environment Status Card -->
			<div class="card border-0 shadow-sm mb-4">
				<div class="card-header bg-white d-flex justify-content-between align-items-center">
					<span class="fw-bold text-dark d-inline-flex align-items-center gap-2">
						<span class="dashicons dashicons-admin-plugins text-primary"></span>
						<?php esc_html_e( 'System & Environment Status', 'jwt-authenticator' ); ?>
					</span>
					<button type="button" class="btn btn-sm btn-outline-primary d-inline-flex align-items-center gap-1" onclick="switchToTab('tab-config-btn')">
						<span class="dashicons dashicons-admin-settings"></span> <?php esc_html_e( 'wp-config Setup →', 'jwt-authenticator' ); ?>
					</button>
				</div>
				<div class="card-body">
					<div class="row g-3">
						<div class="col-md-4 col-sm-6">
							<div class="p-3 bg-light rounded border">
								<div class="text-secondary small fw-semibold text-uppercase" style="font-size: 11px;"><?php esc_html_e( 'PHP Version', 'jwt-authenticator' ); ?></div>
								<div class="d-flex align-items-center justify-content-between mt-1">
									<span class="h5 fw-bold text-dark mb-0"><?php echo esc_html( $php_version ); ?></span>
									<?php if ( version_compare( $php_version, '8.0', '>=' ) ) : ?>
										<span class="badge bg-success"><?php esc_html_e( 'Compatible', 'jwt-authenticator' ); ?></span>
									<?php else : ?>
										<span class="badge bg-danger"><?php esc_html_e( 'Upgrade Required', 'jwt-authenticator' ); ?></span>
									<?php endif; ?>
								</div>
							</div>
						</div>
						<div class="col-md-4 col-sm-6">
							<div class="p-3 bg-light rounded border">
								<div class="text-secondary small fw-semibold text-uppercase" style="font-size: 11px;"><?php esc_html_e( 'WordPress Version', 'jwt-authenticator' ); ?></div>
								<div class="d-flex align-items-center justify-content-between mt-1">
									<span class="h5 fw-bold text-dark mb-0"><?php echo esc_html( $wp_version ); ?></span>
									<span class="badge bg-primary">WP</span>
								</div>
							</div>
						</div>
						<div class="col-md-4 col-sm-6">
							<div class="p-3 bg-light rounded border">
								<div class="text-secondary small fw-semibold text-uppercase" style="font-size: 11px;"><?php esc_html_e( 'MySQL / Database', 'jwt-authenticator' ); ?></div>
								<div class="d-flex align-items-center justify-content-between mt-1">
									<span class="h6 fw-bold text-dark mb-0 font-monospace text-truncate" title="<?php echo esc_attr( $mysql_version ); ?>"><?php echo esc_html( $mysql_version ); ?></span>
									<span class="badge bg-secondary"><?php esc_html_e( 'SQL', 'jwt-authenticator' ); ?></span>
								</div>
							</div>
						</div>
						<div class="col-md-4 col-sm-6">
							<div class="p-3 bg-light rounded border">
								<div class="text-secondary small fw-semibold text-uppercase" style="font-size: 11px;"><?php esc_html_e( 'JWT Secret Key', 'jwt-authenticator' ); ?></div>
								<div class="d-flex align-items-center justify-content-between mt-1">
									<span class="h6 fw-bold mb-0">
										<?php if ( $secret_set ) : ?>
											<span class="badge bg-success"><?php esc_html_e( 'Configured', 'jwt-authenticator' ); ?></span>
										<?php else : ?>
											<span class="badge bg-danger"><?php esc_html_e( 'Not Configured', 'jwt-authenticator' ); ?></span>
										<?php endif; ?>
									</span>
									<code class="small text-muted">JWT_AUTH_SECRET_KEY</code>
								</div>
							</div>
						</div>
						<div class="col-md-4 col-sm-6">
							<div class="p-3 bg-light rounded border">
								<div class="text-secondary small fw-semibold text-uppercase" style="font-size: 11px;"><?php esc_html_e( 'CORS Support', 'jwt-authenticator' ); ?></div>
								<div class="d-flex align-items-center justify-content-between mt-1">
									<span class="h6 fw-bold mb-0">
										<?php if ( $cors_enabled ) : ?>
											<span class="badge bg-success"><?php esc_html_e( 'Enabled', 'jwt-authenticator' ); ?></span>
										<?php else : ?>
											<span class="badge bg-secondary"><?php esc_html_e( 'Disabled', 'jwt-authenticator' ); ?></span>
										<?php endif; ?>
									</span>
									<code class="small text-muted">JWT_AUTH_CORS_ENABLE</code>
								</div>
							</div>
						</div>
						<div class="col-md-4 col-sm-6">
							<div class="p-3 bg-light rounded border">
								<div class="text-secondary small fw-semibold text-uppercase" style="font-size: 11px;"><?php esc_html_e( 'Algorithm & Endpoint', 'jwt-authenticator' ); ?></div>
								<div class="d-flex align-items-center justify-content-between mt-1">
									<span class="badge bg-primary font-monospace">HS256</span>
									<code class="small text-muted text-truncate" style="max-width: 140px;" title="<?php echo esc_attr( $api_token ); ?>"><?php echo esc_html( '/jwt-auth/v1/token' ); ?></code>
								</div>
							</div>
						</div>
					</div>
				</div>
			</div>

			<!-- Quick Actions Toolbar -->
			<div class="card border-0 shadow-sm mb-4">
				<div class="card-header bg-white">
					<span class="fw-bold text-dark"><?php esc_html_e( 'Quick Actions', 'jwt-authenticator' ); ?></span>
				</div>
				<div class="card-body">
					<div class="d-flex flex-wrap gap-2">
						<button type="button" class="btn btn-primary d-inline-flex align-items-center gap-1" onclick="switchToTab('tab-tools-btn')">
							<span class="dashicons dashicons-plus-alt2" style="font-size: 16px; line-height: 1;"></span> <?php esc_html_e( 'Generate Token', 'jwt-authenticator' ); ?>
						</button>
						<button type="button" class="btn btn-outline-secondary d-inline-flex align-items-center gap-1" onclick="switchToTab('tab-tools-btn')">
							<span class="dashicons dashicons-update" style="font-size: 16px; line-height: 1;"></span> <?php esc_html_e( 'Refresh Tool', 'jwt-authenticator' ); ?>
						</button>
						<button type="button" class="btn btn-outline-danger d-inline-flex align-items-center gap-1" id="jwt-btn-purge-expired">
							<span class="dashicons dashicons-trash" style="font-size: 16px; line-height: 1;"></span> <?php esc_html_e( 'Purge Expired', 'jwt-authenticator' ); ?>
						</button>
						<button type="button" class="btn btn-outline-primary d-inline-flex align-items-center gap-1" id="jwt-btn-reload" title="<?php esc_attr_e( 'Reload Data', 'jwt-authenticator' ); ?>">
							<span class="dashicons dashicons-image-rotate" style="font-size: 16px; line-height: 1;"></span> <?php esc_html_e( 'Reload Data', 'jwt-authenticator' ); ?>
						</button>
						<button type="button" class="btn btn-outline-secondary d-inline-flex align-items-center gap-1" onclick="switchToTab('tab-tokens-btn')">
							<span class="dashicons dashicons-list-view" style="font-size: 16px; line-height: 1;"></span> <?php esc_html_e( 'View All Tokens', 'jwt-authenticator' ); ?>
						</button>
						<button type="button" class="btn btn-outline-secondary d-inline-flex align-items-center gap-1" onclick="switchToTab('tab-settings-btn')">
							<span class="dashicons dashicons-admin-generic" style="font-size: 16px; line-height: 1;"></span> <?php esc_html_e( 'Settings', 'jwt-authenticator' ); ?>
						</button>
						<button type="button" class="btn btn-outline-secondary d-inline-flex align-items-center gap-1" onclick="switchToTab('tab-explorer-btn')">
							<span class="dashicons dashicons-visibility" style="font-size: 16px; line-height: 1;"></span> <?php esc_html_e( 'Live API Explorer', 'jwt-authenticator' ); ?>
						</button>
					</div>
				</div>
			</div>
		</div>

		<!-- =================================================================== -->
		<!-- TAB 2: GENERATE TOKEN & TOOLS -->
		<!-- =================================================================== -->
		<div class="tab-pane fade" id="pane-tools" role="tabpanel" aria-labelledby="tab-tools-btn">
			<div class="row g-4">
				<!-- Tool 1: Generate Token Card -->
				<div class="col-lg-6">
					<div class="card border-0 shadow-sm h-100">
						<div class="card-header bg-white">
							<span class="fw-bold text-dark d-inline-flex align-items-center gap-2">
								<span class="dashicons dashicons-plus-alt2 text-primary"></span>
								<?php esc_html_e( 'Generate New JWT Token Pair', 'jwt-authenticator' ); ?>
							</span>
						</div>
						<div class="card-body">
							<form id="jwt-form-generate" onsubmit="return false;">
								<div class="mb-3">
									<label for="jwt-gen-user" class="form-label fw-bold"><?php esc_html_e( 'Target WordPress User:', 'jwt-authenticator' ); ?></label>
									<select id="jwt-gen-user" class="form-select" required>
										<option value=""><?php esc_html_e( '— Select WordPress User —', 'jwt-authenticator' ); ?></option>
										<?php foreach ( $wp_users as $u ) : ?>
											<option value="<?php echo esc_attr( $u->ID ); ?>">
												<?php echo esc_html( $u->display_name . ' (' . $u->user_login . ' - ' . $u->user_email . ')' ); ?>
											</option>
										<?php endforeach; ?>
									</select>
								</div>

								<div class="mb-4">
									<label for="jwt-gen-expiry" class="form-label fw-bold"><?php esc_html_e( 'Access Token Expiry Duration:', 'jwt-authenticator' ); ?></label>
									<select id="jwt-gen-expiry" class="form-select">
										<option value="3600"><?php esc_html_e( '1 Hour (Default)', 'jwt-authenticator' ); ?></option>
										<option value="86400"><?php esc_html_e( '24 Hours (1 Day)', 'jwt-authenticator' ); ?></option>
										<option value="604800"><?php esc_html_e( '7 Days', 'jwt-authenticator' ); ?></option>
										<option value="2592000"><?php esc_html_e( '30 Days', 'jwt-authenticator' ); ?></option>
										<option value="31536000"><?php esc_html_e( '1 Year (Long-lived)', 'jwt-authenticator' ); ?></option>
									</select>
								</div>

								<button type="button" class="btn btn-primary px-4" id="jwt-btn-do-generate">
									<span class="dashicons dashicons-admin-network" style="font-size: 16px; line-height: 1.2;"></span> <?php esc_html_e( 'Generate Token Pair Now', 'jwt-authenticator' ); ?>
								</button>
							</form>

							<!-- Generated Result Card -->
							<div id="jwt-gen-result" class="mt-4 p-3 bg-light rounded border border-primary-subtle" style="display: none;">
								<div class="d-flex align-items-center gap-2 mb-3 text-success fw-bold">
									<span class="dashicons dashicons-yes-alt"></span>
									<span><?php esc_html_e( 'Token Pair Generated Successfully!', 'jwt-authenticator' ); ?></span>
								</div>

								<div class="mb-3">
									<label class="form-label small fw-bold text-secondary"><?php esc_html_e( 'Access Token (Bearer):', 'jwt-authenticator' ); ?></label>
									<div class="input-group">
										<input type="text" readonly id="jwt-res-access" class="form-control font-monospace bg-white">
										<button class="btn btn-outline-secondary jwt-copy-btn" type="button" data-target="jwt-res-access"><?php esc_html_e( 'Copy', 'jwt-authenticator' ); ?></button>
									</div>
								</div>

								<div class="mb-3">
									<label class="form-label small fw-bold text-secondary"><?php esc_html_e( 'Refresh Token:', 'jwt-authenticator' ); ?></label>
									<div class="input-group">
										<input type="text" readonly id="jwt-res-refresh" class="form-control font-monospace bg-white">
										<button class="btn btn-outline-secondary jwt-copy-btn" type="button" data-target="jwt-res-refresh"><?php esc_html_e( 'Copy', 'jwt-authenticator' ); ?></button>
									</div>
								</div>

								<div>
									<label class="form-label small fw-bold text-secondary"><?php esc_html_e( 'cURL Authorization Example:', 'jwt-authenticator' ); ?></label>
									<pre id="jwt-res-curl" class="jwt-terminal-box"></pre>
								</div>
							</div>
						</div>
					</div>
				</div>

				<!-- Tool 2: Refresh & Rotate Tool Card -->
				<div class="col-lg-6">
					<div class="card border-0 shadow-sm h-100">
						<div class="card-header bg-white">
							<span class="fw-bold text-dark d-inline-flex align-items-center gap-2">
								<span class="dashicons dashicons-update text-secondary"></span>
								<?php esc_html_e( 'Refresh & Rotate Token Tool', 'jwt-authenticator' ); ?>
							</span>
						</div>
						<div class="card-body">
							<p class="text-secondary small mb-3">
								<?php esc_html_e( 'Enter any Refresh Token string or active Token JTI identifier to rotate it. The old refresh token will be revoked immediately and a fresh access + refresh pair will be issued.', 'jwt-authenticator' ); ?>
							</p>

							<form id="jwt-form-refresh" onsubmit="return false;">
								<div class="mb-3">
									<label for="jwt-ref-input" class="form-label fw-bold"><?php esc_html_e( 'Refresh Token String or JTI Identifier:', 'jwt-authenticator' ); ?></label>
									<textarea id="jwt-ref-input" rows="3" class="form-control font-monospace" placeholder="<?php esc_attr_e( 'Paste refresh_token string or enter jti identifier…', 'jwt-authenticator' ); ?>" required></textarea>
								</div>

								<button type="button" class="btn btn-primary px-4" id="jwt-btn-do-refresh">
									<span class="dashicons dashicons-update" style="font-size: 16px; line-height: 1.2;"></span> <?php esc_html_e( 'Execute Refresh & Rotate', 'jwt-authenticator' ); ?>
								</button>
							</form>

							<!-- Refresh Result Card -->
							<div id="jwt-refresh-result" class="mt-4 p-3 bg-light rounded border border-success-subtle" style="display: none;">
								<div class="d-flex align-items-center gap-2 mb-3 text-success fw-bold">
									<span class="dashicons dashicons-yes-alt"></span>
									<span><?php esc_html_e( 'Token Rotated and Refreshed Successfully!', 'jwt-authenticator' ); ?></span>
								</div>

								<div class="mb-3">
									<label class="form-label small fw-bold text-secondary"><?php esc_html_e( 'New Access Token:', 'jwt-authenticator' ); ?></label>
									<div class="input-group">
										<input type="text" readonly id="jwt-ref-res-access" class="form-control font-monospace bg-white">
										<button class="btn btn-outline-secondary jwt-copy-btn" type="button" data-target="jwt-ref-res-access"><?php esc_html_e( 'Copy', 'jwt-authenticator' ); ?></button>
									</div>
								</div>

								<div>
									<label class="form-label small fw-bold text-secondary"><?php esc_html_e( 'New Refresh Token:', 'jwt-authenticator' ); ?></label>
									<div class="input-group">
										<input type="text" readonly id="jwt-ref-res-refresh" class="form-control font-monospace bg-white">
										<button class="btn btn-outline-secondary jwt-copy-btn" type="button" data-target="jwt-ref-res-refresh"><?php esc_html_e( 'Copy', 'jwt-authenticator' ); ?></button>
									</div>
								</div>
							</div>
						</div>
					</div>
				</div>
			</div>
		</div>


		<!-- =================================================================== -->
		<!-- TAB 3: ALL TOKENS -->
		<!-- =================================================================== -->
		<div class="tab-pane fade" id="pane-tokens" role="tabpanel" aria-labelledby="tab-tokens-btn">
			<!-- Search & Filter Controls -->
			<div class="card border-0 shadow-sm mb-3">
				<div class="card-body p-3">
					<div class="row g-2 align-items-center">
						<div class="col-md-3">
							<select id="jwt-filter-status" class="form-select form-select-sm">
								<option value="all"><?php esc_html_e( 'All Statuses', 'jwt-authenticator' ); ?></option>
								<option value="active"><?php esc_html_e( '🟢 Active Only', 'jwt-authenticator' ); ?></option>
								<option value="expired"><?php esc_html_e( '🟡 Expired Only', 'jwt-authenticator' ); ?></option>
								<option value="revoked"><?php esc_html_e( '🔴 Revoked Only', 'jwt-authenticator' ); ?></option>
							</select>
						</div>
						<div class="col-md-3">
							<select id="jwt-filter-type" class="form-select form-select-sm">
								<option value="all"><?php esc_html_e( 'All Token Types', 'jwt-authenticator' ); ?></option>
								<option value="access"><?php esc_html_e( 'Access Tokens', 'jwt-authenticator' ); ?></option>
								<option value="refresh"><?php esc_html_e( 'Refresh Tokens', 'jwt-authenticator' ); ?></option>
							</select>
						</div>
						<div class="col-md-6">
							<div class="input-group input-group-sm">
								<input type="search" id="jwt-search-input" class="form-control" placeholder="<?php esc_attr_e( 'Search by user, email, or JTI…', 'jwt-authenticator' ); ?>">
								<button class="btn btn-outline-secondary" type="button" id="jwt-btn-search">
									<span class="dashicons dashicons-search" style="font-size: 14px; line-height: 1.2;"></span> <?php esc_html_e( 'Search', 'jwt-authenticator' ); ?>
								</button>
							</div>
						</div>
					</div>
				</div>
			</div>

			<!-- Tokens Table Card -->
			<div class="card border-0 shadow-sm">
				<div class="table-responsive">
					<table class="table table-hover table-striped align-middle mb-0" id="jwt-tokens-table">
						<thead class="table-light">
							<tr>
								<th style="width: 22%;"><?php esc_html_e( 'User', 'jwt-authenticator' ); ?></th>
								<th style="width: 10%;"><?php esc_html_e( 'Type', 'jwt-authenticator' ); ?></th>
								<th style="width: 22%;"><?php esc_html_e( 'Token Identifier (JTI)', 'jwt-authenticator' ); ?></th>
								<th style="width: 12%;"><?php esc_html_e( 'IP Address', 'jwt-authenticator' ); ?></th>
								<th style="width: 12%;"><?php esc_html_e( 'Issued At', 'jwt-authenticator' ); ?></th>
								<th style="width: 12%;"><?php esc_html_e( 'Status / Expires', 'jwt-authenticator' ); ?></th>
								<th style="width: 10%; text-align: right;"><?php esc_html_e( 'Actions', 'jwt-authenticator' ); ?></th>
							</tr>
						</thead>
						<tbody id="jwt-tokens-tbody">
							<tr>
								<td colspan="7" class="text-center py-4 text-secondary">
									<div class="spinner-border spinner-border-sm text-primary me-2" role="status"></div>
									<?php esc_html_e( 'Loading tokens from database…', 'jwt-authenticator' ); ?>
								</td>
							</tr>
						</tbody>
					</table>
				</div>

				<div class="card-footer bg-white border-top d-flex justify-content-between align-items-center py-3">
					<div class="small text-secondary" id="jwt-pagination-info">
						<?php esc_html_e( 'Showing 0 of 0 tokens', 'jwt-authenticator' ); ?>
					</div>
					<nav aria-label="Tokens pagination">
						<ul class="pagination pagination-sm mb-0" id="jwt-pagination-controls"></ul>
					</nav>
				</div>
			</div>
		</div>

		<!-- =================================================================== -->
		<!-- TAB 4: SETTINGS (CONSOLIDATED ACCORDION) -->
		<!-- =================================================================== -->
		<div class="tab-pane fade" id="pane-settings" role="tabpanel" aria-labelledby="tab-settings-btn">
			<div class="card border-0 shadow-sm mb-4">
				<div class="card-body p-0">
					<div class="accordion accordion-flush" id="jwtSettingsAccordion">

						<!-- Section 1: General & JWT Core -->
						<div class="accordion-item">
							<h2 class="accordion-header" id="headingGeneral">
								<button class="accordion-button fw-bold" type="button" data-bs-toggle="collapse" data-bs-target="#collapseGeneral" aria-expanded="true" aria-controls="collapseGeneral">
									<span class="dashicons dashicons-admin-generic me-2"></span> <?php esc_html_e( 'General & JWT Core', 'jwt-authenticator' ); ?>
								</button>
							</h2>
							<div id="collapseGeneral" class="accordion-collapse collapse show" aria-labelledby="headingGeneral" data-bs-parent="#jwtSettingsAccordion">
								<div class="accordion-body p-4">
									<div class="row g-3">
										<div class="col-md-6">
											<label for="jwt_auth_access_token_expiry" class="form-label fw-semibold"><?php esc_html_e( 'Access Token Expiry (seconds)', 'jwt-authenticator' ); ?></label>
											<input type="number" class="form-control" id="jwt_auth_access_token_expiry" value="<?php echo esc_attr( $access_exp ); ?>" min="60" step="60">
											<div class="form-text"><?php esc_html_e( 'Default 3600 (1 hour). How long an access token stays valid.', 'jwt-authenticator' ); ?></div>
										</div>
										<div class="col-md-6">
											<label for="jwt_auth_refresh_token_expiry" class="form-label fw-semibold"><?php esc_html_e( 'Refresh Token Expiry (seconds)', 'jwt-authenticator' ); ?></label>
											<input type="number" class="form-control" id="jwt_auth_refresh_token_expiry" value="<?php echo esc_attr( $refresh_exp ); ?>" min="3600" step="3600">
											<div class="form-text"><?php esc_html_e( 'Default 2592000 (30 days). Lifetime of a refresh token used for rotation.', 'jwt-authenticator' ); ?></div>
										</div>
										<div class="col-md-6">
											<label for="jwt_auth_custom_header" class="form-label fw-semibold"><?php esc_html_e( 'Custom Header Support', 'jwt-authenticator' ); ?></label>
											<input type="text" class="form-control font-monospace" id="jwt_auth_custom_header" value="<?php echo esc_attr( $custom_hdr ); ?>" placeholder="Authorization">
											<div class="form-text"><?php esc_html_e( 'Accept a Bearer token from an alternative header (e.g. X-Auth-Token, X-JWT-Token). Leave as Authorization for standard usage.', 'jwt-authenticator' ); ?></div>
										</div>
										<div class="col-md-6">
											<label class="form-label d-block fw-semibold"><?php esc_html_e( 'Login Methods', 'jwt-authenticator' ); ?></label>
											<div class="form-check form-switch mt-2">
												<input class="form-check-input" type="checkbox" id="jwt_auth_allow_email_login" <?php checked( $allow_email, true ); ?>>
												<label class="form-check-label" for="jwt_auth_allow_email_login"><?php esc_html_e( 'Allow login via email address in addition to username', 'jwt-authenticator' ); ?></label>
											</div>
											<div class="form-text"><?php esc_html_e( 'When enabled, the token endpoint accepts an email address in place of the username.', 'jwt-authenticator' ); ?></div>
										</div>
									</div>
								</div>
							</div>
						</div>

						<!-- Section 2: API Protection -->
						<div class="accordion-item">
							<h2 class="accordion-header" id="headingProtection">
								<button class="accordion-button fw-bold collapsed" type="button" data-bs-toggle="collapse" data-bs-target="#collapseProtection" aria-expanded="false" aria-controls="collapseProtection">
									<span class="dashicons dashicons-shield me-2"></span> <?php esc_html_e( 'API Protection', 'jwt-authenticator' ); ?>
								</button>
							</h2>
							<div id="collapseProtection" class="accordion-collapse collapse" aria-labelledby="headingProtection" data-bs-parent="#jwtSettingsAccordion">
								<div class="accordion-body p-4">
									<div class="row g-3">
										<div class="col-md-6">
											<label for="jwt_protection_mode" class="form-label fw-semibold"><?php esc_html_e( 'Protection Strategy', 'jwt-authenticator' ); ?></label>
											<select id="jwt_protection_mode" class="form-select">
												<option value="disabled" <?php selected( $protection_mode, 'disabled' ); ?>><?php esc_html_e( 'Standard (default WordPress permissions)', 'jwt-authenticator' ); ?></option>
												<option value="selective" <?php selected( $protection_mode, 'selective' ); ?>><?php esc_html_e( 'Selective — listed Protected routes require a valid token', 'jwt-authenticator' ); ?></option>
												<option value="full" <?php selected( $protection_mode, 'full' ); ?>><?php esc_html_e( 'Full — every endpoint requires a valid token (except Always-public)', 'jwt-authenticator' ); ?></option>
											</select>
											<div class="form-text"><?php esc_html_e( '“Selective” enforces the Protected routes list; “Full” requires authentication for all endpoints except those marked Always-public.', 'jwt-authenticator' ); ?></div>
										</div>
										<div class="col-md-6 d-flex align-items-center">
											<div class="w-100">
												<div class="form-check form-switch">
													<input class="form-check-input" type="checkbox" id="jwt_disable_rest_for_guests" <?php checked( $disable_guests, true ); ?>>
													<label class="form-check-label" for="jwt_disable_rest_for_guests"><?php esc_html_e( 'Block guest (non-logged-in) REST access', 'jwt-authenticator' ); ?></label>
												</div>
												<div class="form-check form-switch mt-2">
													<input class="form-check-input" type="checkbox" id="jwt_disable_rest_api" <?php checked( $disable_rest, true ); ?>>
													<label class="form-check-label" for="jwt_disable_rest_api"><?php esc_html_e( 'Disable REST API for non-admins entirely', 'jwt-authenticator' ); ?></label>
												</div>
											</div>
										</div>
										<div class="col-md-4">
											<label for="jwt_whitelisted_routes" class="form-label fw-semibold"><?php esc_html_e( 'Always-public routes (bypass auth)', 'jwt-authenticator' ); ?></label>
											<textarea class="form-control font-monospace" id="jwt_whitelisted_routes" rows="5" placeholder="/jwt-auth/v1/token&#10;/wp/v2/posts"><?php echo esc_textarea( implode( "\n", $whitelist_arr ) ); ?></textarea>
											<div class="form-text"><?php esc_html_e( 'One route per line. Wildcards supported, e.g. /wp/v2/*.', 'jwt-authenticator' ); ?></div>
										</div>
										<div class="col-md-4">
											<label for="jwt_protected_routes" class="form-label fw-semibold"><?php esc_html_e( 'Protected routes (require token)', 'jwt-authenticator' ); ?></label>
											<textarea class="form-control font-monospace" id="jwt_protected_routes" rows="5" placeholder="/wp/v2/users&#10;/wp/v2/settings"><?php echo esc_textarea( implode( "\n", $protected_arr ) ); ?></textarea>
											<div class="form-text"><?php esc_html_e( 'Enforced only in Selective mode.', 'jwt-authenticator' ); ?></div>
										</div>
										<div class="col-md-4">
											<label for="jwt_disabled_endpoints" class="form-label fw-semibold"><?php esc_html_e( 'Disabled endpoints (blocked entirely)', 'jwt-authenticator' ); ?></label>
											<textarea class="form-control font-monospace" id="jwt_disabled_endpoints" rows="5" placeholder="/wp/v2/settings"><?php echo esc_textarea( implode( "\n", $disabled_arr ) ); ?></textarea>
											<div class="form-text"><?php esc_html_e( 'Returns 404 for everyone regardless of authentication.', 'jwt-authenticator' ); ?></div>
										</div>
									</div>
								</div>
							</div>
						</div>

						<!-- Section 3: Rate Limiting & Geo-IP -->
						<div class="accordion-item">
							<h2 class="accordion-header" id="headingRateLimit">
								<button class="accordion-button fw-bold collapsed" type="button" data-bs-toggle="collapse" data-bs-target="#collapseRateLimit" aria-expanded="false" aria-controls="collapseRateLimit">
									<span class="dashicons dashicons-clock me-2"></span> <?php esc_html_e( 'Rate Limiting & Geo-IP', 'jwt-authenticator' ); ?>
								</button>
							</h2>
							<div id="collapseRateLimit" class="accordion-collapse collapse" aria-labelledby="headingRateLimit" data-bs-parent="#jwtSettingsAccordion">
								<div class="accordion-body p-4">
									<div class="row g-3">
										<div class="col-md-6">
											<label class="form-label d-block fw-semibold"><?php esc_html_e( 'REST API Rate Limiting', 'jwt-authenticator' ); ?></label>
											<div class="form-check form-switch mb-2">
												<input class="form-check-input" type="checkbox" id="jwt_rate_limit_enabled" <?php checked( $rl_enabled, true ); ?>>
												<label class="form-check-label" for="jwt_rate_limit_enabled"><?php esc_html_e( 'Enable rate limiting on REST API requests', 'jwt-authenticator' ); ?></label>
											</div>
											<div class="row g-2">
												<div class="col-6">
													<label for="jwt_rate_limit_requests" class="form-label"><?php esc_html_e( 'Max requests', 'jwt-authenticator' ); ?></label>
													<input type="number" class="form-control" id="jwt_rate_limit_requests" value="<?php echo esc_attr( $rl_requests ); ?>" min="5" max="10000">
												</div>
												<div class="col-6">
													<label for="jwt_rate_limit_window" class="form-label"><?php esc_html_e( 'Window (seconds)', 'jwt-authenticator' ); ?></label>
													<input type="number" class="form-control" id="jwt_rate_limit_window" value="<?php echo esc_attr( $rl_window ); ?>" min="10" max="86400">
												</div>
											</div>
											<div class="form-check form-switch mt-2">
												<input class="form-check-input" type="checkbox" id="jwt_rate_limit_per_user" <?php checked( $rl_per_user, true ); ?>>
												<label class="form-check-label" for="jwt_rate_limit_per_user"><?php esc_html_e( 'Count per authenticated user instead of per IP', 'jwt-authenticator' ); ?></label>
											</div>
										</div>
										<div class="col-md-6">
											<label class="form-label d-block fw-semibold"><?php esc_html_e( 'Geo-IP Identification', 'jwt-authenticator' ); ?></label>
											<label for="jwt_geoip_provider" class="form-label"><?php esc_html_e( 'Provider', 'jwt-authenticator' ); ?></label>
											<select id="jwt_geoip_provider" class="form-select mb-2">
												<option value="none" <?php selected( $geoip_provider, 'none' ); ?>><?php esc_html_e( 'Disabled (no Geo-IP lookups)', 'jwt-authenticator' ); ?></option>
												<option value="ip-api" <?php selected( $geoip_provider, 'ip-api' ); ?>>ip-api.com</option>
												<option value="ipapi" <?php selected( $geoip_provider, 'ipapi' ); ?>>ipapi.co</option>
												<option value="ipinfo" <?php selected( $geoip_provider, 'ipinfo' ); ?>>ipinfo.io</option>
											</select>
											<label for="jwt_geoip_api_key" class="form-label"><?php esc_html_e( 'Provider API key (if required)', 'jwt-authenticator' ); ?></label>
											<input type="text" class="form-control" id="jwt_geoip_api_key" value="<?php echo esc_attr( $geoip_key ); ?>" autocomplete="off">
											<div class="form-text"><?php esc_html_e( 'Records the country of origin for authenticated requests. Choose “Disabled” to turn off lookups entirely.', 'jwt-authenticator' ); ?></div>
										</div>
									</div>
								</div>
							</div>
						</div>

						<!-- Section 4: API Keys & OAuth 2.0 -->
						<div class="accordion-item">
							<h2 class="accordion-header" id="headingApiKeys">
								<button class="accordion-button fw-bold collapsed" type="button" data-bs-toggle="collapse" data-bs-target="#collapseApiKeys" aria-expanded="false" aria-controls="collapseApiKeys">
									<span class="dashicons dashicons-admin-network me-2"></span> <?php esc_html_e( 'API Keys & OAuth 2.0', 'jwt-authenticator' ); ?>
								</button>
							</h2>
							<div id="collapseApiKeys" class="accordion-collapse collapse" aria-labelledby="headingApiKeys" data-bs-parent="#jwtSettingsAccordion">
								<div class="accordion-body p-4">
									<div class="row g-3">
										<div class="col-md-6">
											<h6 class="fw-bold mb-2"><?php esc_html_e( 'API Key Authentication', 'jwt-authenticator' ); ?></h6>
											<p class="small text-secondary mb-3"><?php esc_html_e( 'API keys are accepted from the header below, or from ?api_key=, or an Authorization: Apikey … header.', 'jwt-authenticator' ); ?></p>
											<label for="jwt_api_key_header" class="form-label fw-semibold"><?php esc_html_e( 'API Key Header Name', 'jwt-authenticator' ); ?></label>
											<input type="text" class="form-control font-monospace mb-3" id="jwt_api_key_header" value="<?php echo esc_attr( $api_key_header ); ?>" placeholder="X-API-Key">
											<label for="jwt_api_key_user_id" class="form-label fw-semibold"><?php esc_html_e( 'Fallback user ID for universal keys', 'jwt-authenticator' ); ?></label>
											<input type="number" class="form-control" id="jwt_api_key_user_id" value="<?php echo esc_attr( $api_key_user_id ); ?>" min="1" step="1">
											<div class="form-text"><?php esc_html_e( 'The user identity assigned to universal (non-user-scoped) API keys.', 'jwt-authenticator' ); ?></div>
										</div>
										<div class="col-md-6">
											<h6 class="fw-bold mb-2"><?php esc_html_e( 'OAuth 2.0 Authorization Server', 'jwt-authenticator' ); ?></h6>
											<p class="small text-secondary mb-3"><?php esc_html_e( 'Enables the /jwt-auth/v1/oauth/* endpoints (password, refresh_token, client_credentials grants).', 'jwt-authenticator' ); ?></p>
											<div class="form-check form-switch">
												<input class="form-check-input" type="checkbox" id="jwt_oauth_enabled" <?php checked( $oauth_enabled, true ); ?>>
												<label class="form-check-label" for="jwt_oauth_enabled"><?php esc_html_e( 'Enable OAuth 2.0 endpoints', 'jwt-authenticator' ); ?></label>
											</div>
										</div>
									</div>
								</div>
							</div>
						</div>

						<!-- Section 5: Firebase & WooCommerce -->
						<div class="accordion-item">
							<h2 class="accordion-header" id="headingFirebase">
								<button class="accordion-button fw-bold collapsed" type="button" data-bs-toggle="collapse" data-bs-target="#collapseFirebase" aria-expanded="false" aria-controls="collapseFirebase">
									<span class="dashicons dashicons-cloud me-2"></span> <?php esc_html_e( 'Firebase & WooCommerce', 'jwt-authenticator' ); ?>
								</button>
							</h2>
							<div id="collapseFirebase" class="accordion-collapse collapse" aria-labelledby="headingFirebase" data-bs-parent="#jwtSettingsAccordion">
								<div class="accordion-body p-4">
									<div class="row g-3">
										<div class="col-md-6">
											<div class="form-check form-switch mb-3">
												<input class="form-check-input" type="checkbox" id="jwt_firebase_enabled" <?php checked( $fb_enabled, true ); ?>>
												<label class="form-check-label fw-semibold" for="jwt_firebase_enabled"><?php esc_html_e( 'Enable Firebase authentication', 'jwt-authenticator' ); ?></label>
											</div>
											<div class="mb-2">
												<label for="jwt_firebase_project_id" class="form-label"><?php esc_html_e( 'Firebase Project ID', 'jwt-authenticator' ); ?></label>
												<input type="text" class="form-control" id="jwt_firebase_project_id" value="<?php echo esc_attr( $fb_project ); ?>" placeholder="my-firebase-app">
											</div>
											<div class="mb-2">
												<label for="jwt_firebase_web_api_key" class="form-label"><?php esc_html_e( 'Firebase Web API Key', 'jwt-authenticator' ); ?></label>
												<input type="text" class="form-control font-monospace" id="jwt_firebase_web_api_key" value="<?php echo esc_attr( $fb_web_key ); ?>" placeholder="AIza…" autocomplete="off">
											</div>
											<div class="mb-2">
												<label for="jwt_firebase_login_mode" class="form-label"><?php esc_html_e( 'Login Mode', 'jwt-authenticator' ); ?></label>
												<select id="jwt_firebase_login_mode" class="form-select">
													<option value="both" <?php selected( $fb_login_mode, 'both' ); ?>><?php esc_html_e( 'Both — WordPress and Firebase', 'jwt-authenticator' ); ?></option>
													<option value="firebase_only" <?php selected( $fb_login_mode, 'firebase_only' ); ?>><?php esc_html_e( 'Firebase only — block WordPress login', 'jwt-authenticator' ); ?></option>
												</select>
											</div>
											<div class="form-check form-switch mt-3">
												<input class="form-check-input" type="checkbox" id="jwt_firebase_auto_create_users" <?php checked( $fb_auto_create, true ); ?>>
												<label class="form-check-label" for="jwt_firebase_auto_create_users"><?php esc_html_e( 'Auto-create WordPress users from Firebase credentials', 'jwt-authenticator' ); ?></label>
											</div>
										</div>
										<div class="col-md-6">
											<label class="form-label fw-semibold"><?php esc_html_e( 'Enabled Social Providers', 'jwt-authenticator' ); ?></label>
											<div class="row row-cols-2 g-2 mb-2">
												<?php foreach ( $fb_provider_list as $slug ) : ?>
													<div class="col">
														<div class="form-check">
															<input class="form-check-input jwt-fb-provider" type="checkbox" id="jwt_fb_provider_<?php echo esc_attr( $slug ); ?>" value="<?php echo esc_attr( $slug ); ?>" <?php checked( in_array( $slug, $fb_providers, true ) ); ?>>
															<label class="form-check-label text-capitalize" for="jwt_fb_provider_<?php echo esc_attr( $slug ); ?>"><?php echo esc_html( $slug ); ?></label>
														</div>
													</div>
												<?php endforeach; ?>
											</div>
											<hr class="my-3">
											<h6 class="fw-bold mb-2"><?php esc_html_e( 'WooCommerce Integration', 'jwt-authenticator' ); ?></h6>
											<div class="form-check form-switch mb-2">
												<input class="form-check-input" type="checkbox" id="jwt_woo_firebase_checkout" <?php checked( $woo_checkout, true ); ?>>
												<label class="form-check-label" for="jwt_woo_firebase_checkout"><?php esc_html_e( 'Show Firebase login on WooCommerce checkout', 'jwt-authenticator' ); ?></label>
											</div>
											<div class="form-check form-switch mb-2">
												<input class="form-check-input" type="checkbox" id="jwt_woo_firebase_myaccount" <?php checked( $woo_myaccount, true ); ?>>
												<label class="form-check-label" for="jwt_woo_firebase_myaccount"><?php esc_html_e( 'Show Firebase login on My Account page', 'jwt-authenticator' ); ?></label>
											</div>
											<div class="form-check form-switch mb-2">
												<input class="form-check-input" type="checkbox" id="jwt_woo_sync_to_firebase" <?php checked( $woo_sync, true ); ?>>
												<label class="form-check-label" for="jwt_woo_sync_to_firebase"><?php esc_html_e( 'Auto-register WooCommerce customers to Firebase', 'jwt-authenticator' ); ?></label>
											</div>
											<div class="form-check form-switch mb-2">
												<input class="form-check-input" type="checkbox" id="jwt_firestore_enabled" <?php checked( $firestore_on, true ); ?>>
												<label class="form-check-label" for="jwt_firestore_enabled"><?php esc_html_e( 'Enable Cloud Firestore sync', 'jwt-authenticator' ); ?></label>
											</div>
											<div class="form-check form-switch">
												<input class="form-check-input" type="checkbox" id="jwt_firestore_sync_user_meta" <?php checked( $firestore_meta, true ); ?>>
												<label class="form-check-label" for="jwt_firestore_sync_user_meta"><?php esc_html_e( 'Sync user meta to Firestore', 'jwt-authenticator' ); ?></label>
											</div>
										</div>
									</div>
								</div>
							</div>
						</div>

					</div>
				</div>
				<div class="card-footer bg-white border-top d-flex justify-content-end p-3">
					<button type="button" class="btn btn-primary d-inline-flex align-items-center gap-1" id="jwt-btn-save-settings-inline">
						<span class="dashicons dashicons-saved"></span> <?php esc_html_e( 'Save All Settings', 'jwt-authenticator' ); ?>
					</button>
				</div>
			</div>
		</div>

		<!-- =================================================================== -->
		<!-- TAB 5: WP-CONFIG & JWT CONFIGURATION -->
		<!-- =================================================================== -->
		<div class="tab-pane fade" id="pane-config" role="tabpanel" aria-labelledby="tab-config-btn">
			<div class="row g-4">
				<div class="col-lg-7">
					<div class="card border-0 shadow-sm h-100">
						<div class="card-header bg-white d-flex justify-content-between align-items-center">
							<span class="fw-bold text-dark"><?php esc_html_e( 'Detected wp-config.php JWT Configuration', 'jwt-authenticator' ); ?></span>
							<button type="button" class="btn btn-sm btn-outline-primary" id="jwt-btn-reload-config">
								<span class="dashicons dashicons-update" style="font-size: 14px; line-height: 1;"></span> <?php esc_html_e( 'Re-detect', 'jwt-authenticator' ); ?>
							</button>
						</div>
						<div class="card-body">
							<div class="table-responsive">
								<table class="table table-borderless align-middle">
									<tbody>
										<tr>
											<td class="fw-bold text-secondary" style="width: 35%;"><?php esc_html_e( 'wp-config.php Status:', 'jwt-authenticator' ); ?></td>
											<td>
												<span id="jwt-cfg-file-status" class="badge bg-secondary"><?php esc_html_e( 'Detecting…', 'jwt-authenticator' ); ?></span>
												<div class="small text-muted font-monospace mt-1" id="jwt-cfg-file-path"></div>
											</td>
										</tr>
										<tr>
											<td class="fw-bold text-secondary"><?php esc_html_e( 'JWT_AUTH_SECRET_KEY:', 'jwt-authenticator' ); ?></td>
											<td>
												<div class="d-flex align-items-center gap-2">
													<span id="jwt-cfg-key-status" class="badge bg-secondary"><?php esc_html_e( 'Detecting…', 'jwt-authenticator' ); ?></span>
													<code id="jwt-cfg-key-masked" class="jwt-code-pill">—</code>
												</div>
												<div class="small text-muted mt-1" id="jwt-cfg-key-details"></div>
											</td>
										</tr>
										<tr>
											<td class="fw-bold text-secondary"><?php esc_html_e( 'Key Bit Strength:', 'jwt-authenticator' ); ?></td>
											<td>
												<span id="jwt-cfg-key-strength" class="badge bg-info text-dark">—</span>
											</td>
										</tr>
										<tr>
											<td class="fw-bold text-secondary"><?php esc_html_e( 'JWT_AUTH_CORS_ENABLE:', 'jwt-authenticator' ); ?></td>
											<td>
												<span id="jwt-cfg-cors" class="badge bg-secondary">—</span>
											</td>
										</tr>
										<tr>
											<td class="fw-bold text-secondary"><?php esc_html_e( 'JWT_AUTH_DEV_MODE:', 'jwt-authenticator' ); ?></td>
											<td>
												<span id="jwt-cfg-dev" class="badge bg-secondary">—</span>
											</td>
										</tr>
										<tr>
											<td class="fw-bold text-secondary"><?php esc_html_e( 'Active Algorithm:', 'jwt-authenticator' ); ?></td>
											<td>
												<span class="badge bg-primary font-monospace" id="jwt-cfg-alg">HS256</span>
											</td>
										</tr>
										<tr>
											<td class="fw-bold text-secondary"><?php esc_html_e( 'Access Expiry:', 'jwt-authenticator' ); ?></td>
											<td>
												<span class="text-dark fw-semibold" id="jwt-cfg-access-exp">—</span>
											</td>
										</tr>
										<tr>
											<td class="fw-bold text-secondary"><?php esc_html_e( 'Refresh Expiry:', 'jwt-authenticator' ); ?></td>
											<td>
												<span class="text-dark fw-semibold" id="jwt-cfg-refresh-exp">—</span>
											</td>
										</tr>
										<tr>
											<td class="fw-bold text-secondary"><?php esc_html_e( 'Auth Header:', 'jwt-authenticator' ); ?></td>
											<td>
												<code class="jwt-code-pill" id="jwt-cfg-header">Authorization: Bearer &lt;token&gt;</code>
											</td>
										</tr>
									</tbody>
								</table>
							</div>
						</div>
					</div>
				</div>

				<div class="col-lg-5">
					<div class="card border-0 shadow-sm h-100">
						<div class="card-header bg-white">
							<span class="fw-bold text-dark"><?php esc_html_e( 'wp-config.php Setup Code', 'jwt-authenticator' ); ?></span>
						</div>
						<div class="card-body d-flex flex-column">
							<p class="small text-secondary mb-3">
								<?php esc_html_e( 'Paste these lines into your wp-config.php file above the /* That\'s all, stop editing! Happy publishing. */ line.', 'jwt-authenticator' ); ?>
							</p>

							<div class="mb-3">
								<button type="button" class="btn btn-sm btn-outline-success mb-2" id="jwt-btn-gen-secret">
									<span class="dashicons dashicons-randomize" style="font-size: 14px; line-height: 1;"></span> <?php esc_html_e( 'Generate Random Secure Key', 'jwt-authenticator' ); ?>
								</button>
								<pre class="jwt-terminal-box" id="jwt-config-snippet">define( 'JWT_AUTH_SECRET_KEY', 'your-strong-random-secret-key-goes-here' );
define( 'JWT_AUTH_CORS_ENABLE', true );</pre>
							</div>

							<div class="mt-auto">
								<button type="button" class="btn btn-primary btn-sm w-100" id="jwt-btn-copy-config">
									<span class="dashicons dashicons-admin-page" style="font-size: 14px; line-height: 1;"></span> <?php esc_html_e( 'Copy wp-config Snippet', 'jwt-authenticator' ); ?>
								</button>
							</div>
						</div>
					</div>
				</div>
			</div>
		</div>

		<!-- =================================================================== -->
		<!-- TAB 6: USAGE STATISTICS -->
		<!-- =================================================================== -->
		<div class="tab-pane fade" id="pane-stats" role="tabpanel" aria-labelledby="tab-stats-btn">
			<!-- Metrics Row -->
			<div class="row g-3 mb-4">
				<div class="col-sm-6 col-md-3">
					<div class="card border-0 shadow-sm text-center p-3">
						<div class="text-uppercase text-secondary small fw-bold"><?php esc_html_e( 'Active Sessions', 'jwt-authenticator' ); ?></div>
						<div class="h3 fw-bold text-success mb-0 mt-2" id="jwt-stat-active-sessions">—</div>
					</div>
				</div>
				<div class="col-sm-6 col-md-3">
					<div class="card border-0 shadow-sm text-center p-3">
						<div class="text-uppercase text-secondary small fw-bold"><?php esc_html_e( 'Issued (24 Hours)', 'jwt-authenticator' ); ?></div>
						<div class="h3 fw-bold text-primary mb-0 mt-2" id="jwt-stat-24h">—</div>
					</div>
				</div>
				<div class="col-sm-6 col-md-3">
					<div class="card border-0 shadow-sm text-center p-3">
						<div class="text-uppercase text-secondary small fw-bold"><?php esc_html_e( 'Issued (7 Days)', 'jwt-authenticator' ); ?></div>
						<div class="h3 fw-bold text-info mb-0 mt-2" id="jwt-stat-7d">—</div>
					</div>
				</div>
				<div class="col-sm-6 col-md-3">
					<div class="card border-0 shadow-sm text-center p-3">
						<div class="text-uppercase text-secondary small fw-bold"><?php esc_html_e( 'Issued (30 Days)', 'jwt-authenticator' ); ?></div>
						<div class="h3 fw-bold text-dark mb-0 mt-2" id="jwt-stat-30d">—</div>
					</div>
				</div>
			</div>

			<!-- Token Ratio Breakdown -->
			<div class="card border-0 shadow-sm mb-4">
				<div class="card-header bg-white">
					<span class="fw-bold text-dark"><?php esc_html_e( 'Token Type Distribution', 'jwt-authenticator' ); ?></span>
				</div>
				<div class="card-body">
					<div class="d-flex justify-content-between mb-2 small fw-bold">
						<span class="text-primary" id="jwt-ratio-access-label"><?php esc_html_e( 'Access Tokens: —', 'jwt-authenticator' ); ?></span>
						<span class="text-info text-dark" id="jwt-ratio-refresh-label"><?php esc_html_e( 'Refresh Tokens: —', 'jwt-authenticator' ); ?></span>
					</div>
					<div class="progress" style="height: 16px;">
						<div id="jwt-ratio-bar-access" class="progress-bar bg-primary" role="progressbar" style="width: 50%;"></div>
						<div id="jwt-ratio-bar-refresh" class="progress-bar bg-info" role="progressbar" style="width: 50%;"></div>
					</div>
				</div>
			</div>

			<div class="row g-4">
				<!-- Top Users by Active Tokens -->
				<div class="col-lg-7">
					<div class="card border-0 shadow-sm h-100">
						<div class="card-header bg-white">
							<span class="fw-bold text-dark"><?php esc_html_e( 'Top Users by Active Tokens', 'jwt-authenticator' ); ?></span>
						</div>
						<div class="table-responsive">
							<table class="table table-hover align-middle mb-0">
								<thead class="table-light">
									<tr>
										<th><?php esc_html_e( 'User', 'jwt-authenticator' ); ?></th>
										<th><?php esc_html_e( 'Active Tokens', 'jwt-authenticator' ); ?></th>
										<th style="text-align: right;"><?php esc_html_e( 'Action', 'jwt-authenticator' ); ?></th>
									</tr>
								</thead>
								<tbody id="jwt-top-users-tbody">
									<tr><td colspan="3" class="text-center py-3 text-muted"><?php esc_html_e( 'Loading top users…', 'jwt-authenticator' ); ?></td></tr>
								</tbody>
							</table>
						</div>
					</div>
				</div>

				<!-- Recent IP Activity -->
				<div class="col-lg-5">
					<div class="card border-0 shadow-sm h-100">
						<div class="card-header bg-white">
							<span class="fw-bold text-dark"><?php esc_html_e( 'Recent Client IP Addresses', 'jwt-authenticator' ); ?></span>
						</div>
						<div class="table-responsive">
							<table class="table table-hover align-middle mb-0">
								<thead class="table-light">
									<tr>
										<th><?php esc_html_e( 'IP Address', 'jwt-authenticator' ); ?></th>
										<th><?php esc_html_e( 'Tokens', 'jwt-authenticator' ); ?></th>
										<th><?php esc_html_e( 'Last Seen', 'jwt-authenticator' ); ?></th>
									</tr>
								</thead>
								<tbody id="jwt-recent-ips-tbody">
									<tr><td colspan="3" class="text-center py-3 text-muted"><?php esc_html_e( 'Loading IP activity…', 'jwt-authenticator' ); ?></td></tr>
								</tbody>
							</table>
						</div>
					</div>
				</div>
			</div>
		</div>

		<!-- =================================================================== -->
		<!-- TAB 7: LIVE API EXPLORER -->
		<!-- =================================================================== -->
		<div class="tab-pane fade" id="pane-explorer" role="tabpanel" aria-labelledby="tab-explorer-btn">
			<div class="row g-3">
				<div class="col-lg-5">
					<div class="card h-100 border-0 shadow-sm">
						<div class="card-header bg-white">
							<span class="fw-bold text-dark"><?php esc_html_e( 'Test Token Generation (/jwt-auth/v1/token)', 'jwt-authenticator' ); ?></span>
						</div>
						<div class="card-body">
							<form id="jwt-api-test-form" onsubmit="return false;">
								<div class="mb-3">
									<label for="jwt-test-user" class="form-label fw-semibold"><?php esc_html_e( 'Username or Email', 'jwt-authenticator' ); ?></label>
									<input type="text" class="form-control" id="jwt-test-user" value="<?php echo esc_attr( $current_user->user_login ); ?>" required>
								</div>
								<div class="mb-3">
									<label for="jwt-test-pass" class="form-label fw-semibold"><?php esc_html_e( 'Password', 'jwt-authenticator' ); ?></label>
									<input type="password" class="form-control" id="jwt-test-pass" placeholder="••••••••" required>
								</div>
								<button type="button" class="btn btn-primary w-100" id="jwt-btn-run-test">
									<span class="dashicons dashicons-controls-play"></span> <?php esc_html_e( 'Send Request', 'jwt-authenticator' ); ?>
								</button>
							</form>
						</div>
					</div>
				</div>
				<div class="col-lg-7">
					<div class="card h-100 border-0 shadow-sm">
						<div class="card-header bg-white d-flex justify-content-between align-items-center">
							<span class="fw-bold text-dark"><?php esc_html_e( 'Response Output', 'jwt-authenticator' ); ?></span>
							<span id="jwt-test-status" class="badge bg-secondary"><?php esc_html_e( 'Awaiting request', 'jwt-authenticator' ); ?></span>
						</div>
						<div class="card-body d-flex flex-column">
							<pre id="jwt-test-output" class="jwt-terminal-box flex-grow-1" style="min-height: 200px;"><?php esc_html_e( '// JSON response will appear here after sending the request…', 'jwt-authenticator' ); ?></pre>
						</div>
					</div>
				</div>
			</div>
		</div>

	</div>
</div>

<!-- Floating Toast Notification -->
<div id="jwt-toast" class="jwt-toast-notification"></div>

<script>
(function() {
	'use strict';

	// REST API Configuration Endpoints
	const API_BASE     = <?php echo wp_json_encode( $api_base ); ?>;
	const API_SETTINGS = <?php echo wp_json_encode( $api_settings ); ?>;
	const API_TOKEN    = <?php echo wp_json_encode( $api_token ); ?>;
	const NONCE        = <?php echo wp_json_encode( $rest_nonce ); ?>;
	const SITE_URL     = <?php echo wp_json_encode( get_bloginfo( 'url' ) ); ?>;

	// Localized UI strings
	const I18N = <?php echo wp_json_encode( array(
		'saving'           => __( 'Saving…', 'jwt-authenticator' ),
		'save_failed'      => __( 'Save failed', 'jwt-authenticator' ),
		'saved'            => __( 'All settings saved successfully!', 'jwt-authenticator' ),
		'error_saving'     => __( 'Error saving settings:', 'jwt-authenticator' ),
		'need_credentials' => __( 'Please provide username and password for testing.', 'jwt-authenticator' ),
		'sending'          => __( 'Sending…', 'jwt-authenticator' ),
		'connecting'       => __( 'Connecting to', 'jwt-authenticator' ),
		'network_error'    => __( 'Network Error', 'jwt-authenticator' ),
		'request_failed'   => __( 'Request failed:', 'jwt-authenticator' ),
		'copied'           => __( 'Copied to clipboard!', 'jwt-authenticator' ),
		'copy_failed'      => __( 'Failed to copy', 'jwt-authenticator' ),
		'jti_copied'       => __( 'JTI copied to clipboard!', 'jwt-authenticator' ),
		'snippet_copied'   => __( 'wp-config snippet copied to clipboard!', 'jwt-authenticator' ),
		'key_generated'    => __( 'Generated 64-character cryptographic secret key!', 'jwt-authenticator' ),
		'confirm_revoke'   => __( 'Are you sure you want to revoke this token? Any request using this token will be immediately rejected.', 'jwt-authenticator' ),
		'confirm_delete'   => __( 'Permanently delete this token record from the database? This cannot be undone.', 'jwt-authenticator' ),
		'confirm_purge'    => __( 'Are you sure you want to purge all expired tokens from the database?', 'jwt-authenticator' ),
		'confirm_user_rev' => __( 'Revoke all active tokens for this user?', 'jwt-authenticator' ),
		'token_revoked'    => __( 'Token revoked successfully!', 'jwt-authenticator' ),
		'token_deleted'    => __( 'Token permanently deleted!', 'jwt-authenticator' ),
		'token_refreshed'  => __( 'Token rotated and refreshed successfully!', 'jwt-authenticator' ),
		'user_revoked'     => __( 'All tokens for user revoked!', 'jwt-authenticator' ),
		'select_user'      => __( 'Please select a target user.', 'jwt-authenticator' ),
		'enter_refresh'    => __( 'Please enter a refresh token string or JTI.', 'jwt-authenticator' ),
		'generating'       => __( 'Generating…', 'jwt-authenticator' ),
		'refreshing'       => __( 'Refreshing…', 'jwt-authenticator' ),
		'token_gen_succ'   => __( 'Token pair generated successfully!', 'jwt-authenticator' ),
		'loading_tokens'   => __( 'Loading tokens…', 'jwt-authenticator' ),
		'no_tokens_found'  => __( 'No tokens found matching the current criteria.', 'jwt-authenticator' ),
		'no_users_found'   => __( 'No active tokens recorded yet.', 'jwt-authenticator' ),
		'no_ips_found'     => __( 'No IP logs recorded yet.', 'jwt-authenticator' ),
	) ); ?>;

	// State
	let currentPage   = 1;
	let currentStatus = 'all';
	let currentType   = 'all';
	let currentSearch = '';

	// DOM Elements
	const tbody           = document.getElementById('jwt-tokens-tbody');
	const statTotal       = document.getElementById('jwt-stat-total');
	const statActive      = document.getElementById('jwt-stat-active');
	const statExpired     = document.getElementById('jwt-stat-expired');
	const statRevoked     = document.getElementById('jwt-stat-revoked');
	const filterStatus    = document.getElementById('jwt-filter-status');
	const filterType      = document.getElementById('jwt-filter-type');
	const searchInput     = document.getElementById('jwt-search-input');
	const searchBtn       = document.getElementById('jwt-btn-search');
	const reloadBtn       = document.getElementById('jwt-btn-reload');
	const purgeExpiredBtn = document.getElementById('jwt-btn-purge-expired');
	const paginationInfo  = document.getElementById('jwt-pagination-info');
	const paginationCtrl  = document.getElementById('jwt-pagination-controls');
	const toastEl         = document.getElementById('jwt-toast');

	// Tab Switcher with backward compatibility
	window.switchToTab = function(btnId) {
		if (btnId === 'tab-refresh-btn' || btnId === 'tab-generate-btn') {
			btnId = 'tab-tools-btn';
		}
		const btn = document.getElementById(btnId);
		if (btn) {
			if (typeof bootstrap !== 'undefined' && bootstrap.Tab) {
				const tabInstance = bootstrap.Tab.getOrCreateInstance ? bootstrap.Tab.getOrCreateInstance(btn) : new bootstrap.Tab(btn);
				tabInstance.show();
			} else {
				btn.click();
			}
		}
	};

	// Toast Notification Helper
	function showToast(msg, isError = false) {
		if (!toastEl) return;
		toastEl.textContent = msg;
		toastEl.style.background = isError ? '#dc3545' : '#212529';
		toastEl.style.display = 'block';
		setTimeout(() => { toastEl.style.display = 'none'; }, 3500);
	}

	// Form Element Helpers
	function val(id) {
		const el = document.getElementById(id);
		return el ? el.value : '';
	}
	function num(id) {
		return parseInt(val(id), 10) || 0;
	}
	function checked(id) {
		const el = document.getElementById(id);
		return el ? el.checked : false;
	}
	function lines(id) {
		return (val(id) || '').split('\n').map(s => s.trim()).filter(Boolean);
	}

	function copyToClipboard(text, msg) {
		if (!navigator.clipboard) {
			const ta = document.createElement('textarea');
			ta.value = text;
			document.body.appendChild(ta);
			ta.select();
			try {
				document.execCommand('copy');
				showToast(msg || I18N.copied);
			} catch (err) {
				showToast(I18N.copy_failed, true);
			}
			document.body.removeChild(ta);
			return;
		}
		navigator.clipboard.writeText(text)
			.then(() => showToast(msg || I18N.copied))
			.catch(() => showToast(I18N.copy_failed, true));
	}

	function escapeHtml(str) {
		if (!str) return '';
		return String(str)
			.replace(/&/g, '&amp;')
			.replace(/</g, '&lt;')
			.replace(/>/g, '&gt;')
			.replace(/"/g, '&quot;')
			.replace(/'/g, '&#039;');
	}

	function formatDate(str) {
		if (!str) return '—';
		const d = new Date(str.replace(' ', 'T') + 'Z');
		if (isNaN(d.getTime())) return str;
		return d.toLocaleString(undefined, {
			month: 'short', day: 'numeric', year: 'numeric', hour: '2-digit', minute: '2-digit'
		});
	}

	// -------------------------------------------------------------------------
	// TAB 1 & 2: TOKENS LIST & OVERVIEW
	// -------------------------------------------------------------------------
	async function loadTokens(page = 1) {
		currentPage = page;
		if (tbody) {
			tbody.innerHTML = `<tr><td colspan="7" class="text-center py-4 text-secondary"><div class="spinner-border spinner-border-sm text-primary me-2"></div>${I18N.loading_tokens}</td></tr>`;
		}

		const params = new URLSearchParams({
			page: currentPage,
			per_page: 20,
			status: currentStatus,
			type: currentType,
			search: currentSearch
		});

		try {
			const res = await fetch(`${API_BASE}?${params.toString()}`, {
				headers: { 'X-WP-Nonce': NONCE }
			});
			if (!res.ok) throw new Error('Failed to fetch tokens');
			const data = await res.json();

			if (data.stats) {
				if (statTotal) statTotal.textContent     = Number(data.stats.total).toLocaleString();
				if (statActive) statActive.textContent   = Number(data.stats.active).toLocaleString();
				if (statExpired) statExpired.textContent = Number(data.stats.expired).toLocaleString();
				if (statRevoked) statRevoked.textContent = Number(data.stats.revoked).toLocaleString();
			}

			renderRows(data.tokens);
			renderPagination(data.pagination);
		} catch (err) {
			if (tbody) {
				tbody.innerHTML = `<tr><td colspan="7" class="text-danger text-center py-4">${escapeHtml(err.message)}</td></tr>`;
			}
		}
	}

	function renderRows(tokens) {
		if (!tbody) return;
		if (!tokens || tokens.length === 0) {
			tbody.innerHTML = `<tr><td colspan="7" class="text-center py-5 text-secondary">${I18N.no_tokens_found}</td></tr>`;
			return;
		}

		tbody.innerHTML = tokens.map(t => {
			const statusBadge = t.status === 'active'
				? `<span class="badge bg-success">🟢 Active</span>`
				: (t.status === 'revoked'
					? `<span class="badge bg-danger">🔴 Revoked</span>`
					: `<span class="badge bg-warning text-dark">🟡 Expired</span>`);

			const typeBadge = t.token_type === 'refresh'
				? `<span class="badge bg-info text-dark">Refresh</span>`
				: `<span class="badge bg-primary">Access</span>`;

			const isRevoked = t.revoked || t.status === 'revoked';

			return `
				<tr data-jti="${t.jti}">
					<td>
						<div class="d-flex align-items-center gap-2">
							<img src="${t.avatar_url}" alt="" class="rounded-circle" width="32" height="32">
							<div class="d-flex flex-column" style="line-height: 1.2;">
								<span class="fw-bold text-dark small">${escapeHtml(t.display_name)}</span>
								<span class="text-muted" style="font-size: 11px;">${escapeHtml(t.user_email || t.username)}</span>
							</div>
						</div>
					</td>
					<td>${typeBadge}</td>
					<td>
						<div class="d-flex align-items-center gap-2">
							<code class="jwt-code-pill" title="${t.jti}">${t.jti.substring(0, 14)}…</code>
							<button type="button" class="btn btn-sm btn-outline-secondary py-0 px-1 jwt-btn-copy-jti" data-copy="${t.jti}" style="font-size: 11px;">Copy</button>
						</div>
					</td>
					<td><code class="small text-muted">${escapeHtml(t.ip_address)}</code></td>
					<td><span class="small text-secondary">${formatDate(t.issued_at)}</span></td>
					<td>
						<div>${statusBadge}</div>
						<span class="small text-muted" style="font-size: 11px;">${formatDate(t.expires_at)}</span>
					</td>
					<td style="text-align: right;">
						<div class="d-inline-flex gap-1">
							<button type="button" class="btn btn-sm btn-outline-primary py-0 px-2 jwt-act-refresh" data-jti="${t.jti}" title="Rotate & Refresh Token">
								Refresh
							</button>
							${!isRevoked ? `
								<button type="button" class="btn btn-sm btn-outline-warning py-0 px-2 jwt-act-revoke" data-jti="${t.jti}" title="Revoke this token">
									Revoke
								</button>
							` : ''}
							<button type="button" class="btn btn-sm btn-outline-danger py-0 px-2 jwt-act-delete" data-jti="${t.jti}" title="Permanently delete from database">
								Delete
							</button>
						</div>
					</td>
				</tr>
			`;
		}).join('');

		tbody.querySelectorAll('.jwt-btn-copy-jti').forEach(btn => {
			btn.addEventListener('click', () => copyToClipboard(btn.getAttribute('data-copy'), I18N.jti_copied));
		});

		tbody.querySelectorAll('.jwt-act-refresh').forEach(btn => {
			btn.addEventListener('click', () => refreshSingleToken(btn.getAttribute('data-jti')));
		});

		tbody.querySelectorAll('.jwt-act-revoke').forEach(btn => {
			btn.addEventListener('click', () => revokeSingleToken(btn.getAttribute('data-jti')));
		});

		tbody.querySelectorAll('.jwt-act-delete').forEach(btn => {
			btn.addEventListener('click', () => deleteSingleToken(btn.getAttribute('data-jti')));
		});
	}

	function renderPagination(pg) {
		if (!paginationInfo || !paginationCtrl || !pg) return;
		paginationInfo.textContent = `Showing ${pg.total > 0 ? (pg.page - 1) * pg.per_page + 1 : 0}–${Math.min(pg.page * pg.per_page, pg.total)} of ${pg.total.toLocaleString()} tokens`;

		let html = '';
		if (pg.page > 1) {
			html += `<li class="page-item"><button type="button" class="page-link" data-goto="${pg.page - 1}">&laquo; Prev</button></li>`;
		}
		if (pg.page < pg.total_pages) {
			html += `<li class="page-item"><button type="button" class="page-link" data-goto="${pg.page + 1}">Next &raquo;</button></li>`;
		}
		paginationCtrl.innerHTML = html;

		paginationCtrl.querySelectorAll('button[data-goto]').forEach(btn => {
			btn.addEventListener('click', () => loadTokens(parseInt(btn.getAttribute('data-goto'), 10)));
		});
	}

	async function revokeSingleToken(jti) {
		if (!confirm(I18N.confirm_revoke)) return;
		try {
			const res = await fetch(`${API_BASE}/${jti}`, {
				method: 'DELETE',
				headers: { 'X-WP-Nonce': NONCE, 'Content-Type': 'application/json' },
				body: JSON.stringify({ hard: false })
			});
			const data = await res.json();
			if (!res.ok) throw new Error(data.message || 'Revoke failed');
			showToast(I18N.token_revoked);
			loadTokens(currentPage);
			loadStats();
		} catch (err) {
			showToast(err.message, true);
		}
	}

	async function deleteSingleToken(jti) {
		if (!confirm(I18N.confirm_delete)) return;
		try {
			const res = await fetch(`${API_BASE}/${jti}`, {
				method: 'DELETE',
				headers: { 'X-WP-Nonce': NONCE, 'Content-Type': 'application/json' },
				body: JSON.stringify({ hard: true })
			});
			const data = await res.json();
			if (!res.ok) throw new Error(data.message || 'Delete failed');
			showToast(I18N.token_deleted);
			loadTokens(currentPage);
			loadStats();
		} catch (err) {
			showToast(err.message, true);
		}
	}

	async function refreshSingleToken(jti) {
		try {
			const res = await fetch(`${API_BASE}/refresh`, {
				method: 'POST',
				headers: { 'X-WP-Nonce': NONCE, 'Content-Type': 'application/json' },
				body: JSON.stringify({ jti: jti })
			});
			const data = await res.json();
			if (!res.ok) throw new Error(data.message || 'Refresh failed');

			const accessEl = document.getElementById('jwt-ref-res-access');
			const refreshEl = document.getElementById('jwt-ref-res-refresh');
			const resultBox = document.getElementById('jwt-refresh-result');

			if (accessEl) accessEl.value = data.access_token || '';
			if (refreshEl) refreshEl.value = data.refresh_token || '';
			if (resultBox) resultBox.style.display = 'block';

			switchToTab('tab-tools-btn');
			showToast(I18N.token_refreshed);
			loadTokens(currentPage);
			loadStats();
		} catch (err) {
			showToast(err.message, true);
		}
	}

	// Purge Expired Tokens
	if (purgeExpiredBtn) {
		purgeExpiredBtn.addEventListener('click', async () => {
			if (!confirm(I18N.confirm_purge)) return;
			try {
				const res = await fetch(`${API_BASE}/purge-expired`, {
					method: 'POST',
					headers: { 'X-WP-Nonce': NONCE, 'Content-Type': 'application/json' }
				});
				const data = await res.json();
				if (!res.ok) throw new Error(data.message || 'Purge failed');
				showToast(data.message || 'Expired tokens purged!');
				loadTokens(1);
				loadStats();
			} catch (err) {
				showToast(err.message, true);
			}
		});
	}

	// Filters & Search
	if (filterStatus) {
		filterStatus.addEventListener('change', () => { currentStatus = filterStatus.value; loadTokens(1); });
	}
	if (filterType) {
		filterType.addEventListener('change', () => { currentType = filterType.value; loadTokens(1); });
	}
	if (searchBtn) {
		searchBtn.addEventListener('click', () => { currentSearch = searchInput ? searchInput.value.trim() : ''; loadTokens(1); });
	}
	if (searchInput) {
		searchInput.addEventListener('keydown', (e) => {
			if (e.key === 'Enter') {
				e.preventDefault();
				currentSearch = searchInput.value.trim();
				loadTokens(1);
			}
		});
	}
	if (reloadBtn) {
		reloadBtn.addEventListener('click', () => {
			loadTokens(currentPage);
			loadStats();
			loadConfig();
			showToast('Data refreshed');
		});
	}

	// Clickable Stat Cards (Tab 1) -> Switches to All Tokens with filter
	document.querySelectorAll('.jwt-stat-card').forEach(card => {
		card.addEventListener('click', () => {
			const filter = card.getAttribute('data-filter') || 'all';
			if (filterStatus) {
				filterStatus.value = filter;
			}
			currentStatus = filter;
			switchToTab('tab-tokens-btn');
			loadTokens(1);
		});
	});

	// -------------------------------------------------------------------------
	// TAB 3: SAVE SETTINGS
	// -------------------------------------------------------------------------
	async function saveAllSettings(btn) {
		const targetBtn = btn || document.getElementById('jwt-btn-save-settings');
		const allSaveBtns = [
			document.getElementById('jwt-btn-save-settings'),
			document.getElementById('jwt-btn-save-settings-inline')
		].filter(Boolean);

		allSaveBtns.forEach(b => {
			b.disabled = true;
			b.dataset.origHtml = b.innerHTML;
			b.innerHTML = '<span class="spinner-border spinner-border-sm me-1"></span> ' + I18N.saving;
		});

		const payload = {
			access_token_expiry:        num('jwt_auth_access_token_expiry'),
			refresh_token_expiry:       num('jwt_auth_refresh_token_expiry'),
			custom_header:              val('jwt_auth_custom_header').trim(),
			allow_email_login:          checked('jwt_auth_allow_email_login'),
			protection_mode:            val('jwt_protection_mode'),
			disable_rest_for_guests:    checked('jwt_disable_rest_for_guests'),
			disable_rest_api:           checked('jwt_disable_rest_api'),
			whitelisted_routes:         lines('jwt_whitelisted_routes'),
			protected_routes:           lines('jwt_protected_routes'),
			disabled_endpoints:         lines('jwt_disabled_endpoints'),
			rate_limit_enabled:         checked('jwt_rate_limit_enabled'),
			rate_limit_requests:        num('jwt_rate_limit_requests'),
			rate_limit_window:          num('jwt_rate_limit_window'),
			rate_limit_per_user:        checked('jwt_rate_limit_per_user'),
			geoip_provider:             val('jwt_geoip_provider'),
			geoip_api_key:              val('jwt_geoip_api_key').trim(),
			api_key_header:             val('jwt_api_key_header').trim(),
			api_key_user_id:            num('jwt_api_key_user_id'),
			oauth_enabled:              checked('jwt_oauth_enabled'),
			firebase_enabled:           checked('jwt_firebase_enabled'),
			firebase_project_id:        val('jwt_firebase_project_id').trim(),
			firebase_web_api_key:       val('jwt_firebase_web_api_key').trim(),
			firebase_enabled_providers: Array.from(document.querySelectorAll('.jwt-fb-provider:checked')).map(cb => cb.value),
			firebase_login_mode:        val('jwt_firebase_login_mode'),
			firebase_auto_create_users: checked('jwt_firebase_auto_create_users'),
			woo_firebase_checkout:      checked('jwt_woo_firebase_checkout'),
			woo_firebase_myaccount:     checked('jwt_woo_firebase_myaccount'),
			woo_sync_to_firebase:       checked('jwt_woo_sync_to_firebase'),
			firestore_enabled:          checked('jwt_firestore_enabled'),
			firestore_sync_user_meta:   checked('jwt_firestore_sync_user_meta')
		};

		try {
			const res = await fetch(API_SETTINGS, {
				method: 'POST',
				headers: { 'X-WP-Nonce': NONCE, 'Content-Type': 'application/json' },
				body: JSON.stringify({ jwt_auth_options: payload })
			});
			const data = await res.json();
			if (!res.ok) throw new Error(data.message || I18N.save_failed);
			showToast(I18N.saved);
			loadConfig();
		} catch (err) {
			showToast(I18N.error_saving + ' ' + err.message, true);
		} finally {
			allSaveBtns.forEach(b => {
				b.disabled = false;
				if (b.dataset.origHtml) b.innerHTML = b.dataset.origHtml;
			});
		}
	}

	const btnSaveHeader = document.getElementById('jwt-btn-save-settings');
	if (btnSaveHeader) {
		btnSaveHeader.addEventListener('click', () => saveAllSettings(btnSaveHeader));
	}
	const btnSaveInline = document.getElementById('jwt-btn-save-settings-inline');
	if (btnSaveInline) {
		btnSaveInline.addEventListener('click', () => saveAllSettings(btnSaveInline));
	}

	// -------------------------------------------------------------------------
	// TAB 5: WP-CONFIG & JWT CONFIG DETECTION
	// -------------------------------------------------------------------------
	async function loadConfig() {
		try {
			const res = await fetch(`${API_BASE}/config-detect`, { headers: { 'X-WP-Nonce': NONCE } });
			if (!res.ok) throw new Error('Failed to load configuration status');
			const data = await res.json();

			const fileBadge = document.getElementById('jwt-cfg-file-status');
			if (fileBadge) {
				if (data.wp_config_found) {
					fileBadge.className = 'badge bg-success';
					fileBadge.textContent = 'Found & Accessible';
				} else {
					fileBadge.className = 'badge bg-danger';
					fileBadge.textContent = 'Not Found';
				}
			}
			const filePathEl = document.getElementById('jwt-cfg-file-path');
			if (filePathEl) filePathEl.textContent = data.wp_config_path || '';

			const keyBadge = document.getElementById('jwt-cfg-key-status');
			const keyMasked = document.getElementById('jwt-cfg-key-masked');
			const keyDetails = document.getElementById('jwt-cfg-key-details');

			if (keyBadge) {
				if (data.secret_key_configured) {
					keyBadge.className = 'badge bg-success';
					keyBadge.textContent = 'Configured & Active';
					if (keyMasked) keyMasked.textContent = data.secret_key_masked;
					if (keyDetails) keyDetails.textContent = data.secret_key_note || `${data.secret_key_length} characters (${data.secret_key_length * 8}-bit entropy)`;
				} else if (data.misplaced) {
					keyBadge.className = 'badge bg-warning text-dark';
					keyBadge.textContent = 'Misplaced in wp-config.php';
					if (keyMasked) keyMasked.textContent = data.secret_key_masked || '••••••••';
					if (keyDetails) keyDetails.innerHTML = '<span class="text-danger fw-bold">Placed AFTER wp-settings.php!</span> Move define(\'JWT_AUTH_SECRET_KEY\') above /* That\'s all, stop editing! */';
				} else {
					keyBadge.className = 'badge bg-danger';
					keyBadge.textContent = 'Missing';
					if (keyMasked) keyMasked.textContent = 'Not Configured';
					if (keyDetails) keyDetails.textContent = data.secret_key_note || 'Add define(\'JWT_AUTH_SECRET_KEY\', \'...\') to wp-config.php';
				}
			}

			const strengthBadge = document.getElementById('jwt-cfg-key-strength');
			if (strengthBadge) {
				strengthBadge.textContent = data.secret_key_strength;
				strengthBadge.className = data.secret_key_configured ? 'badge bg-success' : 'badge bg-danger';
			}

			const corsBadge = document.getElementById('jwt-cfg-cors');
			if (corsBadge) {
				corsBadge.textContent = data.cors_enabled ? 'Enabled' : 'Disabled';
				corsBadge.className = data.cors_enabled ? 'badge bg-success' : 'badge bg-secondary';
			}

			const devBadge = document.getElementById('jwt-cfg-dev');
			if (devBadge) {
				devBadge.textContent = data.dev_mode ? 'Active' : 'Inactive';
				devBadge.className = data.dev_mode ? 'badge bg-warning text-dark' : 'badge bg-secondary';
			}

			const algEl = document.getElementById('jwt-cfg-alg');
			if (algEl) algEl.textContent = data.algorithm;

			const accExpEl = document.getElementById('jwt-cfg-access-exp');
			if (accExpEl) accExpEl.textContent = `${Number(data.access_token_expiry).toLocaleString()} seconds (${Math.round(data.access_token_expiry / 3600)}h)`;

			const refExpEl = document.getElementById('jwt-cfg-refresh-exp');
			if (refExpEl) refExpEl.textContent = `${Number(data.refresh_token_expiry).toLocaleString()} seconds (${Math.round(data.refresh_token_expiry / 86400)}d)`;

			const hdrEl = document.getElementById('jwt-cfg-header');
			if (hdrEl) hdrEl.textContent = `${data.custom_header}: Bearer <token>`;
		} catch (err) {
			console.error('Config detect error:', err);
		}
	}

	const btnReloadConfig = document.getElementById('jwt-btn-reload-config');
	if (btnReloadConfig) {
		btnReloadConfig.addEventListener('click', loadConfig);
	}

	const btnGenSecret = document.getElementById('jwt-btn-gen-secret');
	if (btnGenSecret) {
		btnGenSecret.addEventListener('click', () => {
			const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()-_=+[]{}';
			let randomKey = '';
			for (let i = 0; i < 64; i++) {
				randomKey += chars.charAt(Math.floor(Math.random() * chars.length));
			}
			const snippetEl = document.getElementById('jwt-config-snippet');
			if (snippetEl) {
				snippetEl.textContent = `define( 'JWT_AUTH_SECRET_KEY', '${randomKey}' );\ndefine( 'JWT_AUTH_CORS_ENABLE', true );`;
			}
			showToast(I18N.key_generated);
		});
	}

	const btnCopyConfig = document.getElementById('jwt-btn-copy-config');
	if (btnCopyConfig) {
		btnCopyConfig.addEventListener('click', () => {
			const snippetEl = document.getElementById('jwt-config-snippet');
			if (snippetEl) {
				copyToClipboard(snippetEl.textContent, I18N.snippet_copied);
			}
		});
	}

	// -------------------------------------------------------------------------
	// TAB 6: USAGE STATISTICS
	// -------------------------------------------------------------------------
	async function loadStats() {
		try {
			const res = await fetch(`${API_BASE}/stats`, { headers: { 'X-WP-Nonce': NONCE } });
			if (!res.ok) throw new Error('Failed to load stats');
			const data = await res.json();

			const activeSess = document.getElementById('jwt-stat-active-sessions');
			const s24h       = document.getElementById('jwt-stat-24h');
			const s7d        = document.getElementById('jwt-stat-7d');
			const s30d       = document.getElementById('jwt-stat-30d');

			if (activeSess) activeSess.textContent = Number(data.active).toLocaleString();
			if (s24h) s24h.textContent             = Number(data.created_24h).toLocaleString();
			if (s7d) s7d.textContent               = Number(data.created_7d).toLocaleString();
			if (s30d) s30d.textContent             = Number(data.created_30d).toLocaleString();

			// Token Ratio Breakdown
			const totalTokens = (data.access_count + data.refresh_count) || 1;
			const accessPct   = Math.round((data.access_count / totalTokens) * 100);
			const refreshPct  = 100 - accessPct;

			const ratioAccLabel = document.getElementById('jwt-ratio-access-label');
			const ratioRefLabel = document.getElementById('jwt-ratio-refresh-label');
			const barAccess     = document.getElementById('jwt-ratio-bar-access');
			const barRefresh    = document.getElementById('jwt-ratio-bar-refresh');

			if (ratioAccLabel) ratioAccLabel.textContent = `Access Tokens: ${Number(data.access_count).toLocaleString()} (${accessPct}%)`;
			if (ratioRefLabel) ratioRefLabel.textContent = `Refresh Tokens: ${Number(data.refresh_count).toLocaleString()} (${refreshPct}%)`;
			if (barAccess) barAccess.style.width = `${accessPct}%`;
			if (barRefresh) barRefresh.style.width = `${refreshPct}%`;

			// Top Users
			const topUsersTbody = document.getElementById('jwt-top-users-tbody');
			if (topUsersTbody) {
				if (data.top_users && data.top_users.length > 0) {
					topUsersTbody.innerHTML = data.top_users.map(u => `
						<tr>
							<td>
								<div class="d-flex align-items-center gap-2">
									<img src="${u.avatar_url}" alt="" class="rounded-circle" width="28" height="28">
									<div class="d-flex flex-column" style="line-height: 1.2;">
										<span class="fw-bold text-dark small">${escapeHtml(u.display_name)}</span>
										<span class="text-muted" style="font-size: 11px;">${escapeHtml(u.user_email || u.username)}</span>
									</div>
								</div>
							</td>
							<td><span class="badge bg-success-subtle text-success fw-bold">${u.token_count} active</span></td>
							<td style="text-align: right;">
								<button type="button" class="btn btn-sm btn-outline-danger py-0 px-2 jwt-btn-revoke-user" data-user="${u.user_id}">Revoke All</button>
							</td>
						</tr>
					`).join('');

					topUsersTbody.querySelectorAll('.jwt-btn-revoke-user').forEach(btn => {
						btn.addEventListener('click', async () => {
							const uid = btn.getAttribute('data-user');
							if (!confirm(I18N.confirm_user_rev)) return;
							try {
								const r = await fetch(`${API_BASE}/revoke-user`, {
									method: 'POST',
									headers: { 'X-WP-Nonce': NONCE, 'Content-Type': 'application/json' },
									body: JSON.stringify({ user_id: parseInt(uid, 10) })
								});
								const d = await r.json();
								if (!r.ok) throw new Error(d.message);
								showToast(I18N.user_revoked);
								loadTokens(currentPage);
								loadStats();
							} catch (e) {
								showToast(e.message, true);
							}
						});
					});
				} else {
					topUsersTbody.innerHTML = `<tr><td colspan="3" class="text-center py-3 text-secondary">${I18N.no_users_found}</td></tr>`;
				}
			}

			// Recent IPs
			const recentIpsTbody = document.getElementById('jwt-recent-ips-tbody');
			if (recentIpsTbody) {
				if (data.recent_ips && data.recent_ips.length > 0) {
					recentIpsTbody.innerHTML = data.recent_ips.map(ip => `
						<tr>
							<td><code class="small text-dark">${escapeHtml(ip.ip_address)}</code></td>
							<td><span class="badge bg-secondary">${ip.token_count}</span></td>
							<td><span class="small text-muted">${formatDate(ip.last_seen)}</span></td>
						</tr>
					`).join('');
				} else {
					recentIpsTbody.innerHTML = `<tr><td colspan="3" class="text-center py-3 text-secondary">${I18N.no_ips_found}</td></tr>`;
				}
			}
		} catch (err) {
			console.error('Stats error:', err);
		}
	}

	// -------------------------------------------------------------------------
	// TAB 6: TOKEN TOOLS (GENERATE & REFRESH/ROTATE)
	// -------------------------------------------------------------------------
	const btnDoGenerate = document.getElementById('jwt-btn-do-generate');
	if (btnDoGenerate) {
		btnDoGenerate.addEventListener('click', async () => {
			const userId = val('jwt-gen-user');
			const expiry = val('jwt-gen-expiry');

			if (!userId) {
				alert(I18N.select_user);
				return;
			}

			btnDoGenerate.disabled = true;
			const origHtml = btnDoGenerate.innerHTML;
			btnDoGenerate.innerHTML = `<span class="spinner-border spinner-border-sm me-1"></span> ${I18N.generating}`;

			try {
				const res = await fetch(`${API_BASE}/generate`, {
					method: 'POST',
					headers: { 'X-WP-Nonce': NONCE, 'Content-Type': 'application/json' },
					body: JSON.stringify({ user_id: parseInt(userId, 10), expiry_seconds: parseInt(expiry, 10) })
				});
				const data = await res.json();
				if (!res.ok) throw new Error(data.message || 'Token generation failed');

				const accEl = document.getElementById('jwt-res-access');
				const refEl = document.getElementById('jwt-res-refresh');
				const curlEl = document.getElementById('jwt-res-curl');
				const resBox = document.getElementById('jwt-gen-result');

				if (accEl) accEl.value = data.access_token || '';
				if (refEl) refEl.value = data.refresh_token || '';
				if (curlEl) curlEl.textContent = `curl -X GET "${SITE_URL}/wp-json/wp/v2/users/me" \\\n  -H "Authorization: Bearer ${data.access_token}"`;
				if (resBox) resBox.style.display = 'block';

				showToast(I18N.token_gen_succ);
				loadTokens(1);
				loadStats();
			} catch (err) {
				alert('Error: ' + err.message);
			} finally {
				btnDoGenerate.disabled = false;
				btnDoGenerate.innerHTML = origHtml;
			}
		});
	}

	const btnDoRefresh = document.getElementById('jwt-btn-do-refresh');
	if (btnDoRefresh) {
		btnDoRefresh.addEventListener('click', async () => {
			const input = val('jwt-ref-input').trim();
			if (!input) {
				alert(I18N.enter_refresh);
				return;
			}

			btnDoRefresh.disabled = true;
			const origHtml = btnDoRefresh.innerHTML;
			btnDoRefresh.innerHTML = `<span class="spinner-border spinner-border-sm me-1"></span> ${I18N.refreshing}`;

			const payload = input.includes('.') ? { refresh_token: input } : { jti: input };

			try {
				const res = await fetch(`${API_BASE}/refresh`, {
					method: 'POST',
					headers: { 'X-WP-Nonce': NONCE, 'Content-Type': 'application/json' },
					body: JSON.stringify(payload)
				});
				const data = await res.json();
				if (!res.ok) throw new Error(data.message || 'Refresh failed');

				const accEl = document.getElementById('jwt-ref-res-access');
				const refEl = document.getElementById('jwt-ref-res-refresh');
				const resBox = document.getElementById('jwt-refresh-result');

				if (accEl) accEl.value = data.access_token || '';
				if (refEl) refEl.value = data.refresh_token || '';
				if (resBox) resBox.style.display = 'block';

				showToast(I18N.token_refreshed);
				loadTokens(1);
				loadStats();
			} catch (err) {
				alert('Error: ' + err.message);
			} finally {
				btnDoRefresh.disabled = false;
				btnDoRefresh.innerHTML = origHtml;
			}
		});
	}

	// Copy buttons helper
	document.querySelectorAll('.jwt-copy-btn').forEach(btn => {
		btn.addEventListener('click', () => {
			const targetId = btn.getAttribute('data-target');
			const input = document.getElementById(targetId);
			if (input && input.value) copyToClipboard(input.value, I18N.copied);
		});
	});

	// -------------------------------------------------------------------------
	// TAB 7: LIVE API EXPLORER
	// -------------------------------------------------------------------------
	const btnRunTest = document.getElementById('jwt-btn-run-test');
	if (btnRunTest) {
		btnRunTest.addEventListener('click', async () => {
			const user = val('jwt-test-user').trim();
			const pass = val('jwt-test-pass');
			const output = document.getElementById('jwt-test-output');
			const statusBadge = document.getElementById('jwt-test-status');

			if (!user || !pass) {
				alert(I18N.need_credentials);
				return;
			}

			if (statusBadge) {
				statusBadge.className = 'badge bg-secondary';
				statusBadge.textContent = I18N.sending;
			}
			if (output) {
				output.textContent = I18N.connecting + ' ' + API_TOKEN + '…';
			}

			try {
				const res = await fetch(API_TOKEN, {
					method: 'POST',
					headers: { 'Content-Type': 'application/json' },
					body: JSON.stringify({ username: user, password: pass })
				});
				const status = res.status;
				const data = await res.json();

				if (statusBadge) {
					if (res.ok) {
						statusBadge.className = 'badge bg-success';
						statusBadge.textContent = status + ' OK';
					} else {
						statusBadge.className = 'badge bg-danger';
						statusBadge.textContent = status + ' ' + (res.statusText || 'Error');
					}
				}
				if (output) {
					output.textContent = JSON.stringify(data, null, 2);
				}
			} catch (err) {
				if (statusBadge) {
					statusBadge.className = 'badge bg-danger';
					statusBadge.textContent = I18N.network_error;
				}
				if (output) {
					output.textContent = I18N.request_failed + ' ' + err.message;
				}
			}
		});
	}

	// -------------------------------------------------------------------------
	// URL HASH SUPPORT ON PAGE LOAD
	// -------------------------------------------------------------------------
	if (window.location.hash) {
		const hash = window.location.hash;
		const targetBtn = document.querySelector(`button[data-bs-target="${hash}"]`);
		if (targetBtn) {
			switchToTab(targetBtn.id);
		}
	}

	// -------------------------------------------------------------------------
	// INITIAL DATA LOAD
	// -------------------------------------------------------------------------
	loadTokens(1);
	loadConfig();
	loadStats();
})();
</script>
