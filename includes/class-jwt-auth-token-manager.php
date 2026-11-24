<?php
/**
 * JWT Token Manager — refresh, revocation, and listing.
 *
 * MIT License
 *
 * Copyright (c) 2024 x1t9
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 *
 * @package JWT_Authenticator
 * @since   2.0.0
 */

use JwtAuthenticator\Firebase\JWT\JWT;
use JwtAuthenticator\Firebase\JWT\Key;

/**
 * Class Jwt_Auth_Token_Manager
 *
 * Handles token refresh, revocation, listing, and cron cleanup.
 *
 * @since 2.0.0
 */
class Jwt_Auth_Token_Manager {

	/**
	 * Singleton instance.
	 *
	 * @var Jwt_Auth_Token_Manager|null
	 */
	private static ?Jwt_Auth_Token_Manager $instance = null;

	/**
	 * REST API namespace.
	 *
	 * @var string
	 */
	private string $namespace = 'jwt-auth/v1';

	/**
	 * Number of tokens per page.
	 *
	 * @var int
	 */
	private int $per_page = 20;

	/**
	 * Private constructor — use get_instance().
	 */
	private function __construct() {}

	/**
	 * Returns the singleton instance.
	 *
	 * @return self
	 */
	public static function get_instance(): self {
		if ( null === self::$instance ) {
			self::$instance = new self();
		}
		return self::$instance;
	}

	/**
	 * Register REST API routes.
	 * Hook this onto rest_api_init.
	 */
	public function add_api_routes(): void {
		register_rest_route(
			$this->namespace,
			'token/refresh',
			[
				'methods'             => 'POST',
				'callback'            => [ $this, 'handle_refresh' ],
				'permission_callback' => [ $this, 'token_permission_callback' ],
			]
		);

		register_rest_route(
			$this->namespace,
			'token/revoke',
			[
				'methods'             => 'POST',
				'callback'            => [ $this, 'handle_revoke' ],
				'permission_callback' => [ $this, 'token_permission_callback' ],
			]
		);

		register_rest_route(
			$this->namespace,
			'tokens',
			[
				'methods'             => 'GET',
				'callback'            => [ $this, 'handle_list_tokens' ],
				'permission_callback' => 'is_user_logged_in',
			]
		);

		register_rest_route(
			$this->namespace,
			'tokens/(?P<jti>[a-zA-Z0-9_\-]+)',
			[
				'methods'             => 'DELETE',
				'callback'            => [ $this, 'handle_delete_token' ],
				'permission_callback' => 'is_user_logged_in',
				'args'                => [
					'jti' => [
						'required'          => true,
						'sanitize_callback' => 'sanitize_text_field',
					],
				],
			]
		);

		// ---------------------------------------------------------------------
		// Admin Token Dashboard Routes
		// ---------------------------------------------------------------------

		// Admin: List all tokens across all users (with filters & stats)
		register_rest_route(
			$this->namespace,
			'admin/tokens',
			[
				'methods'             => 'GET',
				'callback'            => [ $this, 'handle_admin_list_tokens' ],
				'permission_callback' => [ $this, 'admin_permission_check' ],
			]
		);

		// Admin: Delete or revoke any token by JTI
		register_rest_route(
			$this->namespace,
			'admin/tokens/(?P<jti>[a-zA-Z0-9_\-]+)',
			[
				'methods'             => 'DELETE',
				'callback'            => [ $this, 'handle_admin_delete_token' ],
				'permission_callback' => [ $this, 'admin_permission_check' ],
				'args'                => [
					'jti'  => [
						'required'          => true,
						'sanitize_callback' => 'sanitize_text_field',
					],
					'hard' => [
						'required' => false,
						'default'  => false,
					],
				],
			]
		);

		// Admin: Generate token pair for a specific user
		register_rest_route(
			$this->namespace,
			'admin/tokens/generate',
			[
				'methods'             => 'POST',
				'callback'            => [ $this, 'handle_admin_generate_token' ],
				'permission_callback' => [ $this, 'admin_permission_check' ],
			]
		);

		// Admin: Refresh a token
		register_rest_route(
			$this->namespace,
			'admin/tokens/refresh',
			[
				'methods'             => 'POST',
				'callback'            => [ $this, 'handle_admin_refresh_token' ],
				'permission_callback' => [ $this, 'admin_permission_check' ],
			]
		);

		// Admin: Purge all expired tokens
		register_rest_route(
			$this->namespace,
			'admin/tokens/purge-expired',
			[
				'methods'             => 'POST',
				'callback'            => [ $this, 'handle_admin_purge_expired' ],
				'permission_callback' => [ $this, 'admin_permission_check' ],
			]
		);

		// Admin: Revoke all tokens for a user
		register_rest_route(
			$this->namespace,
			'admin/tokens/revoke-user',
			[
				'methods'             => 'POST',
				'callback'            => [ $this, 'handle_admin_revoke_user' ],
				'permission_callback' => [ $this, 'admin_permission_check' ],
			]
		);

		// Admin: Detailed Token Usage Statistics
		register_rest_route(
			$this->namespace,
			'admin/tokens/stats',
			[
				'methods'             => 'GET',
				'callback'            => [ $this, 'handle_admin_token_stats' ],
				'permission_callback' => [ $this, 'admin_permission_check' ],
			]
		);

		// Admin: wp-config.php JWT Configuration Detection & Details
		register_rest_route(
			$this->namespace,
			'admin/tokens/config-detect',
			[
				'methods'             => 'GET',
				'callback'            => [ $this, 'handle_admin_config_detect' ],
				'permission_callback' => [ $this, 'admin_permission_check' ],
			]
		);
	}

	/**
	 * Hook into determine_current_user (priority 15) to reject revoked tokens.
	 *
	 * Runs AFTER Jwt_Auth_Public (default priority 10).
	 *
	 * @param int|bool $user_id Current resolved user ID.
	 * @return int|bool
	 */
	public function check_revoked_on_determine( $user_id ) {
		if ( ! $user_id ) {
			return $user_id;
		}

		// Only run on REST requests.
		$rest_api_slug = rest_get_url_prefix();
		$requested_url = isset( $_SERVER['REQUEST_URI'] )
			? sanitize_url( wp_unslash( $_SERVER['REQUEST_URI'] ) )
			: '';
		$is_rest       = ( defined( 'REST_REQUEST' ) && REST_REQUEST ) || ( false !== strpos( $requested_url, $rest_api_slug ) );
		if ( ! $is_rest ) {
			return $user_id;
		}

		// Grab the Bearer token from the request.
		$auth_header = ! empty( $_SERVER['HTTP_AUTHORIZATION'] )
			? sanitize_text_field( wp_unslash( $_SERVER['HTTP_AUTHORIZATION'] ) )
			: '';
		if ( ! $auth_header ) {
			$auth_header = ! empty( $_SERVER['REDIRECT_HTTP_AUTHORIZATION'] )
				? sanitize_text_field( wp_unslash( $_SERVER['REDIRECT_HTTP_AUTHORIZATION'] ) )
				: '';
		}

		if ( ! $auth_header || strpos( $auth_header, 'Bearer ' ) !== 0 ) {
			return $user_id;
		}

		[ $raw_token ] = sscanf( $auth_header, 'Bearer %s' );
		if ( ! $raw_token ) {
			return $user_id;
		}

		$secret_key = defined( 'JWT_AUTH_SECRET_KEY' ) ? JWT_AUTH_SECRET_KEY : false;
		if ( ! $secret_key ) {
			return $user_id;
		}

		try {
			$algorithm = apply_filters( 'jwt_auth_algorithm', 'HS256' );
			$decoded   = JWT::decode( $raw_token, new Key( $secret_key, $algorithm ) );
			if ( isset( $decoded->jti ) && $this->is_revoked( $decoded->jti ) ) {
				// Token revoked — deny authentication.
				return false;
			}
		} catch ( \Exception $e ) {
			// Already caught/handled by Jwt_Auth_Public; don't double-report.
		}

		return $user_id;
	}

	// -------------------------------------------------------------------------
	// REST endpoint handlers
	// -------------------------------------------------------------------------

	/**
	 * Handle POST /jwt-auth/v1/token/refresh
	 *
	 * @param WP_REST_Request $request Incoming request.
	 * @return WP_REST_Response|WP_Error
	 */
	public function handle_refresh( WP_REST_Request $request ) {
		$refresh_token_string = sanitize_text_field( (string) $request->get_param( 'refresh_token' ) );
		if ( ! $refresh_token_string ) {
			return new WP_Error( 'jwt_auth_missing_refresh_token', 'refresh_token parameter is required.', [ 'status' => 400 ] );
		}

		$secret_key = defined( 'JWT_AUTH_SECRET_KEY' ) ? JWT_AUTH_SECRET_KEY : false;
		if ( ! $secret_key ) {
			return new WP_Error( 'jwt_auth_bad_config', 'JWT is not configured properly.', [ 'status' => 403 ] );
		}

		try {
			$algorithm = apply_filters( 'jwt_auth_algorithm', 'HS256' );
			$decoded   = JWT::decode( $refresh_token_string, new Key( $secret_key, $algorithm ) );
		} catch ( \Exception $e ) {
			return new WP_Error( 'jwt_auth_invalid_refresh_token', $e->getMessage(), [ 'status' => 401 ] );
		}

		// Must be a refresh token.
		if ( ! isset( $decoded->type ) || 'refresh' !== $decoded->type ) {
			return new WP_Error( 'jwt_auth_invalid_refresh_token', 'Provided token is not a refresh token.', [ 'status' => 401 ] );
		}

		if ( ! isset( $decoded->jti ) || $this->is_revoked( $decoded->jti ) ) {
			return new WP_Error( 'jwt_auth_revoked_token', 'Refresh token has been revoked.', [ 'status' => 401 ] );
		}

		if ( ! isset( $decoded->data->user->id ) ) {
			return new WP_Error( 'jwt_auth_bad_refresh_token', 'User ID not found in refresh token.', [ 'status' => 401 ] );
		}

		$user = get_user_by( 'id', (int) $decoded->data->user->id );
		if ( ! $user ) {
			return new WP_Error( 'jwt_auth_user_not_found', 'User not found.', [ 'status' => 403 ] );
		}

		// Rotate: revoke the old refresh token.
		$this->revoke_token( $decoded->jti, $user->ID );

		// Issue a new token pair.
		$pair = $this->generate_token_pair( $user, $secret_key, $algorithm );

		return rest_ensure_response( $pair );
	}

	/**
	 * Handle POST /jwt-auth/v1/token/revoke
	 *
	 * @param WP_REST_Request $request Incoming request.
	 * @return WP_REST_Response|WP_Error
	 */
	public function handle_revoke( WP_REST_Request $request ) {
		$secret_key = defined( 'JWT_AUTH_SECRET_KEY' ) ? JWT_AUTH_SECRET_KEY : false;
		if ( ! $secret_key ) {
			return new WP_Error( 'jwt_auth_bad_config', 'JWT is not configured properly.', [ 'status' => 403 ] );
		}

		// Prefer body param; fall back to Authorization header.
		$raw_token = sanitize_text_field( (string) $request->get_param( 'token' ) );
		if ( ! $raw_token ) {
			$auth_header = $request->get_header( 'Authorization' );
			if ( $auth_header && strpos( $auth_header, 'Bearer ' ) === 0 ) {
				[ $raw_token ] = sscanf( $auth_header, 'Bearer %s' );
			}
		}

		if ( ! $raw_token ) {
			return new WP_Error( 'jwt_auth_missing_token', 'No token provided to revoke.', [ 'status' => 400 ] );
		}

		try {
			$algorithm = apply_filters( 'jwt_auth_algorithm', 'HS256' );
			$decoded   = JWT::decode( $raw_token, new Key( $secret_key, $algorithm ) );
		} catch ( \Exception $e ) {
			return new WP_Error( 'jwt_auth_invalid_token', $e->getMessage(), [ 'status' => 401 ] );
		}

		if ( ! isset( $decoded->jti ) ) {
			return new WP_Error( 'jwt_auth_missing_jti', 'Token does not contain a jti claim.', [ 'status' => 400 ] );
		}

		$user_id = get_current_user_id();
		$this->revoke_token( $decoded->jti, $user_id );

		return rest_ensure_response( [ 'code' => 'jwt_auth_token_revoked', 'message' => 'Token revoked successfully.' ] );
	}

	/**
	 * Handle GET /jwt-auth/v1/tokens
	 *
	 * @param WP_REST_Request $request Incoming request.
	 * @return WP_REST_Response
	 */
	public function handle_list_tokens( WP_REST_Request $request ): WP_REST_Response {
		$user_id = get_current_user_id();
		$page    = max( 1, (int) $request->get_param( 'page' ) );
		$tokens  = $this->get_user_tokens( $user_id, $page );
		return rest_ensure_response( $tokens );
	}

	/**
	 * Handle DELETE /jwt-auth/v1/tokens/{jti}
	 *
	 * @param WP_REST_Request $request Incoming request.
	 * @return WP_REST_Response|WP_Error
	 */
	public function handle_delete_token( WP_REST_Request $request ) {
		$jti     = sanitize_text_field( (string) $request->get_param( 'jti' ) );
		$user_id = get_current_user_id();

		global $wpdb;
		$table = $wpdb->prefix . 'jwt_tokens';

		// Verify the token belongs to the current user.
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery
		$exists = $wpdb->get_var(
			$wpdb->prepare(
				"SELECT id FROM {$table} WHERE jti = %s AND user_id = %d LIMIT 1",
				$jti,
				$user_id
			)
		);

		if ( ! $exists ) {
			return new WP_Error( 'jwt_auth_token_not_found', 'Token not found or does not belong to you.', [ 'status' => 404 ] );
		}

		$this->revoke_token( $jti, $user_id );

		return rest_ensure_response( [ 'code' => 'jwt_auth_token_revoked', 'message' => 'Token revoked successfully.' ] );
	}

	// -------------------------------------------------------------------------
	// Permission callbacks
	// -------------------------------------------------------------------------

	/**
	 * Permission callback: allow authenticated users OR requests carrying a valid refresh_token body param.
	 *
	 * @param WP_REST_Request $request Incoming request.
	 * @return bool
	 */
	public function token_permission_callback( WP_REST_Request $request ): bool {
		if ( is_user_logged_in() ) {
			return true;
		}

		// Allow refresh and revoke if the caller provides a parseable token.
		$secret_key = defined( 'JWT_AUTH_SECRET_KEY' ) ? JWT_AUTH_SECRET_KEY : false;
		if ( ! $secret_key ) {
			return false;
		}

		$raw = sanitize_text_field( (string) $request->get_param( 'refresh_token' ) )
			?: sanitize_text_field( (string) $request->get_param( 'token' ) );

		if ( ! $raw ) {
			$auth_header = $request->get_header( 'Authorization' );
			if ( $auth_header && strpos( $auth_header, 'Bearer ' ) === 0 ) {
				[ $raw ] = sscanf( $auth_header, 'Bearer %s' );
			}
		}

		if ( ! $raw ) {
			return false;
		}

		try {
			$algorithm = apply_filters( 'jwt_auth_algorithm', 'HS256' );
			JWT::decode( $raw, new Key( $secret_key, $algorithm ) );
			return true;
		} catch ( \Exception $e ) {
			return false;
		}
	}

	// -------------------------------------------------------------------------
	// Core DB / token methods
	// -------------------------------------------------------------------------

	/**
	 * Store a token record in the jwt_tokens table.
	 *
	 * @param int    $user_id      WordPress user ID.
	 * @param string $token_string Raw JWT string (will be hashed).
	 * @param string $type         'access' or 'refresh'.
	 * @param int    $expires_at   Unix timestamp for expiration.
	 * @param string $jti          JWT ID claim.
	 * @return bool True on success.
	 */
	public function store_token( int $user_id, string $token_string, string $type, int $expires_at, string $jti ): bool {
		global $wpdb;
		$table = $wpdb->prefix . 'jwt_tokens';

		$token_hash = hash( 'sha256', $token_string );
		$ip_address = isset( $_SERVER['REMOTE_ADDR'] )
			? sanitize_text_field( wp_unslash( $_SERVER['REMOTE_ADDR'] ) )
			: '';
		$user_agent = isset( $_SERVER['HTTP_USER_AGENT'] )
			? sanitize_text_field( wp_unslash( $_SERVER['HTTP_USER_AGENT'] ) )
			: '';

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery
		$result = $wpdb->insert(
			$table,
			[
				'user_id'    => $user_id,
				'token_hash' => $token_hash,
				'token_type' => $type,
				'jti'        => $jti,
				'issued_at'  => gmdate( 'Y-m-d H:i:s' ),
				'expires_at' => gmdate( 'Y-m-d H:i:s', $expires_at ),
				'revoked'    => 0,
				'ip_address' => $ip_address,
				'user_agent' => $user_agent,
			],
			[ '%d', '%s', '%s', '%s', '%s', '%s', '%d', '%s', '%s' ]
		);

		return false !== $result;
	}

	/**
	 * Check whether a token (by JTI) has been revoked.
	 *
	 * @param string $jti JWT ID.
	 * @return bool True if revoked.
	 */
	public function is_revoked( string $jti ): bool {
		global $wpdb;
		$table = $wpdb->prefix . 'jwt_tokens';

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery
		$revoked = $wpdb->get_var(
			$wpdb->prepare(
				"SELECT revoked FROM {$table} WHERE jti = %s LIMIT 1",
				$jti
			)
		);

		// If not found in DB we treat as not revoked (pre-2.0 tokens).
		if ( null === $revoked ) {
			return false;
		}

		return (bool) $revoked;
	}

	/**
	 * Mark a token as revoked.
	 *
	 * @param string $jti     JWT ID.
	 * @param int    $user_id Optional user ID for extra safety check.
	 * @return bool True on success.
	 */
	public function revoke_token( string $jti, int $user_id = 0 ): bool {
		global $wpdb;
		$table = $wpdb->prefix . 'jwt_tokens';

		$where        = [ 'jti' => $jti ];
		$where_format = [ '%s' ];

		if ( $user_id > 0 ) {
			$where['user_id']  = $user_id;
			$where_format[]    = '%d';
		}

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery
		$result = $wpdb->update(
			$table,
			[
				'revoked'    => 1,
				'revoked_at' => gmdate( 'Y-m-d H:i:s' ),
			],
			$where,
			[ '%d', '%s' ],
			$where_format
		);

		return false !== $result;
	}

	/**
	 * Revoke all tokens for a given user.
	 *
	 * @param int $user_id WordPress user ID.
	 * @return bool True on success.
	 */
	public function revoke_all_user_tokens( int $user_id ): bool {
		global $wpdb;
		$table = $wpdb->prefix . 'jwt_tokens';

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery
		$result = $wpdb->update(
			$table,
			[
				'revoked'    => 1,
				'revoked_at' => gmdate( 'Y-m-d H:i:s' ),
			],
			[ 'user_id' => $user_id, 'revoked' => 0 ],
			[ '%d', '%s' ],
			[ '%d', '%d' ]
		);

		return false !== $result;
	}

	/**
	 * Generate an access + refresh token pair for a user and store both.
	 *
	 * @param WP_User $user       The WordPress user.
	 * @param string  $secret_key JWT secret key.
	 * @param string  $algorithm  JWT algorithm (e.g. 'HS256').
	 * @return array{access_token: string, refresh_token: string, expires_in: int, token_type: string}
	 */
	public function generate_token_pair( WP_User $user, string $secret_key, string $algorithm ): array {
		$issued_at = time();

		$access_expiry_seconds  = (int) get_option( 'jwt_auth_access_token_expiry', 3600 );
		$refresh_expiry_seconds = (int) get_option( 'jwt_auth_refresh_token_expiry', 2592000 );

		$access_expires_at  = $issued_at + $access_expiry_seconds;
		$refresh_expires_at = $issued_at + $refresh_expiry_seconds;

		$access_jti  = Jwt_Auth_Helpers::generate_jti();
		$refresh_jti = Jwt_Auth_Helpers::generate_jti();

		$not_before = apply_filters( 'jwt_auth_not_before', $issued_at, $issued_at );
		$access_exp = apply_filters( 'jwt_auth_expire', $access_expires_at, $issued_at );

		$access_payload = apply_filters(
			'jwt_auth_token_before_sign',
			[
				'iss'  => get_bloginfo( 'url' ),
				'iat'  => $issued_at,
				'nbf'  => $not_before,
				'exp'  => $access_exp,
				'jti'  => $access_jti,
				'type' => 'access',
				'data' => [
					'user' => [
						'id' => $user->ID,
					],
				],
			],
			$user
		);

		$refresh_payload = [
			'iss'  => get_bloginfo( 'url' ),
			'iat'  => $issued_at,
			'nbf'  => $not_before,
			'exp'  => $refresh_expires_at,
			'jti'  => $refresh_jti,
			'type' => 'refresh',
			'data' => [
				'user' => [
					'id' => $user->ID,
				],
			],
		];

		$access_token_string  = JWT::encode( $access_payload, $secret_key, $algorithm );
		$refresh_token_string = JWT::encode( $refresh_payload, $secret_key, $algorithm );

		$this->store_token( $user->ID, $access_token_string, 'access', $access_exp, $access_jti );
		$this->store_token( $user->ID, $refresh_token_string, 'refresh', $refresh_expires_at, $refresh_jti );

		return [
			'access_token'  => $access_token_string,
			'refresh_token' => $refresh_token_string,
			'expires_in'    => $access_expiry_seconds,
			'token_type'    => 'Bearer',
		];
	}

	/**
	 * Delete expired tokens from the DB (called by wp_cron weekly).
	 */
	public function cleanup_expired_tokens(): void {
		global $wpdb;
		$table = $wpdb->prefix . 'jwt_tokens';

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery
		$wpdb->query(
			$wpdb->prepare(
				"DELETE FROM {$table} WHERE expires_at < %s",
				gmdate( 'Y-m-d H:i:s' )
			)
		);
	}

	/**
	 * Get a paginated list of tokens for a user.
	 *
	 * @param int $user_id WordPress user ID.
	 * @param int $page    Page number (1-based).
	 * @return array{tokens: array, total: int, page: int, per_page: int}
	 */
	public function get_user_tokens( int $user_id, int $page = 1 ): array {
		global $wpdb;
		$table  = $wpdb->prefix . 'jwt_tokens';
		$offset = ( $page - 1 ) * $this->per_page;

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery
		$tokens = $wpdb->get_results(
			$wpdb->prepare(
				"SELECT id, token_type, jti, issued_at, expires_at, revoked, revoked_at, ip_address
				 FROM {$table}
				 WHERE user_id = %d
				 ORDER BY issued_at DESC
				 LIMIT %d OFFSET %d",
				$user_id,
				$this->per_page,
				$offset
			),
			ARRAY_A
		);

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery
		$total = (int) $wpdb->get_var(
			$wpdb->prepare(
				"SELECT COUNT(*) FROM {$table} WHERE user_id = %d",
				$user_id
			)
		);

		return [
			'tokens'   => $tokens ?: [],
			'total'    => $total,
			'page'     => $page,
			'per_page' => $this->per_page,
		];
	}

	// -------------------------------------------------------------------------
	// Admin Token Dashboard Handlers
	// -------------------------------------------------------------------------

	/**
	 * Permission callback for admin token management.
	 *
	 * @return bool
	 */
	public function admin_permission_check(): bool {
		return current_user_can( 'manage_options' );
	}

	/**
	 * Handle GET /jwt-auth/v1/admin/tokens
	 *
	 * Returns all tokens with user info, status, filters, and summary statistics.
	 *
	 * @param WP_REST_Request $request Incoming request.
	 * @return WP_REST_Response
	 */
	public function handle_admin_list_tokens( WP_REST_Request $request ): WP_REST_Response {
		global $wpdb;
		$table = $wpdb->prefix . 'jwt_tokens';

		$page     = max( 1, (int) $request->get_param( 'page' ) );
		$per_page = min( 100, max( 5, (int) ( $request->get_param( 'per_page' ) ?: 20 ) ) );
		$offset   = ( $page - 1 ) * $per_page;
		$status   = sanitize_text_field( (string) $request->get_param( 'status' ) );
		$type     = sanitize_text_field( (string) $request->get_param( 'type' ) );
		$search   = sanitize_text_field( (string) $request->get_param( 'search' ) );

		$now    = gmdate( 'Y-m-d H:i:s' );
		$where  = [ '1=1' ];
		$params = [];

		if ( 'active' === $status ) {
			$where[]  = 't.revoked = 0 AND t.expires_at > %s';
			$params[] = $now;
		} elseif ( 'expired' === $status ) {
			$where[]  = 't.expires_at <= %s';
			$params[] = $now;
		} elseif ( 'revoked' === $status ) {
			$where[] = 't.revoked = 1';
		}

		if ( in_array( $type, [ 'access', 'refresh' ], true ) ) {
			$where[]  = 't.token_type = %s';
			$params[] = $type;
		}

		if ( ! empty( $search ) ) {
			$like     = '%' . $wpdb->esc_like( $search ) . '%';
			$where[]  = '(t.jti LIKE %s OR u.user_login LIKE %s OR u.user_email LIKE %s OR u.display_name LIKE %s)';
			$params[] = $like;
			$params[] = $like;
			$params[] = $like;
			$params[] = $like;
		}

		$where_sql = implode( ' AND ', $where );

		// Summary statistics
		$total_tokens   = (int) $wpdb->get_var( "SELECT COUNT(*) FROM {$table}" );
		$active_tokens  = (int) $wpdb->get_var( $wpdb->prepare( "SELECT COUNT(*) FROM {$table} WHERE revoked = 0 AND expires_at > %s", $now ) );
		$revoked_tokens = (int) $wpdb->get_var( "SELECT COUNT(*) FROM {$table} WHERE revoked = 1" );
		$expired_tokens = (int) $wpdb->get_var( $wpdb->prepare( "SELECT COUNT(*) FROM {$table} WHERE expires_at <= %s", $now ) );

		// Filtered total count
		$count_sql = "SELECT COUNT(*) FROM {$table} t LEFT JOIN {$wpdb->users} u ON t.user_id = u.ID WHERE {$where_sql}";
		if ( ! empty( $params ) ) {
			$count_sql = $wpdb->prepare( $count_sql, $params );
		}
		$filtered_total = (int) $wpdb->get_var( $count_sql );

		// Query rows with user details
		$query_sql = "SELECT t.id, t.user_id, t.token_type, t.jti, t.issued_at, t.expires_at, t.revoked, t.revoked_at, t.ip_address,
		                     u.user_login, u.user_email, u.display_name
		              FROM {$table} t
		              LEFT JOIN {$wpdb->users} u ON t.user_id = u.ID
		              WHERE {$where_sql}
		              ORDER BY t.issued_at DESC
		              LIMIT %d OFFSET %d";
		$query_params = array_merge( $params, [ $per_page, $offset ] );
		$rows = $wpdb->get_results( $wpdb->prepare( $query_sql, $query_params ), ARRAY_A );

		$tokens = [];
		foreach ( (array) $rows as $row ) {
			$is_expired  = strtotime( $row['expires_at'] ) <= time();
			$is_revoked  = (bool) $row['revoked'];
			$item_status = $is_revoked ? 'revoked' : ( $is_expired ? 'expired' : 'active' );

			$tokens[] = [
				'id'           => (int) $row['id'],
				'user_id'      => (int) $row['user_id'],
				'username'     => $row['user_login'] ?: 'User #' . $row['user_id'],
				'user_email'   => $row['user_email'] ?: '',
				'display_name' => $row['display_name'] ?: 'User #' . $row['user_id'],
				'avatar_url'   => get_avatar_url( $row['user_id'], [ 'size' => 48 ] ),
				'token_type'   => $row['token_type'],
				'jti'          => $row['jti'],
				'issued_at'    => $row['issued_at'],
				'expires_at'   => $row['expires_at'],
				'revoked'      => $is_revoked,
				'revoked_at'   => $row['revoked_at'],
				'status'       => $item_status,
				'ip_address'   => $row['ip_address'] ?: '—',
			];
		}

		return rest_ensure_response( [
			'tokens'     => $tokens,
			'pagination' => [
				'total'       => $filtered_total,
				'page'        => $page,
				'per_page'    => $per_page,
				'total_pages' => max( 1, (int) ceil( $filtered_total / $per_page ) ),
			],
			'stats'      => [
				'total'   => $total_tokens,
				'active'  => $active_tokens,
				'revoked' => $revoked_tokens,
				'expired' => $expired_tokens,
			],
		] );
	}

	/**
	 * Handle DELETE /jwt-auth/v1/admin/tokens/{jti}
	 *
	 * Admins can revoke or permanently delete any token by JTI.
	 *
	 * @param WP_REST_Request $request Incoming request.
	 * @return WP_REST_Response|WP_Error
	 */
	public function handle_admin_delete_token( WP_REST_Request $request ) {
		global $wpdb;
		$table = $wpdb->prefix . 'jwt_tokens';
		$jti   = sanitize_text_field( (string) $request->get_param( 'jti' ) );
		$hard  = (bool) $request->get_param( 'hard' );

		if ( $hard ) {
			$deleted = $wpdb->delete( $table, [ 'jti' => $jti ], [ '%s' ] );
			if ( false === $deleted ) {
				return new WP_Error( 'jwt_auth_delete_failed', 'Failed to delete token.', [ 'status' => 500 ] );
			}
			return rest_ensure_response( [
				'success' => true,
				'message' => 'Token permanently deleted.',
			] );
		}

		// Soft delete / revoke
		$wpdb->update(
			$table,
			[
				'revoked'    => 1,
				'revoked_at' => gmdate( 'Y-m-d H:i:s' ),
			],
			[ 'jti' => $jti ],
			[ '%d', '%s' ],
			[ '%s' ]
		);

		return rest_ensure_response( [
			'success' => true,
			'message' => 'Token revoked successfully.',
		] );
	}

	/**
	 * Handle POST /jwt-auth/v1/admin/tokens/generate
	 *
	 * Admin tool: Generate token pair for any user directly from dashboard.
	 *
	 * @param WP_REST_Request $request Incoming request.
	 * @return WP_REST_Response|WP_Error
	 */
	public function handle_admin_generate_token( WP_REST_Request $request ) {
		$user_id = (int) $request->get_param( 'user_id' );
		if ( ! $user_id ) {
			return new WP_Error( 'jwt_auth_missing_user', 'User ID is required.', [ 'status' => 400 ] );
		}

		$user = get_user_by( 'id', $user_id );
		if ( ! $user ) {
			return new WP_Error( 'jwt_auth_user_not_found', 'User not found.', [ 'status' => 404 ] );
		}

		$secret_key = defined( 'JWT_AUTH_SECRET_KEY' ) ? JWT_AUTH_SECRET_KEY : false;
		if ( ! $secret_key ) {
			return new WP_Error( 'jwt_auth_bad_config', 'JWT Secret Key is not configured in wp-config.php.', [ 'status' => 403 ] );
		}

		$algorithm = apply_filters( 'jwt_auth_algorithm', 'HS256' );
		$pair      = $this->generate_token_pair( $user, $secret_key, $algorithm );

		return rest_ensure_response( array_merge( $pair, [
			'user_id'      => $user->ID,
			'username'     => $user->user_login,
			'display_name' => $user->display_name,
			'user_email'   => $user->user_email,
		] ) );
	}

	/**
	 * Handle POST /jwt-auth/v1/admin/tokens/refresh
	 *
	 * Admin tool: Refresh/rotate a token by either refresh_token or JTI.
	 *
	 * @param WP_REST_Request $request Incoming request.
	 * @return WP_REST_Response|WP_Error
	 */
	public function handle_admin_refresh_token( WP_REST_Request $request ) {
		$jti           = sanitize_text_field( (string) $request->get_param( 'jti' ) );
		$refresh_token = sanitize_text_field( (string) $request->get_param( 'refresh_token' ) );

		if ( empty( $refresh_token ) && ! empty( $jti ) ) {
			global $wpdb;
			$table = $wpdb->prefix . 'jwt_tokens';
			$row   = $wpdb->get_row( $wpdb->prepare( "SELECT * FROM {$table} WHERE jti = %s LIMIT 1", $jti ), ARRAY_A );

			if ( ! $row ) {
				return new WP_Error( 'jwt_auth_not_found', 'Token not found.', [ 'status' => 404 ] );
			}

			$user = get_user_by( 'id', (int) $row['user_id'] );
			if ( ! $user ) {
				return new WP_Error( 'jwt_auth_user_not_found', 'Associated user not found.', [ 'status' => 404 ] );
			}

			$secret_key = defined( 'JWT_AUTH_SECRET_KEY' ) ? JWT_AUTH_SECRET_KEY : false;
			if ( ! $secret_key ) {
				return new WP_Error( 'jwt_auth_bad_config', 'JWT is not configured properly.', [ 'status' => 403 ] );
			}

			// Revoke the old token
			$this->revoke_token( $jti, $user->ID );

			// Generate new token pair
			$algorithm = apply_filters( 'jwt_auth_algorithm', 'HS256' );
			$pair      = $this->generate_token_pair( $user, $secret_key, $algorithm );

			return rest_ensure_response( array_merge( $pair, [
				'message' => 'Token rotated and new token pair generated successfully.',
			] ) );
		}

		// Delegate to standard refresh
		return $this->handle_refresh( $request );
	}

	/**
	 * Handle POST /jwt-auth/v1/admin/tokens/purge-expired
	 *
	 * @param WP_REST_Request $request Incoming request.
	 * @return WP_REST_Response
	 */
	public function handle_admin_purge_expired( WP_REST_Request $request ): WP_REST_Response {
		global $wpdb;
		$table = $wpdb->prefix . 'jwt_tokens';
		$now   = gmdate( 'Y-m-d H:i:s' );

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery
		$deleted = $wpdb->query( $wpdb->prepare( "DELETE FROM {$table} WHERE expires_at < %s", $now ) );

		return rest_ensure_response( [
			'success' => true,
			'purged'  => (int) $deleted,
			'message' => sprintf( '%d expired tokens permanently purged.', (int) $deleted ),
		] );
	}

	/**
	 * Handle POST /jwt-auth/v1/admin/tokens/revoke-user
	 *
	 * @param WP_REST_Request $request Incoming request.
	 * @return WP_REST_Response|WP_Error
	 */
	public function handle_admin_revoke_user( WP_REST_Request $request ) {
		$user_id = (int) $request->get_param( 'user_id' );
		if ( ! $user_id ) {
			return new WP_Error( 'jwt_auth_missing_user', 'User ID is required.', [ 'status' => 400 ] );
		}

		$this->revoke_all_user_tokens( $user_id );

		return rest_ensure_response( [
			'success' => true,
			'message' => 'All tokens for user revoked.',
		] );
	}

	/**
	 * Handle GET /jwt-auth/v1/admin/tokens/stats
	 *
	 * Returns detailed usage statistics and breakdown.
	 *
	 * @param WP_REST_Request $request Incoming request.
	 * @return WP_REST_Response
	 */
	public function handle_admin_token_stats( WP_REST_Request $request ): WP_REST_Response {
		global $wpdb;
		$table = $wpdb->prefix . 'jwt_tokens';
		$now   = gmdate( 'Y-m-d H:i:s' );

		$total   = (int) $wpdb->get_var( "SELECT COUNT(*) FROM {$table}" );
		$active  = (int) $wpdb->get_var( $wpdb->prepare( "SELECT COUNT(*) FROM {$table} WHERE revoked = 0 AND expires_at > %s", $now ) );
		$expired = (int) $wpdb->get_var( $wpdb->prepare( "SELECT COUNT(*) FROM {$table} WHERE expires_at <= %s", $now ) );
		$revoked = (int) $wpdb->get_var( "SELECT COUNT(*) FROM {$table} WHERE revoked = 1" );

		$access_count  = (int) $wpdb->get_var( "SELECT COUNT(*) FROM {$table} WHERE token_type = 'access'" );
		$refresh_count = (int) $wpdb->get_var( "SELECT COUNT(*) FROM {$table} WHERE token_type = 'refresh'" );

		$time_24h = gmdate( 'Y-m-d H:i:s', time() - 86400 );
		$time_7d  = gmdate( 'Y-m-d H:i:s', time() - ( 7 * 86400 ) );
		$time_30d = gmdate( 'Y-m-d H:i:s', time() - ( 30 * 86400 ) );

		$created_24h = (int) $wpdb->get_var( $wpdb->prepare( "SELECT COUNT(*) FROM {$table} WHERE issued_at >= %s", $time_24h ) );
		$created_7d  = (int) $wpdb->get_var( $wpdb->prepare( "SELECT COUNT(*) FROM {$table} WHERE issued_at >= %s", $time_7d ) );
		$created_30d = (int) $wpdb->get_var( $wpdb->prepare( "SELECT COUNT(*) FROM {$table} WHERE issued_at >= %s", $time_30d ) );

		// Top users by active tokens
		$top_users_raw = $wpdb->get_results(
			$wpdb->prepare(
				"SELECT t.user_id, COUNT(*) as token_count, u.user_login, u.display_name, u.user_email
				 FROM {$table} t
				 LEFT JOIN {$wpdb->users} u ON t.user_id = u.ID
				 WHERE t.revoked = 0 AND t.expires_at > %s
				 GROUP BY t.user_id
				 ORDER BY token_count DESC
				 LIMIT 10",
				$now
			),
			ARRAY_A
		);

		$top_users = [];
		foreach ( (array) $top_users_raw as $u ) {
			$top_users[] = [
				'user_id'      => (int) $u['user_id'],
				'username'     => $u['user_login'] ?: 'User #' . $u['user_id'],
				'display_name' => $u['display_name'] ?: 'User #' . $u['user_id'],
				'user_email'   => $u['user_email'] ?: '',
				'token_count'  => (int) $u['token_count'],
				'avatar_url'   => get_avatar_url( $u['user_id'], [ 'size' => 40 ] ),
			];
		}

		// Recent IP addresses
		$recent_ips_raw = $wpdb->get_results(
			"SELECT ip_address, COUNT(*) as token_count, MAX(issued_at) as last_seen
			 FROM {$table}
			 WHERE ip_address IS NOT NULL AND ip_address != ''
			 GROUP BY ip_address
			 ORDER BY last_seen DESC
			 LIMIT 8",
			ARRAY_A
		);

		$recent_ips = [];
		foreach ( (array) $recent_ips_raw as $ip ) {
			$recent_ips[] = [
				'ip_address'  => $ip['ip_address'],
				'token_count' => (int) $ip['token_count'],
				'last_seen'   => $ip['last_seen'],
			];
		}

		return rest_ensure_response( [
			'total'         => $total,
			'active'        => $active,
			'expired'       => $expired,
			'revoked'       => $revoked,
			'access_count'  => $access_count,
			'refresh_count' => $refresh_count,
			'created_24h'   => $created_24h,
			'created_7d'    => $created_7d,
			'created_30d'   => $created_30d,
			'top_users'     => $top_users,
			'recent_ips'    => $recent_ips,
		] );
	}

	/**
	 * Handle GET /jwt-auth/v1/admin/tokens/config-detect
	 *
	 * Detects wp-config.php configuration, secret key details, and runtime status.
	 *
	 * @param WP_REST_Request $request Incoming request.
	 * @return WP_REST_Response
	 */
	public function handle_admin_config_detect( WP_REST_Request $request ): WP_REST_Response {
		$secret_key   = defined( 'JWT_AUTH_SECRET_KEY' ) ? JWT_AUTH_SECRET_KEY : false;
		$cors_enabled = defined( 'JWT_AUTH_CORS_ENABLE' ) ? JWT_AUTH_CORS_ENABLE : false;
		$dev_mode     = defined( 'JWT_AUTH_DEV_MODE' ) ? JWT_AUTH_DEV_MODE : false;

		// Check multiple possible wp-config.php paths (handles root, subfolder, Bedrock, and standard setups)
		$wp_config_path   = '';
		$wp_config_found  = false;
		$in_file_detected = false;
		$misplaced        = false;
		$file_secret_key  = '';

		$possible_paths = array_filter( [
			defined( 'ABSPATH' ) ? ABSPATH . 'wp-config.php' : '',
			defined( 'ABSPATH' ) ? rtrim( ABSPATH, '/\\' ) . '/wp-config.php' : '',
			defined( 'ABSPATH' ) ? dirname( rtrim( ABSPATH, '/\\' ) ) . '/wp-config.php' : '',
			defined( 'ABSPATH' ) ? dirname( ABSPATH ) . '/wp-config.php' : '',
			defined( 'WP_CONTENT_DIR' ) ? dirname( WP_CONTENT_DIR ) . '/wp-config.php' : '',
			! empty( $_SERVER['DOCUMENT_ROOT'] ) ? rtrim( sanitize_text_field( wp_unslash( $_SERVER['DOCUMENT_ROOT'] ) ), '/\\' ) . '/wp-config.php' : '',
		] );

		foreach ( $possible_paths as $candidate ) {
			if ( @file_exists( $candidate ) ) {
				$wp_config_path  = $candidate;
				$wp_config_found = true;
				break;
			}
		}

		if ( $wp_config_found && @is_readable( $wp_config_path ) ) {
			$content = @file_get_contents( $wp_config_path );
			if ( false !== $content ) {
				if ( false !== strpos( $content, 'JWT_AUTH_SECRET_KEY' ) ) {
					$in_file_detected = true;
					if ( preg_match( "/define\s*\(\s*['\"]JWT_AUTH_SECRET_KEY['\"]\s*,\s*['\"]([^'\"]+)['\"]/i", $content, $matches ) ) {
						$file_secret_key = $matches[1];
					}

					// Check if placed after wp-settings.php (which prevents it from loading early enough)
					$settings_pos = strpos( $content, 'wp-settings.php' );
					$key_pos      = strpos( $content, 'JWT_AUTH_SECRET_KEY' );
					if ( false !== $settings_pos && $key_pos > $settings_pos && empty( $secret_key ) ) {
						$misplaced = true;
					}
				}

				if ( ! $cors_enabled && preg_match( "/define\s*\(\s*['\"]JWT_AUTH_CORS_ENABLE['\"]\s*,\s*(true|1)/i", $content ) ) {
					$cors_enabled = true;
				}
				if ( ! $dev_mode && preg_match( "/define\s*\(\s*['\"]JWT_AUTH_DEV_MODE['\"]\s*,\s*(true|1)/i", $content ) ) {
					$dev_mode = true;
				}
			}
		}

		// If runtime constant is missing but found in file, use file key for diagnostics
		$effective_key = ! empty( $secret_key ) ? (string) $secret_key : (string) $file_secret_key;
		$key_length    = strlen( $effective_key );
		$key_masked    = '';

		if ( $key_length > 0 ) {
			if ( $key_length > 8 ) {
				$key_masked = substr( $effective_key, 0, 4 ) . '••••••••' . substr( $effective_key, -4 );
			} else {
				$key_masked = '••••••••';
			}
		}

		$strength = 'Missing';
		if ( $key_length >= 64 ) {
			$strength = 'Excellent (512-bit+)';
		} elseif ( $key_length >= 32 ) {
			$strength = 'Strong (256-bit)';
		} elseif ( $key_length > 0 ) {
			$strength = 'Moderate / Short';
		}

		$is_configured = ! empty( $secret_key );
		$status_note   = '';
		if ( $is_configured ) {
			$status_note = $in_file_detected ? 'Configured in wp-config.php (Active)' : 'Configured via PHP constant / Environment (Active)';
		} elseif ( $misplaced ) {
			$status_note = 'Found in wp-config.php, but placed AFTER wp-settings.php! Move above "Happy publishing."';
		} elseif ( $in_file_detected ) {
			$status_note = 'Found in wp-config.php file';
		} else {
			$status_note = 'Not configured. Add define(\'JWT_AUTH_SECRET_KEY\', \'...\') to wp-config.php';
		}

		$algorithm     = apply_filters( 'jwt_auth_algorithm', 'HS256' );
		$access_exp    = (int) get_option( 'jwt_auth_access_token_expiry', 3600 );
		$refresh_exp   = (int) get_option( 'jwt_auth_refresh_token_expiry', 604800 );
		$custom_header = get_option( 'jwt_auth_custom_header', 'Authorization' );

		return rest_ensure_response( [
			'secret_key_configured' => $is_configured,
			'secret_key_masked'     => $key_masked,
			'secret_key_length'     => $key_length,
			'secret_key_strength'   => $strength,
			'secret_key_note'       => $status_note,
			'misplaced'             => $misplaced,
			'wp_config_found'       => $wp_config_found || $is_configured,
			'wp_config_path'        => $wp_config_path,
			'in_file_detected'      => $in_file_detected,
			'cors_enabled'          => (bool) $cors_enabled,
			'dev_mode'              => (bool) $dev_mode,
			'algorithm'             => $algorithm,
			'access_token_expiry'   => $access_exp,
			'refresh_token_expiry'  => $refresh_exp,
			'custom_header'         => $custom_header,
			'rest_api_url'          => rest_url( 'jwt-auth/v1' ),
			'endpoints'             => [
				'token'          => rest_url( 'jwt-auth/v1/token' ),
				'token_validate' => rest_url( 'jwt-auth/v1/token/validate' ),
				'token_refresh'  => rest_url( 'jwt-auth/v1/token/refresh' ),
				'token_revoke'   => rest_url( 'jwt-auth/v1/token/revoke' ),
			],
		] );
	}
}
