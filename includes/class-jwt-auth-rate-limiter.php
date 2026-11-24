<?php
/**
 * JWT Auth Rate Limiter
 *
 * Middleware that enforces per-IP or per-user request rate limits on the
 * WordPress REST API using the jwt_rate_limits database table.
 *
 * @package JWT_Authenticator
 * @license MIT
 * @link    https://opensource.org/licenses/MIT
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Class Jwt_Auth_Rate_Limiter
 *
 * Singleton that checks and records request counts in sliding windows,
 * returning HTTP 429 responses when a client exceeds the configured limit.
 */
class Jwt_Auth_Rate_Limiter {

	/**
	 * Singleton instance.
	 *
	 * @var Jwt_Auth_Rate_Limiter|null
	 */
	private static ?Jwt_Auth_Rate_Limiter $instance = null;

	/**
	 * Whether rate limiting is active.
	 *
	 * @var bool
	 */
	private bool $enabled;

	/**
	 * Maximum requests allowed within the window.
	 *
	 * @var int
	 */
	private int $max_requests;

	/**
	 * Window duration in seconds.
	 *
	 * @var int
	 */
	private int $window_seconds;

	/**
	 * Whether to limit per authenticated user instead of per IP.
	 *
	 * @var bool
	 */
	private bool $per_user;

	/**
	 * Private constructor — use get_instance().
	 */
	private function __construct() {
		$this->load_settings();
	}

	/**
	 * Returns the singleton instance.
	 *
	 * @return Jwt_Auth_Rate_Limiter
	 */
	public static function get_instance(): Jwt_Auth_Rate_Limiter {
		if ( null === self::$instance ) {
			self::$instance = new self();
		}
		return self::$instance;
	}

	/**
	 * Load settings from WordPress options.
	 *
	 * @return void
	 */
	private function load_settings(): void {
		$this->enabled        = (bool) get_option( 'jwt_auth_rate_limit_enabled', false );
		$this->max_requests   = (int) get_option( 'jwt_auth_rate_limit_requests', 100 );
		$this->window_seconds = (int) get_option( 'jwt_auth_rate_limit_window', 3600 );
		$this->per_user       = (bool) get_option( 'jwt_auth_rate_limit_per_user', false );
	}

	/**
	 * Register WordPress hooks.
	 *
	 * @return void
	 */
	public function register_hooks(): void {
		add_filter( 'rest_pre_dispatch', [ $this, 'check_rate_limit' ], 5, 3 );
		add_filter( 'rest_post_dispatch', [ $this, 'add_rate_limit_headers' ], 10, 3 );
		add_action( 'jwt_auth_cleanup_rate_limits', [ $this, 'cleanup_old_windows' ] );
		add_action( 'rest_api_init', [ $this, 'register_admin_routes' ] );
	}

	/**
	 * REST pre-dispatch filter: enforce rate limit.
	 *
	 * @param mixed           $result  Current dispatch result.
	 * @param WP_REST_Server  $server  REST server instance.
	 * @param WP_REST_Request $request Current request.
	 * @return mixed WP_Error on rate-limit breach, original $result otherwise.
	 */
	public function check_rate_limit( $result, WP_REST_Server $server, WP_REST_Request $request ) {
		if ( ! $this->enabled ) {
			return $result;
		}

		if ( is_wp_error( $result ) ) {
			return $result;
		}

		$identifier = $this->get_identifier();
		$route      = $request->get_route();

		if ( $this->is_rate_limited( $identifier, $route ) ) {
			$window_reset = $this->get_window_reset_time( $identifier, $route );
			$retry_after  = max( 0, $window_reset - time() );

			return new WP_Error(
				'rate_limit_exceeded',
				__( 'Too many requests. Please slow down.', 'jwt-authenticator' ),
				[
					'status'      => 429,
					'retry_after' => $retry_after,
				]
			);
		}

		$this->increment_request_count( $identifier, $route );

		return $result;
	}

	/**
	 * REST post-dispatch filter: add rate-limit headers to the response.
	 *
	 * @param WP_REST_Response $response Current response.
	 * @param WP_REST_Server   $server   REST server instance.
	 * @param WP_REST_Request  $request  Current request.
	 * @return WP_REST_Response
	 */
	public function add_rate_limit_headers( WP_REST_Response $response, WP_REST_Server $server, WP_REST_Request $request ): WP_REST_Response {
		if ( ! $this->enabled ) {
			return $response;
		}

		$identifier = $this->get_identifier();
		$route      = $request->get_route();
		$headers    = $this->get_rate_limit_headers( $identifier, $route );

		foreach ( $headers as $header_name => $header_value ) {
			$response->header( $header_name, $header_value );
		}

		return $response;
	}

	/**
	 * Check whether the identifier has exceeded the rate limit.
	 *
	 * @param string $identifier Client identifier (user ID or IP).
	 * @param string $route      Current REST route.
	 * @return bool
	 */
	public function is_rate_limited( string $identifier, string $route ): bool {
		global $wpdb;

		$table = $wpdb->prefix . 'jwt_rate_limits';

		// phpcs:disable WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching
		$requests = $wpdb->get_var(
			$wpdb->prepare(
				"SELECT requests FROM {$table}
				 WHERE identifier = %s
				   AND endpoint   = %s
				   AND window_start > DATE_SUB(NOW(), INTERVAL %d SECOND)
				 LIMIT 1",
				$identifier,
				$route,
				$this->window_seconds
			)
		);
		// phpcs:enable

		return ( (int) $requests ) >= $this->max_requests;
	}

	/**
	 * Increment (or initialise) the request counter for an identifier/route.
	 *
	 * Uses INSERT … ON DUPLICATE KEY UPDATE to avoid race conditions.
	 * A UNIQUE KEY on (identifier, endpoint) is assumed in the schema.
	 *
	 * @param string $identifier Client identifier.
	 * @param string $route      Current REST route.
	 * @return void
	 */
	public function increment_request_count( string $identifier, string $route ): void {
		global $wpdb;

		$table = $wpdb->prefix . 'jwt_rate_limits';

		// phpcs:disable WordPress.DB.DirectDatabaseQuery.DirectQuery
		$wpdb->query(
			$wpdb->prepare(
				"INSERT INTO {$table} (identifier, endpoint, requests, window_start)
				 VALUES (%s, %s, 1, NOW())
				 ON DUPLICATE KEY UPDATE
				     requests     = IF(window_start > DATE_SUB(NOW(), INTERVAL %d SECOND),
				                      requests + 1,
				                      1),
				     window_start = IF(window_start > DATE_SUB(NOW(), INTERVAL %d SECOND),
				                      window_start,
				                      NOW())",
				$identifier,
				$route,
				$this->window_seconds,
				$this->window_seconds
			)
		);
		// phpcs:enable
	}

	/**
	 * Delete expired rate-limit rows.
	 *
	 * Intended to be run via WP-Cron (jwt_auth_cleanup_rate_limits).
	 *
	 * @return void
	 */
	public function cleanup_old_windows(): void {
		global $wpdb;

		$table = $wpdb->prefix . 'jwt_rate_limits';

		// phpcs:disable WordPress.DB.DirectDatabaseQuery.DirectQuery
		$wpdb->query(
			$wpdb->prepare(
				"DELETE FROM {$table}
				 WHERE window_start < DATE_SUB(NOW(), INTERVAL %d SECOND)",
				$this->window_seconds
			)
		);
		// phpcs:enable
	}

	/**
	 * Build rate-limit headers for a given identifier and route.
	 *
	 * @param string $identifier Client identifier.
	 * @param string $route      Current REST route.
	 * @return array Associative array of header name → value.
	 */
	public function get_rate_limit_headers( string $identifier, string $route ): array {
		global $wpdb;

		$table = $wpdb->prefix . 'jwt_rate_limits';

		// phpcs:disable WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching
		$row = $wpdb->get_row(
			$wpdb->prepare(
				"SELECT requests, window_start FROM {$table}
				 WHERE identifier = %s
				   AND endpoint   = %s
				   AND window_start > DATE_SUB(NOW(), INTERVAL %d SECOND)
				 LIMIT 1",
				$identifier,
				$route,
				$this->window_seconds
			)
		);
		// phpcs:enable

		$used      = $row ? (int) $row->requests : 0;
		$remaining = max( 0, $this->max_requests - $used );

		if ( $row ) {
			$window_start = strtotime( $row->window_start );
			$reset_time   = $window_start + $this->window_seconds;
		} else {
			$reset_time = time() + $this->window_seconds;
		}

		return [
			'X-RateLimit-Limit'     => $this->max_requests,
			'X-RateLimit-Remaining' => $remaining,
			'X-RateLimit-Reset'     => $reset_time,
		];
	}

	// -------------------------------------------------------------------------
	// Admin REST routes
	// -------------------------------------------------------------------------

	/**
	 * Register admin REST routes for rate-limiter settings.
	 *
	 * @return void
	 */
	public function register_admin_routes(): void {
		register_rest_route(
			'jwt-auth/v1',
			'/admin/rate-limit',
			[
				[
					'methods'             => WP_REST_Server::READABLE,
					'callback'            => [ $this, 'get_rate_limit_settings' ],
					'permission_callback' => [ $this, 'admin_permission_check' ],
				],
				[
					'methods'             => WP_REST_Server::CREATABLE,
					'callback'            => [ $this, 'update_rate_limit_settings' ],
					'permission_callback' => [ $this, 'admin_permission_check' ],
					'args'                => [
						'enabled'      => [ 'type' => 'boolean', 'required' => false ],
						'requests'     => [ 'type' => 'integer', 'required' => false, 'minimum' => 1 ],
						'window'       => [ 'type' => 'integer', 'required' => false, 'minimum' => 1 ],
						'per_user'     => [ 'type' => 'boolean', 'required' => false ],
					],
				],
			]
		);
	}

	/**
	 * Permission callback: requires manage_options capability.
	 *
	 * @return bool|WP_Error
	 */
	public function admin_permission_check() {
		if ( ! current_user_can( 'manage_options' ) ) {
			return new WP_Error(
				'rest_forbidden',
				__( 'You do not have permission to manage rate-limit settings.', 'jwt-authenticator' ),
				[ 'status' => 403 ]
			);
		}
		return true;
	}

	/**
	 * GET /jwt-auth/v1/admin/rate-limit — return current settings.
	 *
	 * @return WP_REST_Response
	 */
	public function get_rate_limit_settings(): WP_REST_Response {
		return new WP_REST_Response(
			[
				'enabled'      => $this->enabled,
				'requests'     => $this->max_requests,
				'window'       => $this->window_seconds,
				'per_user'     => $this->per_user,
			],
			200
		);
	}

	/**
	 * POST /jwt-auth/v1/admin/rate-limit — update settings.
	 *
	 * @param WP_REST_Request $request Incoming request.
	 * @return WP_REST_Response
	 */
	public function update_rate_limit_settings( WP_REST_Request $request ): WP_REST_Response {
		$map = [
			'enabled'  => 'jwt_auth_rate_limit_enabled',
			'requests' => 'jwt_auth_rate_limit_requests',
			'window'   => 'jwt_auth_rate_limit_window',
			'per_user' => 'jwt_auth_rate_limit_per_user',
		];

		$updated = [];
		foreach ( $map as $param => $option ) {
			if ( $request->has_param( $param ) ) {
				$value = $request->get_param( $param );
				update_option( $option, $value );
				$updated[ $param ] = $value;
			}
		}

		$this->load_settings();

		return new WP_REST_Response(
			[
				'success' => true,
				'updated' => $updated,
			],
			200
		);
	}

	// -------------------------------------------------------------------------
	// Helpers
	// -------------------------------------------------------------------------

	/**
	 * Get the client identifier: user ID (if per-user mode and logged in), else IP.
	 *
	 * @return string
	 */
	private function get_identifier(): string {
		$user_id = get_current_user_id();

		if ( $this->per_user && $user_id > 0 ) {
			return 'user_' . $user_id;
		}

		return $this->get_client_ip();
	}

	/**
	 * Retrieve the best-guess client IP address.
	 *
	 * @return string
	 */
	private function get_client_ip(): string {
		$headers = [
			'HTTP_CF_CONNECTING_IP',
			'HTTP_X_FORWARDED_FOR',
			'HTTP_X_REAL_IP',
			'REMOTE_ADDR',
		];

		foreach ( $headers as $header ) {
			if ( ! empty( $_SERVER[ $header ] ) ) {
				// X-Forwarded-For may contain a comma-separated list; take the first.
				$ip = trim( explode( ',', sanitize_text_field( wp_unslash( $_SERVER[ $header ] ) ) )[0] );
				if ( filter_var( $ip, FILTER_VALIDATE_IP ) ) {
					return $ip;
				}
			}
		}

		return '0.0.0.0';
	}

	/**
	 * Calculate when the current window resets for a given identifier/route.
	 *
	 * @param string $identifier Client identifier.
	 * @param string $route      Current REST route.
	 * @return int Unix timestamp of window reset.
	 */
	private function get_window_reset_time( string $identifier, string $route ): int {
		global $wpdb;

		$table = $wpdb->prefix . 'jwt_rate_limits';

		// phpcs:disable WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching
		$window_start = $wpdb->get_var(
			$wpdb->prepare(
				"SELECT window_start FROM {$table}
				 WHERE identifier = %s
				   AND endpoint   = %s
				   AND window_start > DATE_SUB(NOW(), INTERVAL %d SECOND)
				 LIMIT 1",
				$identifier,
				$route,
				$this->window_seconds
			)
		);
		// phpcs:enable

		if ( $window_start ) {
			return strtotime( $window_start ) + $this->window_seconds;
		}

		return time() + $this->window_seconds;
	}
}
