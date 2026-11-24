<?php
/**
 * Analytics Tracking and Reporting
 *
 * @package JWT_Authenticator
 * @license MIT
 * @link    https://opensource.org/licenses/MIT
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
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Class Jwt_Auth_Analytics
 *
 * Tracks JWT authentication events and exposes an admin REST API for analytics reporting.
 */
class Jwt_Auth_Analytics {

	/**
	 * Singleton instance.
	 *
	 * @var Jwt_Auth_Analytics|null
	 */
	private static ?Jwt_Auth_Analytics $instance = null;

	/**
	 * Get singleton instance.
	 *
	 * @return Jwt_Auth_Analytics
	 */
	public static function get_instance(): Jwt_Auth_Analytics {
		if ( null === self::$instance ) {
			self::$instance = new self();
		}
		return self::$instance;
	}

	/**
	 * Private constructor — use get_instance().
	 */
	private function __construct() {}

	/**
	 * Register WordPress hooks.
	 *
	 * @return void
	 */
	public function register_hooks(): void {
		add_action( 'jwt_auth_token_generated', [ $this, 'track_token_generated' ], 10, 3 );
		add_filter( 'rest_pre_dispatch', [ $this, 'track_request' ], 99, 3 );
		add_action( 'rest_api_init', [ $this, 'register_analytics_routes' ] );
	}

	// -------------------------------------------------------------------------
	// Hook Callbacks
	// -------------------------------------------------------------------------

	/**
	 * Track a token generation event.
	 *
	 * @param int    $user_id     WordPress user ID.
	 * @param string $token_type  'access' or 'refresh'.
	 * @param string $auth_method Auth method used (e.g. 'password', 'firebase').
	 * @return void
	 */
	public function track_token_generated( int $user_id, string $token_type, string $auth_method ): void {
		$endpoint = isset( $_SERVER['REQUEST_URI'] ) ? sanitize_text_field( wp_unslash( $_SERVER['REQUEST_URI'] ) ) : '';
		$this->track_event( 'token_generated', $user_id, $endpoint, $auth_method );
	}

	/**
	 * Track incoming REST requests (fires as a filter, returns $result unchanged).
	 *
	 * @param mixed           $result  Current result (null means not yet dispatched).
	 * @param WP_REST_Server  $server  REST server instance.
	 * @param WP_REST_Request $request Incoming request.
	 * @return mixed Unmodified $result.
	 */
	public function track_request( $result, WP_REST_Server $server, WP_REST_Request $request ) {
		// Only track jwt-auth routes to avoid noise.
		$route = $request->get_route();
		if ( false === strpos( $route, '/jwt-auth/' ) ) {
			return $result;
		}

		$user_id     = get_current_user_id();
		$auth_method = $this->detect_auth_method( $request );

		$this->track_event( 'api_request', $user_id, $route, $auth_method );

		return $result;
	}

	// -------------------------------------------------------------------------
	// Core Event Tracking
	// -------------------------------------------------------------------------

	/**
	 * Record an analytics event to the database.
	 *
	 * @param string $event_type  Event type identifier.
	 * @param int    $user_id     WordPress user ID (0 for anonymous).
	 * @param string $endpoint    REST endpoint or URI.
	 * @param string $auth_method Authentication method used.
	 * @param array  $extra       Additional metadata to store as JSON.
	 * @return void
	 */
	public function track_event(
		string $event_type,
		int    $user_id    = 0,
		string $endpoint   = '',
		string $auth_method = '',
		array  $extra      = []
	): void {
		global $wpdb;

		$ip         = $this->get_client_ip();
		$geo        = Jwt_Auth_Geo_IP::get_instance()->get_location( $ip );
		$user_agent = isset( $_SERVER['HTTP_USER_AGENT'] )
			? sanitize_text_field( wp_unslash( $_SERVER['HTTP_USER_AGENT'] ) )
			: '';

		$metadata = ! empty( $extra ) ? wp_json_encode( $extra ) : null;

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery
		$wpdb->insert(
			$wpdb->prefix . 'jwt_analytics',
			[
				'event_type'   => sanitize_text_field( $event_type ),
				'user_id'      => $user_id > 0 ? $user_id : null,
				'endpoint'     => sanitize_text_field( $endpoint ),
				'auth_method'  => sanitize_text_field( $auth_method ),
				'ip_address'   => sanitize_text_field( $ip ),
				'country_code' => sanitize_text_field( $geo['country_code'] ),
				'country_name' => sanitize_text_field( $geo['country_name'] ),
				'user_agent'   => $user_agent,
				'metadata'     => $metadata,
				'created_at'   => current_time( 'mysql', true ),
			],
			[ '%s', '%d', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s' ]
		);
	}

	// -------------------------------------------------------------------------
	// Admin REST Routes
	// -------------------------------------------------------------------------

	/**
	 * Register analytics admin REST routes.
	 *
	 * @return void
	 */
	public function register_analytics_routes(): void {
		register_rest_route(
			'jwt-auth/v1',
			'/admin/analytics',
			[
				'methods'             => WP_REST_Server::READABLE,
				'callback'            => [ $this, 'handle_analytics_endpoint' ],
				'permission_callback' => [ $this, 'admin_permission_check' ],
				'args'                => [
					'days' => [
						'required'          => false,
						'type'              => 'integer',
						'default'           => 30,
						'minimum'           => 1,
						'maximum'           => 365,
						'sanitize_callback' => 'absint',
					],
				],
			]
		);
	}

	/**
	 * Permission callback — requires manage_options.
	 *
	 * @return bool
	 */
	public function admin_permission_check(): bool {
		return current_user_can( 'manage_options' );
	}

	/**
	 * Handle GET /jwt-auth/v1/admin/analytics
	 *
	 * @param WP_REST_Request $request Incoming request.
	 * @return WP_REST_Response|WP_Error
	 */
	public function handle_analytics_endpoint( WP_REST_Request $request ) {
		global $wpdb;

		$days      = (int) $request->get_param( 'days' );
		$table     = $wpdb->prefix . 'jwt_analytics';
		$date_from = gmdate( 'Y-m-d H:i:s', strtotime( "-{$days} days" ) );

		// Total tokens generated.
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.PreparedSQL.InterpolatedNotPrepared
		$total_tokens = (int) $wpdb->get_var(
			$wpdb->prepare(
				"SELECT COUNT(*) FROM `{$table}` WHERE event_type = %s AND created_at >= %s",
				'token_generated',
				$date_from
			)
		);

		// Auth failures.
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.PreparedSQL.InterpolatedNotPrepared
		$auth_failures = (int) $wpdb->get_var(
			$wpdb->prepare(
				"SELECT COUNT(*) FROM `{$table}` WHERE event_type = %s AND created_at >= %s",
				'auth_failed',
				$date_from
			)
		);

		// Top 10 endpoints.
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.PreparedSQL.InterpolatedNotPrepared
		$top_endpoints = $wpdb->get_results(
			$wpdb->prepare(
				"SELECT endpoint, COUNT(*) AS request_count
				FROM `{$table}`
				WHERE created_at >= %s AND endpoint != ''
				GROUP BY endpoint
				ORDER BY request_count DESC
				LIMIT 10",
				$date_from
			),
			ARRAY_A
		);

		// Auth method breakdown.
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.PreparedSQL.InterpolatedNotPrepared
		$auth_method_breakdown = $wpdb->get_results(
			$wpdb->prepare(
				"SELECT auth_method, COUNT(*) AS count
				FROM `{$table}`
				WHERE created_at >= %s AND auth_method != ''
				GROUP BY auth_method
				ORDER BY count DESC",
				$date_from
			),
			ARRAY_A
		);

		// Daily requests (last N days grouped by date).
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.PreparedSQL.InterpolatedNotPrepared
		$daily_requests = $wpdb->get_results(
			$wpdb->prepare(
				"SELECT DATE(created_at) AS date, COUNT(*) AS request_count
				FROM `{$table}`
				WHERE created_at >= %s
				GROUP BY DATE(created_at)
				ORDER BY date ASC",
				$date_from
			),
			ARRAY_A
		);

		// Top 10 countries.
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.PreparedSQL.InterpolatedNotPrepared
		$top_countries = $wpdb->get_results(
			$wpdb->prepare(
				"SELECT country_code, country_name, COUNT(*) AS request_count
				FROM `{$table}`
				WHERE created_at >= %s AND country_code != ''
				GROUP BY country_code, country_name
				ORDER BY request_count DESC
				LIMIT 10",
				$date_from
			),
			ARRAY_A
		);

		return rest_ensure_response(
			[
				'period_days'          => $days,
				'total_tokens_generated' => $total_tokens,
				'auth_failures'        => $auth_failures,
				'top_endpoints'        => $top_endpoints        ?: [],
				'auth_method_breakdown' => $auth_method_breakdown ?: [],
				'daily_requests'       => $daily_requests       ?: [],
				'top_countries'        => $top_countries        ?: [],
			]
		);
	}

	// -------------------------------------------------------------------------
	// Helpers
	// -------------------------------------------------------------------------

	/**
	 * Get the best available client IP address.
	 *
	 * Falls back to Jwt_Auth_Helpers::get_client_ip() when available.
	 *
	 * @return string
	 */
	private function get_client_ip(): string {
		if ( class_exists( 'Jwt_Auth_Helpers' ) && method_exists( 'Jwt_Auth_Helpers', 'get_client_ip' ) ) {
			return Jwt_Auth_Helpers::get_client_ip();
		}

		// Fallback.
		$headers = [
			'HTTP_CF_CONNECTING_IP',
			'HTTP_X_FORWARDED_FOR',
			'HTTP_X_REAL_IP',
			'REMOTE_ADDR',
		];

		foreach ( $headers as $header ) {
			if ( ! empty( $_SERVER[ $header ] ) ) {
				$ip = sanitize_text_field( wp_unslash( $_SERVER[ $header ] ) );
				// X-Forwarded-For can contain a comma-separated list; take the first.
				if ( false !== strpos( $ip, ',' ) ) {
					$ip = trim( explode( ',', $ip )[0] );
				}
				if ( filter_var( $ip, FILTER_VALIDATE_IP ) ) {
					return $ip;
				}
			}
		}

		return '';
	}

	/**
	 * Attempt to detect the authentication method from the request.
	 *
	 * @param WP_REST_Request $request Incoming request.
	 * @return string
	 */
	private function detect_auth_method( WP_REST_Request $request ): string {
		$auth_header = $request->get_header( 'authorization' );

		if ( empty( $auth_header ) ) {
			return '';
		}

		$auth_header_lower = strtolower( $auth_header );

		if ( 0 === strpos( $auth_header_lower, 'bearer ' ) ) {
			return 'jwt';
		}

		if ( 0 === strpos( $auth_header_lower, 'basic ' ) ) {
			return 'basic';
		}

		if ( 0 === strpos( $auth_header_lower, 'apikey ' ) ) {
			return 'api_key';
		}

		return 'unknown';
	}
}
