<?php
/**
 * JWT Authenticator — API Key Authentication
 *
 * Handles universal and user-specific API key authentication,
 * REST endpoints for managing API keys, and the determine_current_user filter.
 *
 * @package    JWT_Authenticator
 * @subpackage JWT_Authenticator/includes
 * @license    MIT https://opensource.org/licenses/MIT
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Class Jwt_Auth_Api_Keys
 *
 * Singleton. Register hooks via register_hooks().
 */
class Jwt_Auth_Api_Keys {

	/**
	 * Singleton instance.
	 *
	 * @var Jwt_Auth_Api_Keys|null
	 */
	private static ?Jwt_Auth_Api_Keys $instance = null;

	/**
	 * Private constructor — use get_instance().
	 */
	private function __construct() {}

	/**
	 * Returns the singleton instance.
	 *
	 * @return Jwt_Auth_Api_Keys
	 */
	public static function get_instance(): Jwt_Auth_Api_Keys {
		if ( null === self::$instance ) {
			self::$instance = new self();
		}
		return self::$instance;
	}

	/**
	 * Register WordPress hooks.
	 *
	 * @return void
	 */
	public function register_hooks(): void {
		add_filter( 'determine_current_user', [ $this, 'authenticate_with_api_key' ], 20 );
		add_action( 'rest_api_init', [ $this, 'register_api_key_routes' ] );
	}

	// -------------------------------------------------------------------------
	// REST route registration
	// -------------------------------------------------------------------------

	/**
	 * Register all API key REST routes.
	 *
	 * @return void
	 */
	public function register_api_key_routes(): void {
		$namespace = 'jwt-auth/v1';
		$base      = 'api-keys';

		// User routes.
		register_rest_route(
			$namespace,
			'/' . $base,
			[
				[
					'methods'             => WP_REST_Server::READABLE,
					'callback'            => [ $this, 'rest_list_keys' ],
					'permission_callback' => [ $this, 'permission_logged_in' ],
				],
				[
					'methods'             => WP_REST_Server::CREATABLE,
					'callback'            => [ $this, 'rest_create_key' ],
					'permission_callback' => [ $this, 'permission_logged_in' ],
					'args'                => [
						'name'        => [
							'required'          => true,
							'type'              => 'string',
							'sanitize_callback' => 'sanitize_text_field',
						],
						'permissions' => [
							'required' => false,
							'type'     => 'array',
							'default'  => [],
							'items'    => [ 'type' => 'string' ],
						],
						'expires_at'  => [
							'required' => false,
							'type'     => 'string',
							'default'  => null,
						],
					],
				],
			]
		);

		register_rest_route(
			$namespace,
			'/' . $base . '/(?P<id>\d+)',
			[
				'methods'             => WP_REST_Server::DELETABLE,
				'callback'            => [ $this, 'rest_delete_key' ],
				'permission_callback' => [ $this, 'permission_logged_in' ],
				'args'                => [
					'id' => [
						'required' => true,
						'type'     => 'integer',
					],
				],
			]
		);

		// Admin routes.
		register_rest_route(
			$namespace,
			'/' . $base . '/admin',
			[
				'methods'             => WP_REST_Server::READABLE,
				'callback'            => [ $this, 'rest_admin_list_keys' ],
				'permission_callback' => [ $this, 'permission_admin' ],
			]
		);

		register_rest_route(
			$namespace,
			'/' . $base . '/admin/universal',
			[
				'methods'             => WP_REST_Server::CREATABLE,
				'callback'            => [ $this, 'rest_create_universal_key' ],
				'permission_callback' => [ $this, 'permission_admin' ],
				'args'                => [
					'name'        => [
						'required'          => true,
						'type'              => 'string',
						'sanitize_callback' => 'sanitize_text_field',
					],
					'permissions' => [
						'required' => false,
						'type'     => 'array',
						'default'  => [],
						'items'    => [ 'type' => 'string' ],
					],
					'expires_at'  => [
						'required' => false,
						'type'     => 'string',
						'default'  => null,
					],
				],
			]
		);
	}

	// -------------------------------------------------------------------------
	// Permission callbacks
	// -------------------------------------------------------------------------

	/**
	 * Permission callback: user must be logged in.
	 *
	 * @return bool|WP_Error
	 */
	public function permission_logged_in() {
		if ( ! is_user_logged_in() ) {
			return new WP_Error(
				'rest_not_logged_in',
				__( 'You must be logged in to manage API keys.', 'jwt-authenticator' ),
				[ 'status' => 401 ]
			);
		}
		return true;
	}

	/**
	 * Permission callback: user must be an administrator.
	 *
	 * @return bool|WP_Error
	 */
	public function permission_admin() {
		if ( ! current_user_can( 'manage_options' ) ) {
			return new WP_Error(
				'rest_forbidden',
				__( 'You do not have permission to perform this action.', 'jwt-authenticator' ),
				[ 'status' => 403 ]
			);
		}
		return true;
	}

	// -------------------------------------------------------------------------
	// REST callbacks
	// -------------------------------------------------------------------------

	/**
	 * List current user's API keys.
	 *
	 * @param WP_REST_Request $request Request object.
	 * @return WP_REST_Response
	 */
	public function rest_list_keys( WP_REST_Request $request ): WP_REST_Response {
		global $wpdb;

		$user_id = get_current_user_id();
		$table   = $wpdb->prefix . 'jwt_api_keys';

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery
		$keys = $wpdb->get_results(
			$wpdb->prepare(
				"SELECT id, name, permissions, last_used, expires_at, active, created_at
				 FROM {$table}
				 WHERE user_id = %d
				 ORDER BY created_at DESC",
				$user_id
			),
			ARRAY_A
		);

		foreach ( $keys as &$key ) {
			$key['permissions'] = $key['permissions'] ? json_decode( $key['permissions'], true ) : [];
		}
		unset( $key );

		return rest_ensure_response( $keys );
	}

	/**
	 * Create a new API key for the current user.
	 *
	 * @param WP_REST_Request $request Request object.
	 * @return WP_REST_Response|WP_Error
	 */
	public function rest_create_key( WP_REST_Request $request ) {
		$user_id    = get_current_user_id();
		$name       = $request->get_param( 'name' );
		$perms      = (array) $request->get_param( 'permissions' );
		$expires_at = $request->get_param( 'expires_at' );

		$result = $this->create_api_key( $user_id, $name, $perms, $expires_at );

		if ( is_wp_error( $result ) ) {
			return $result;
		}

		return rest_ensure_response( $result );
	}

	/**
	 * Delete (deactivate) one of the current user's API keys.
	 *
	 * @param WP_REST_Request $request Request object.
	 * @return WP_REST_Response|WP_Error
	 */
	public function rest_delete_key( WP_REST_Request $request ) {
		global $wpdb;

		$user_id = get_current_user_id();
		$id      = (int) $request->get_param( 'id' );
		$table   = $wpdb->prefix . 'jwt_api_keys';

		// Verify ownership.
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery
		$existing = $wpdb->get_row(
			$wpdb->prepare(
				"SELECT id FROM {$table} WHERE id = %d AND user_id = %d",
				$id,
				$user_id
			)
		);

		if ( ! $existing ) {
			return new WP_Error(
				'jwt_auth_api_key_not_found',
				__( 'API key not found or you do not have permission to delete it.', 'jwt-authenticator' ),
				[ 'status' => 404 ]
			);
		}

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery
		$wpdb->update(
			$table,
			[ 'active' => 0 ],
			[ 'id' => $id, 'user_id' => $user_id ],
			[ '%d' ],
			[ '%d', '%d' ]
		);

		return rest_ensure_response( [ 'deleted' => true, 'id' => $id ] );
	}

	/**
	 * Admin: list all API keys.
	 *
	 * @param WP_REST_Request $request Request object.
	 * @return WP_REST_Response
	 */
	public function rest_admin_list_keys( WP_REST_Request $request ): WP_REST_Response {
		global $wpdb;

		$table = $wpdb->prefix . 'jwt_api_keys';

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery
		$keys = $wpdb->get_results(
			"SELECT id, user_id, name, permissions, last_used, expires_at, active, created_at
			 FROM {$table}
			 ORDER BY created_at DESC",
			ARRAY_A
		);

		foreach ( $keys as &$key ) {
			$key['permissions'] = $key['permissions'] ? json_decode( $key['permissions'], true ) : [];
		}
		unset( $key );

		return rest_ensure_response( $keys );
	}

	/**
	 * Admin: create a universal API key (not bound to any user).
	 *
	 * @param WP_REST_Request $request Request object.
	 * @return WP_REST_Response|WP_Error
	 */
	public function rest_create_universal_key( WP_REST_Request $request ) {
		$name       = $request->get_param( 'name' );
		$perms      = (array) $request->get_param( 'permissions' );
		$expires_at = $request->get_param( 'expires_at' );

		$result = $this->create_api_key( 0, $name, $perms, $expires_at, true );

		if ( is_wp_error( $result ) ) {
			return $result;
		}

		return rest_ensure_response( $result );
	}

	// -------------------------------------------------------------------------
	// Core authentication filter
	// -------------------------------------------------------------------------

	/**
	 * Attempt to authenticate the request using an API key.
	 *
	 * Hooked into determine_current_user at priority 20.
	 *
	 * @param int|false $user Existing resolved user ID (or false).
	 * @return int|false|WP_Error
	 */
	public function authenticate_with_api_key( $user ) {
		// Don't override an already-authenticated user.
		if ( $user ) {
			return $user;
		}

		$api_key = $this->extract_api_key_from_request();

		if ( null === $api_key ) {
			return $user;
		}

		global $wpdb;

		$key_hash = Jwt_Auth_Helpers::hash_api_key( $api_key );
		$table    = $wpdb->prefix . 'jwt_api_keys';

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery
		$record = $wpdb->get_row(
			$wpdb->prepare(
				"SELECT id, user_id, permissions
				 FROM {$table}
				 WHERE key_hash = %s
				   AND active = 1
				   AND (expires_at IS NULL OR expires_at > NOW())",
				$key_hash
			)
		);

		if ( ! $record ) {
			return new WP_Error(
				'jwt_auth_invalid_api_key',
				__( 'Invalid API key.', 'jwt-authenticator' ),
				[ 'status' => 401 ]
			);
		}

		// Optional route-level permission check.
		if ( ! empty( $record->permissions ) ) {
			$permissions = json_decode( $record->permissions, true );
			if ( is_array( $permissions ) && ! empty( $permissions ) ) {
				$current_route = $this->get_current_rest_route();
				$allowed       = false;
				foreach ( $permissions as $pattern ) {
					if ( $current_route && fnmatch( $pattern, $current_route ) ) {
						$allowed = true;
						break;
					}
				}
				if ( ! $allowed ) {
					return new WP_Error(
						'jwt_auth_api_key_forbidden',
						__( 'API key does not have permission to access this route.', 'jwt-authenticator' ),
						[ 'status' => 403 ]
					);
				}
			}
		}

		// Update last_used timestamp.
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery
		$wpdb->update(
			$table,
			[ 'last_used' => current_time( 'mysql', true ) ],
			[ 'id' => (int) $record->id ],
			[ '%s' ],
			[ '%d' ]
		);

		// Universal key — resolve to configured fallback user.
		if ( null === $record->user_id ) {
			$fallback = (int) get_option( 'jwt_auth_api_key_user_id', 1 );
			return $fallback > 0 ? $fallback : 1;
		}

		return (int) $record->user_id;
	}

	// -------------------------------------------------------------------------
	// Public helpers
	// -------------------------------------------------------------------------

	/**
	 * Create a new API key.
	 *
	 * @param int         $user_id     WordPress user ID (0 for universal keys).
	 * @param string      $name        Human-readable label.
	 * @param array       $permissions Array of route patterns the key may access.
	 * @param string|null $expires_at  MySQL datetime string or null for no expiry.
	 * @param bool        $universal   Whether this is a universal (non-user) key.
	 * @return array|WP_Error
	 */
	public function create_api_key(
		int $user_id,
		string $name,
		array $permissions = [],
		?string $expires_at = null,
		bool $universal = false
	) {
		global $wpdb;

		$plaintext = 'jwta_' . bin2hex( random_bytes( 24 ) );
		$key_hash  = Jwt_Auth_Helpers::hash_api_key( $plaintext );
		$table     = $wpdb->prefix . 'jwt_api_keys';
		$now       = current_time( 'mysql', true );

		$data   = [
			'user_id'     => $universal ? null : $user_id,
			'api_key'     => substr( $plaintext, 0, 12 ) . '…', // Store only a preview; full key is hashed.
			'key_hash'    => $key_hash,
			'name'        => $name,
			'permissions' => ! empty( $permissions ) ? wp_json_encode( $permissions ) : null,
			'expires_at'  => $expires_at,
			'active'      => 1,
			'created_at'  => $now,
		];
		$format = [ '%d', '%s', '%s', '%s', '%s', '%s', '%d', '%s' ];

		if ( $universal ) {
			// user_id column should store NULL.
			$data['user_id'] = null;
			$format[0]       = '%s'; // Will be cast correctly by WPDB when value is null.
		}

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery
		$inserted = $wpdb->insert( $table, $data, $format );

		if ( false === $inserted ) {
			return new WP_Error(
				'jwt_auth_api_key_create_failed',
				__( 'Failed to create API key.', 'jwt-authenticator' ),
				[ 'status' => 500 ]
			);
		}

		return [
			'id'         => $wpdb->insert_id,
			'api_key'    => $plaintext, // Returned ONCE — never stored in plaintext.
			'name'       => $name,
			'created_at' => $now,
		];
	}

	// -------------------------------------------------------------------------
	// Private helpers
	// -------------------------------------------------------------------------

	/**
	 * Extract an API key from the current request.
	 *
	 * Checks (in order):
	 *   1. Custom/default header (jwt_auth_api_key_header option, default X-API-Key)
	 *   2. Query parameter `api_key`
	 *   3. Authorization: ApiKey <key>
	 *
	 * @return string|null Plaintext key, or null if none found.
	 */
	private function extract_api_key_from_request(): ?string {
		$header_name = get_option( 'jwt_auth_api_key_header', 'X-API-Key' );

		// 1. Custom / default header.
		$server_key = 'HTTP_' . strtoupper( str_replace( '-', '_', $header_name ) );
		if ( ! empty( $_SERVER[ $server_key ] ) ) {
			return sanitize_text_field( wp_unslash( $_SERVER[ $server_key ] ) );
		}

		// 2. Query parameter.
		// phpcs:ignore WordPress.Security.NonceVerification
		if ( ! empty( $_GET['api_key'] ) ) {
			// phpcs:ignore WordPress.Security.NonceVerification
			return sanitize_text_field( wp_unslash( $_GET['api_key'] ) );
		}

		// 3. Authorization: ApiKey <key>.
		$auth_header = '';
		if ( ! empty( $_SERVER['HTTP_AUTHORIZATION'] ) ) {
			$auth_header = wp_unslash( $_SERVER['HTTP_AUTHORIZATION'] );
		} elseif ( function_exists( 'apache_request_headers' ) ) {
			$headers = apache_request_headers();
			if ( ! empty( $headers['Authorization'] ) ) {
				$auth_header = $headers['Authorization'];
			}
		}

		if ( $auth_header && substr( $auth_header, 0, 7 ) === 'ApiKey ' ) {
			return sanitize_text_field( substr( $auth_header, 7 ) );
		}

		return null;
	}

	/**
	 * Get the current REST API route being accessed.
	 *
	 * @return string|null
	 */
	private function get_current_rest_route(): ?string {
		// phpcs:ignore WordPress.Security.NonceVerification
		if ( isset( $_SERVER['REQUEST_URI'] ) ) {
			$request_uri = wp_unslash( $_SERVER['REQUEST_URI'] );
			$rest_prefix = rest_get_url_prefix();
			$pos         = strpos( $request_uri, '/' . $rest_prefix . '/' );
			if ( false !== $pos ) {
				return substr( $request_uri, $pos + strlen( '/' . $rest_prefix ) );
			}
		}
		return null;
	}
}
