<?php
/**
 * JWT Auth Protection
 *
 * Manages API endpoint protection policies: selective auth, role-based auth,
 * full-REST disabling, and per-route blocking.
 *
 * @package JWT_Authenticator
 * @license MIT
 * @link    https://opensource.org/licenses/MIT
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Class Jwt_Auth_Protection
 *
 * Singleton that handles REST API protection modes, whitelisting,
 * route disabling, guest-access enforcement, and role-based routing.
 */
class Jwt_Auth_Protection {

	/**
	 * Singleton instance.
	 *
	 * @var Jwt_Auth_Protection|null
	 */
	private static ?Jwt_Auth_Protection $instance = null;

	/**
	 * Protection mode: 'disabled' | 'selective' | 'full'.
	 *
	 * @var string
	 */
	private string $protection_mode;

	/**
	 * Routes that always require authentication (selective mode).
	 *
	 * @var array
	 */
	private array $protected_routes;

	/**
	 * Routes always allowed without authentication.
	 *
	 * @var array
	 */
	private array $whitelisted_routes;

	/**
	 * Routes to completely disable (404).
	 *
	 * @var array
	 */
	private array $disabled_endpoints;

	/**
	 * Whether to disable REST for guests.
	 *
	 * @var bool
	 */
	private bool $disable_rest_for_guests;

	/**
	 * Whether to disable REST API for everyone except admins.
	 *
	 * @var bool
	 */
	private bool $disable_rest_api;

	/**
	 * Role → allowed route patterns map.
	 *
	 * @var array
	 */
	private array $role_route_map;

	/**
	 * Private constructor — use get_instance().
	 */
	private function __construct() {
		$this->load_settings();
	}

	/**
	 * Returns the singleton instance.
	 *
	 * @return Jwt_Auth_Protection
	 */
	public static function get_instance(): Jwt_Auth_Protection {
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
		$this->protection_mode        = get_option( 'jwt_auth_protection_mode', 'disabled' );
		$this->protected_routes       = $this->decode_json_option( 'jwt_auth_protected_routes', [] );
		$this->disabled_endpoints     = $this->decode_json_option( 'jwt_auth_disabled_endpoints', [] );
		$this->role_route_map         = $this->decode_json_option( 'jwt_auth_role_route_map', [] );
		$this->disable_rest_for_guests = (bool) get_option( 'jwt_auth_disable_rest_for_guests', false );
		$this->disable_rest_api        = (bool) get_option( 'jwt_auth_disable_rest_api', false );

		// Merge stored whitelist with built-in defaults.
		$stored_whitelist         = $this->decode_json_option( 'jwt_auth_whitelisted_routes', [] );
		$this->whitelisted_routes = array_unique(
			array_merge( $this->get_default_whitelist(), $stored_whitelist )
		);
	}

	/**
	 * Decode a JSON-encoded WordPress option into an array.
	 *
	 * @param string $option_name Option name.
	 * @param array  $default     Default value.
	 * @return array
	 */
	private function decode_json_option( string $option_name, array $default ): array {
		$raw = get_option( $option_name, '' );
		if ( empty( $raw ) ) {
			return $default;
		}
		$decoded = json_decode( $raw, true );
		return is_array( $decoded ) ? $decoded : $default;
	}

	/**
	 * Register WordPress hooks.
	 *
	 * @return void
	 */
	public function register_hooks(): void {
		add_filter( 'rest_pre_dispatch', [ $this, 'check_protection' ], 1, 3 );
		add_filter( 'rest_authentication_errors', [ $this, 'check_guest_access' ], 20 );
		add_action( 'rest_api_init', [ $this, 'register_admin_routes' ] );
	}

	/**
	 * REST pre-dispatch filter: enforce protection policies.
	 *
	 * @param mixed           $result  Current dispatch result.
	 * @param WP_REST_Server  $server  REST server.
	 * @param WP_REST_Request $request Current request.
	 * @return mixed WP_Error on denial, original $result otherwise.
	 */
	public function check_protection( $result, WP_REST_Server $server, WP_REST_Request $request ) {
		// If already an error, pass it through.
		if ( is_wp_error( $result ) ) {
			return $result;
		}

		$route   = $request->get_route();
		$user_id = get_current_user_id();

		// --- Global REST API disable (non-admins only) ---
		if ( $this->disable_rest_api ) {
			if ( ! current_user_can( 'manage_options' ) ) {
				return new WP_Error(
					'rest_disabled',
					__( 'REST API is disabled.', 'jwt-authenticator' ),
					[ 'status' => 404 ]
				);
			}
		}

		// --- Completely disabled endpoints ---
		if ( $this->is_route_disabled( $route ) ) {
			return new WP_Error(
				'rest_endpoint_disabled',
				__( 'This endpoint is disabled.', 'jwt-authenticator' ),
				[ 'status' => 404 ]
			);
		}

		// --- Whitelisted routes bypass auth checks ---
		if ( $this->is_route_whitelisted( $route ) ) {
			return $result;
		}

		// --- Protection-mode checks ---
		$auth_required = false;

		if ( 'full' === $this->protection_mode ) {
			$auth_required = true;
		} elseif ( 'selective' === $this->protection_mode ) {
			$auth_required = $this->is_route_protected( $route );
		}

		if ( $auth_required && $user_id === 0 ) {
			return new WP_Error(
				'rest_not_logged_in',
				__( 'Authentication is required to access this endpoint.', 'jwt-authenticator' ),
				[ 'status' => 401 ]
			);
		}

		// --- Role-based route permission (only for authenticated users) ---
		if ( $user_id > 0 && ! empty( $this->role_route_map ) ) {
			if ( ! $this->user_has_route_permission( $user_id, $route ) ) {
				return new WP_Error(
					'rest_forbidden',
					__( 'Your role does not have permission to access this endpoint.', 'jwt-authenticator' ),
					[ 'status' => 403 ]
				);
			}
		}

		return $result;
	}

	/**
	 * REST authentication-errors filter: enforce guest access restriction.
	 *
	 * @param WP_Error|null|bool $error Existing auth error.
	 * @return WP_Error|null|bool
	 */
	public function check_guest_access( $error ) {
		// Another auth method already set an error — respect it.
		if ( ! empty( $error ) ) {
			return $error;
		}

		if ( ! $this->disable_rest_for_guests ) {
			return $error;
		}

		if ( get_current_user_id() > 0 ) {
			return $error;
		}

		// Determine the current REST route.
		$route = $this->get_current_rest_route();

		if ( null !== $route && $this->is_route_whitelisted( $route ) ) {
			return $error;
		}

		return new WP_Error(
			'rest_not_logged_in',
			__( 'Authentication required.', 'jwt-authenticator' ),
			[ 'status' => 401 ]
		);
	}

	/**
	 * Check whether a route matches the protected-routes list.
	 *
	 * @param string $route Current REST route.
	 * @return bool
	 */
	public function is_route_protected( string $route ): bool {
		return $this->match_route_patterns( $route, $this->protected_routes );
	}

	/**
	 * Check whether a route is whitelisted (always allowed).
	 *
	 * @param string $route Current REST route.
	 * @return bool
	 */
	public function is_route_whitelisted( string $route ): bool {
		return $this->match_route_patterns( $route, $this->whitelisted_routes );
	}

	/**
	 * Check whether a route is disabled.
	 *
	 * @param string $route Current REST route.
	 * @return bool
	 */
	public function is_route_disabled( string $route ): bool {
		return $this->match_route_patterns( $route, $this->disabled_endpoints );
	}

	/**
	 * Check whether the given user has permission to access a route,
	 * according to the role-route map.
	 *
	 * When no role in the map covers the route at all, access is allowed
	 * (the map only restricts routes that are explicitly listed).
	 *
	 * @param int    $user_id WordPress user ID.
	 * @param string $route   Current REST route.
	 * @return bool
	 */
	public function user_has_route_permission( int $user_id, string $route ): bool {
		if ( empty( $this->role_route_map ) ) {
			return true;
		}

		// Collect all route patterns that appear in the map across any role.
		$all_mapped_patterns = [];
		foreach ( $this->role_route_map as $patterns ) {
			if ( is_array( $patterns ) ) {
				$all_mapped_patterns = array_merge( $all_mapped_patterns, $patterns );
			}
		}

		// If this route is not restricted by the map at all, allow it.
		if ( ! $this->match_route_patterns( $route, $all_mapped_patterns ) ) {
			return true;
		}

		$user = get_userdata( $user_id );
		if ( ! $user ) {
			return false;
		}

		foreach ( $user->roles as $role ) {
			if ( isset( $this->role_route_map[ $role ] ) && is_array( $this->role_route_map[ $role ] ) ) {
				if ( $this->match_route_patterns( $route, $this->role_route_map[ $role ] ) ) {
					return true;
				}
			}
		}

		// Admins always have access.
		if ( current_user_can( 'manage_options' ) ) {
			return true;
		}

		return false;
	}

	/**
	 * Returns the default list of always-whitelisted routes.
	 *
	 * @return array
	 */
	public function get_default_whitelist(): array {
		return [
			'/jwt-auth/v1/token',
			'/jwt-auth/v1/token/validate',
			'/jwt-auth/v1/token/refresh',
			'/jwt-auth/v1/auth/firebase/*',
			'/jwt-auth/v1/auth/oauth/*',
			'/oauth/*',
		];
	}

	// -------------------------------------------------------------------------
	// Admin REST routes
	// -------------------------------------------------------------------------

	/**
	 * Register admin REST routes for protection settings.
	 *
	 * @return void
	 */
	public function register_admin_routes(): void {
		register_rest_route(
			'jwt-auth/v1',
			'/admin/protection',
			[
				[
					'methods'             => WP_REST_Server::READABLE,
					'callback'            => [ $this, 'get_protection_settings' ],
					'permission_callback' => [ $this, 'admin_permission_check' ],
				],
				[
					'methods'             => WP_REST_Server::CREATABLE,
					'callback'            => [ $this, 'update_protection_settings' ],
					'permission_callback' => [ $this, 'admin_permission_check' ],
					'args'                => $this->get_protection_route_args(),
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
				__( 'You do not have permission to manage protection settings.', 'jwt-authenticator' ),
				[ 'status' => 403 ]
			);
		}
		return true;
	}

	/**
	 * GET /jwt-auth/v1/admin/protection — return current settings.
	 *
	 * @return WP_REST_Response
	 */
	public function get_protection_settings(): WP_REST_Response {
		return new WP_REST_Response(
			[
				'protection_mode'          => get_option( 'jwt_auth_protection_mode', 'disabled' ),
				'protected_routes'         => $this->decode_json_option( 'jwt_auth_protected_routes', [] ),
				'whitelisted_routes'       => $this->decode_json_option( 'jwt_auth_whitelisted_routes', [] ),
				'disable_rest_for_guests'  => (bool) get_option( 'jwt_auth_disable_rest_for_guests', false ),
				'disabled_endpoints'       => $this->decode_json_option( 'jwt_auth_disabled_endpoints', [] ),
				'role_route_map'           => $this->decode_json_option( 'jwt_auth_role_route_map', [] ),
				'disable_rest_api'         => (bool) get_option( 'jwt_auth_disable_rest_api', false ),
				'default_whitelist'        => $this->get_default_whitelist(),
			],
			200
		);
	}

	/**
	 * POST /jwt-auth/v1/admin/protection — update settings.
	 *
	 * @param WP_REST_Request $request Incoming request.
	 * @return WP_REST_Response
	 */
	public function update_protection_settings( WP_REST_Request $request ): WP_REST_Response {
		$updated = [];

		if ( $request->has_param( 'protection_mode' ) ) {
			$mode = sanitize_text_field( $request->get_param( 'protection_mode' ) );
			update_option( 'jwt_auth_protection_mode', $mode );
			$updated['protection_mode'] = $mode;
		}

		foreach ( [ 'protected_routes', 'whitelisted_routes', 'disabled_endpoints' ] as $key ) {
			if ( $request->has_param( $key ) ) {
				$value = $request->get_param( $key );
				update_option( 'jwt_auth_' . $key, wp_json_encode( array_values( (array) $value ) ) );
				$updated[ $key ] = $value;
			}
		}

		if ( $request->has_param( 'role_route_map' ) ) {
			$map = $request->get_param( 'role_route_map' );
			update_option( 'jwt_auth_role_route_map', wp_json_encode( (array) $map ) );
			$updated['role_route_map'] = $map;
		}

		foreach ( [ 'disable_rest_for_guests', 'disable_rest_api' ] as $bool_key ) {
			if ( $request->has_param( $bool_key ) ) {
				$value = (bool) $request->get_param( $bool_key );
				update_option( 'jwt_auth_' . $bool_key, $value );
				$updated[ $bool_key ] = $value;
			}
		}

		// Reload settings for the response.
		$this->load_settings();

		return new WP_REST_Response(
			[
				'success' => true,
				'updated' => $updated,
			],
			200
		);
	}

	/**
	 * REST route argument schema for the POST protection endpoint.
	 *
	 * @return array
	 */
	private function get_protection_route_args(): array {
		return [
			'protection_mode'         => [
				'type'     => 'string',
				'enum'     => [ 'disabled', 'selective', 'full' ],
				'required' => false,
			],
			'protected_routes'        => [
				'type'     => 'array',
				'items'    => [ 'type' => 'string' ],
				'required' => false,
			],
			'whitelisted_routes'      => [
				'type'     => 'array',
				'items'    => [ 'type' => 'string' ],
				'required' => false,
			],
			'disabled_endpoints'      => [
				'type'     => 'array',
				'items'    => [ 'type' => 'string' ],
				'required' => false,
			],
			'role_route_map'          => [
				'type'     => 'object',
				'required' => false,
			],
			'disable_rest_for_guests' => [
				'type'     => 'boolean',
				'required' => false,
			],
			'disable_rest_api'        => [
				'type'     => 'boolean',
				'required' => false,
			],
		];
	}

	// -------------------------------------------------------------------------
	// Helpers
	// -------------------------------------------------------------------------

	/**
	 * Match a route against an array of patterns.
	 * Patterns may contain '*' as a wildcard (treated as '.*' in regex).
	 *
	 * @param string $route    REST route string.
	 * @param array  $patterns Array of route patterns.
	 * @return bool
	 */
	private function match_route_patterns( string $route, array $patterns ): bool {
		foreach ( $patterns as $pattern ) {
			if ( ! is_string( $pattern ) || '' === $pattern ) {
				continue;
			}

			// Exact match (no wildcard).
			if ( false === strpos( $pattern, '*' ) ) {
				if ( $route === $pattern ) {
					return true;
				}
				continue;
			}

			// Wildcard match: convert '*' to '.*' and anchor.
			$regex = '#^' . str_replace( '\*', '.*', preg_quote( $pattern, '#' ) ) . '$#';
			if ( preg_match( $regex, $route ) ) {
				return true;
			}
		}
		return false;
	}

	/**
	 * Retrieve the current REST route from the global WP_REST_Request, if any.
	 *
	 * @return string|null
	 */
	private function get_current_rest_route(): ?string {
		$request = $GLOBALS['wp_rest_server'] ?? null;
		if ( $request && method_exists( $request, 'get_raw_data' ) ) {
			// Use the server's route via the global $wp object.
			global $wp;
			if ( isset( $wp->query_vars['rest_route'] ) ) {
				return '/' . ltrim( $wp->query_vars['rest_route'], '/' );
			}
		}
		return null;
	}
}
