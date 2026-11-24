<?php
/**
 * JWT Authenticator — OAuth 2.0 Server & Client
 *
 * Implements a minimal OAuth 2.0 server (password, refresh_token,
 * client_credentials grant types) and stubs for OAuth 2.0 client
 * flows (Google, GitHub).
 *
 * @package    JWT_Authenticator
 * @subpackage JWT_Authenticator/includes
 * @license    MIT https://opensource.org/licenses/MIT
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Class Jwt_Auth_OAuth
 *
 * Singleton. Register hooks via register_hooks().
 */
class Jwt_Auth_OAuth {

	/**
	 * Singleton instance.
	 *
	 * @var Jwt_Auth_OAuth|null
	 */
	private static ?Jwt_Auth_OAuth $instance = null;

	/**
	 * Private constructor — use get_instance().
	 */
	private function __construct() {}

	/**
	 * Returns the singleton instance.
	 *
	 * @return Jwt_Auth_OAuth
	 */
	public static function get_instance(): Jwt_Auth_OAuth {
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
		add_action( 'rest_api_init', [ $this, 'register_routes' ] );
	}

	// -------------------------------------------------------------------------
	// REST route registration
	// -------------------------------------------------------------------------

	/**
	 * Register OAuth 2.0 REST routes.
	 *
	 * @return void
	 */
	public function register_routes(): void {
		if ( ! $this->is_enabled() ) {
			return;
		}

		$namespace = 'jwt-auth/v1';

		register_rest_route(
			$namespace,
			'/oauth/token',
			[
				'methods'             => WP_REST_Server::CREATABLE,
				'callback'            => [ $this, 'handle_token_request' ],
				'permission_callback' => '__return_true',
				'args'                => [
					'grant_type'    => [
						'required' => true,
						'type'     => 'string',
						'enum'     => [ 'password', 'refresh_token', 'client_credentials' ],
					],
					// password grant.
					'username'      => [ 'type' => 'string', 'default' => '' ],
					'password'      => [ 'type' => 'string', 'default' => '' ],
					// refresh_token grant.
					'refresh_token' => [ 'type' => 'string', 'default' => '' ],
					// client_credentials grant.
					'client_id'     => [ 'type' => 'string', 'default' => '' ],
					'client_secret' => [ 'type' => 'string', 'default' => '' ],
					'scope'         => [ 'type' => 'string', 'default' => '' ],
				],
			]
		);

		register_rest_route(
			$namespace,
			'/oauth/authorize',
			[
				'methods'             => WP_REST_Server::READABLE,
				'callback'            => [ $this, 'handle_authorize_request' ],
				'permission_callback' => '__return_true',
			]
		);

		register_rest_route(
			$namespace,
			'/oauth/revoke',
			[
				'methods'             => WP_REST_Server::CREATABLE,
				'callback'            => [ $this, 'handle_revoke_request' ],
				'permission_callback' => '__return_true',
				'args'                => [
					'token' => [
						'required' => true,
						'type'     => 'string',
					],
				],
			]
		);
	}

	// -------------------------------------------------------------------------
	// REST callbacks
	// -------------------------------------------------------------------------

	/**
	 * Handle POST /oauth/token — issue tokens for supported grant types.
	 *
	 * @param WP_REST_Request $request Request object.
	 * @return array|WP_Error OAuth 2.0 formatted response or error.
	 */
	public function handle_token_request( WP_REST_Request $request ) {
		$grant_type = $request->get_param( 'grant_type' );

		switch ( $grant_type ) {
			case 'password':
				return $this->handle_password_grant( $request );

			case 'refresh_token':
				return $this->handle_refresh_token_grant( $request );

			case 'client_credentials':
				return $this->handle_client_credentials_grant( $request );

			default:
				return new WP_Error(
					'unsupported_grant_type',
					__( 'The grant type is not supported by the authorization server.', 'jwt-authenticator' ),
					[ 'status' => 400 ]
				);
		}
	}

	/**
	 * Handle GET /oauth/authorize — authorization endpoint (redirect flow).
	 *
	 * @param WP_REST_Request $request Request object.
	 * @return WP_REST_Response|WP_Error
	 */
	public function handle_authorize_request( WP_REST_Request $request ) {
		// Minimal implementation — redirects to login if not authenticated.
		if ( ! is_user_logged_in() ) {
			return new WP_Error(
				'login_required',
				__( 'User authentication is required.', 'jwt-authenticator' ),
				[ 'status' => 401 ]
			);
		}

		$client_id    = sanitize_text_field( $request->get_param( 'client_id' ) ?? '' );
		$redirect_uri = esc_url_raw( $request->get_param( 'redirect_uri' ) ?? '' );
		$state        = sanitize_text_field( $request->get_param( 'state' ) ?? '' );

		if ( empty( $client_id ) || empty( $redirect_uri ) ) {
			return new WP_Error(
				'invalid_request',
				__( 'client_id and redirect_uri are required.', 'jwt-authenticator' ),
				[ 'status' => 400 ]
			);
		}

		// Generate a temporary authorization code.
		$code = bin2hex( random_bytes( 16 ) );
		set_transient( 'jwt_oauth_code_' . $code, [
			'user_id'      => get_current_user_id(),
			'client_id'    => $client_id,
			'redirect_uri' => $redirect_uri,
		], 5 * MINUTE_IN_SECONDS );

		$redirect = add_query_arg(
			array_filter( [ 'code' => $code, 'state' => $state ] ),
			$redirect_uri
		);

		return rest_ensure_response( [ 'redirect' => $redirect ] );
	}

	/**
	 * Handle POST /oauth/revoke — revoke an access token.
	 *
	 * @param WP_REST_Request $request Request object.
	 * @return WP_REST_Response|WP_Error
	 */
	public function handle_revoke_request( WP_REST_Request $request ) {
		$token = $request->get_param( 'token' );

		if ( class_exists( 'Jwt_Auth_Token_Manager' ) ) {
			$manager = Jwt_Auth_Token_Manager::get_instance();
			if ( method_exists( $manager, 'revoke_token' ) ) {
				$result = $manager->revoke_token( $token );
				if ( is_wp_error( $result ) ) {
					return $result;
				}
			}
		}

		// Per RFC 7009 §2.2, always return 200 even if the token was not found.
		return rest_ensure_response( [ 'revoked' => true ] );
	}

	// -------------------------------------------------------------------------
	// Grant handlers (private)
	// -------------------------------------------------------------------------

	/**
	 * Process a password grant.
	 *
	 * @param WP_REST_Request $request Request object.
	 * @return array|WP_Error
	 */
	private function handle_password_grant( WP_REST_Request $request ) {
		$username = $request->get_param( 'username' );
		$password = $request->get_param( 'password' );

		if ( empty( $username ) || empty( $password ) ) {
			return new WP_Error(
				'invalid_request',
				__( 'username and password are required for the password grant.', 'jwt-authenticator' ),
				[ 'status' => 400 ]
			);
		}

		// Accept email or username.
		$user = is_email( $username )
			? get_user_by( 'email', $username )
			: get_user_by( 'login', $username );

		if ( ! $user || ! wp_check_password( $password, $user->user_pass, $user->ID ) ) {
			return new WP_Error(
				'invalid_grant',
				__( 'The provided credentials are invalid.', 'jwt-authenticator' ),
				[ 'status' => 401 ]
			);
		}

		return $this->build_token_response( $user->ID, $request->get_param( 'scope' ) );
	}

	/**
	 * Process a refresh_token grant.
	 *
	 * @param WP_REST_Request $request Request object.
	 * @return array|WP_Error
	 */
	private function handle_refresh_token_grant( WP_REST_Request $request ) {
		$refresh_token = $request->get_param( 'refresh_token' );

		if ( empty( $refresh_token ) ) {
			return new WP_Error(
				'invalid_request',
				__( 'refresh_token is required.', 'jwt-authenticator' ),
				[ 'status' => 400 ]
			);
		}

		if ( ! class_exists( 'Jwt_Auth_Token_Manager' ) ) {
			return new WP_Error(
				'server_error',
				__( 'Token manager is not available.', 'jwt-authenticator' ),
				[ 'status' => 500 ]
			);
		}

		$manager = Jwt_Auth_Token_Manager::get_instance();
		if ( ! method_exists( $manager, 'validate_refresh_token' ) ) {
			return new WP_Error(
				'server_error',
				__( 'Refresh token validation is not available.', 'jwt-authenticator' ),
				[ 'status' => 500 ]
			);
		}

		$payload = $manager->validate_refresh_token( $refresh_token );
		if ( is_wp_error( $payload ) ) {
			return new WP_Error(
				'invalid_grant',
				__( 'The refresh token is invalid or has expired.', 'jwt-authenticator' ),
				[ 'status' => 401 ]
			);
		}

		$user_id = isset( $payload->sub ) ? (int) $payload->sub : 0;
		if ( ! $user_id ) {
			return new WP_Error(
				'invalid_grant',
				__( 'Cannot resolve user from refresh token.', 'jwt-authenticator' ),
				[ 'status' => 401 ]
			);
		}

		return $this->build_token_response( $user_id, '' );
	}

	/**
	 * Process a client_credentials grant.
	 *
	 * @param WP_REST_Request $request Request object.
	 * @return array|WP_Error
	 */
	private function handle_client_credentials_grant( WP_REST_Request $request ) {
		$client_id     = $request->get_param( 'client_id' );
		$client_secret = $request->get_param( 'client_secret' );

		if ( empty( $client_id ) || empty( $client_secret ) ) {
			return new WP_Error(
				'invalid_request',
				__( 'client_id and client_secret are required.', 'jwt-authenticator' ),
				[ 'status' => 400 ]
			);
		}

		if ( ! $this->validate_client( $client_id, $client_secret ) ) {
			return new WP_Error(
				'invalid_client',
				__( 'Client authentication failed.', 'jwt-authenticator' ),
				[ 'status' => 401 ]
			);
		}

		// Use the configured API key user (default: admin 1) for machine-to-machine tokens.
		$user_id = (int) get_option( 'jwt_auth_api_key_user_id', 1 );

		return $this->build_token_response( $user_id, $request->get_param( 'scope' ), false );
	}

	// -------------------------------------------------------------------------
	// Public helpers
	// -------------------------------------------------------------------------

	/**
	 * Validate a client_id / client_secret pair against registered OAuth clients.
	 *
	 * @param string $client_id     The OAuth client ID.
	 * @param string $client_secret The plaintext client secret.
	 * @return bool True if the client is valid.
	 */
	public function validate_client( string $client_id, string $client_secret ): bool {
		$clients = $this->get_registered_clients();

		foreach ( $clients as $client ) {
			if (
				isset( $client['client_id'], $client['client_secret_hash'] ) &&
				$client['client_id'] === $client_id &&
				hash_equals( $client['client_secret_hash'], hash( 'sha256', $client_secret ) )
			) {
				return true;
			}
		}

		return false;
	}

	/**
	 * Get or register an OAuth client.
	 *
	 * If a client with the given client_id already exists, return it.
	 * Otherwise create a new client entry and persist it.
	 *
	 * @param string $client_id    OAuth client identifier.
	 * @param string $redirect_uri Allowed redirect URI for the client.
	 * @return array Client record (includes plaintext secret on first creation).
	 */
	public function get_or_register_client( string $client_id, string $redirect_uri ): array {
		$clients = $this->get_registered_clients();

		foreach ( $clients as $client ) {
			if ( isset( $client['client_id'] ) && $client['client_id'] === $client_id ) {
				// Return existing — plaintext secret is not stored; omit from response.
				return array_diff_key( $client, array_flip( [ 'client_secret_hash' ] ) );
			}
		}

		// Register a new client.
		$secret        = bin2hex( random_bytes( 32 ) );
		$secret_hash   = hash( 'sha256', $secret );
		$new_client    = [
			'client_id'          => $client_id,
			'client_secret_hash' => $secret_hash,
			'redirect_uri'       => $redirect_uri,
			'grants'             => [ 'authorization_code', 'refresh_token' ],
			'created_at'         => current_time( 'mysql', true ),
		];

		$clients[] = $new_client;
		update_option( 'jwt_auth_oauth_clients', wp_json_encode( $clients ), false );

		// Return record with plaintext secret — only available at creation time.
		return [
			'client_id'     => $client_id,
			'client_secret' => $secret, // Returned ONCE.
			'redirect_uri'  => $redirect_uri,
			'grants'        => $new_client['grants'],
		];
	}

	// -------------------------------------------------------------------------
	// Private helpers
	// -------------------------------------------------------------------------

	/**
	 * Check whether the OAuth server is enabled.
	 *
	 * @return bool
	 */
	private function is_enabled(): bool {
		return (bool) get_option( 'jwt_auth_oauth_enabled', true );
	}

	/**
	 * Get the array of registered OAuth clients from options.
	 *
	 * @return array
	 */
	private function get_registered_clients(): array {
		$raw = get_option( 'jwt_auth_oauth_clients', '[]' );
		$parsed = json_decode( $raw, true );
		return is_array( $parsed ) ? $parsed : [];
	}

	/**
	 * Build an OAuth 2.0 token response array.
	 *
	 * @param int    $user_id       WordPress user ID.
	 * @param string $scope         Requested scope string.
	 * @param bool   $with_refresh  Whether to include a refresh token.
	 * @return array|WP_Error
	 */
	private function build_token_response( int $user_id, string $scope = '', bool $with_refresh = true ) {
		if ( ! class_exists( 'Jwt_Auth_Token_Manager' ) ) {
			return new WP_Error(
				'server_error',
				__( 'Token manager is not available.', 'jwt-authenticator' ),
				[ 'status' => 500 ]
			);
		}

		$manager = Jwt_Auth_Token_Manager::get_instance();
		$user    = get_user_by( 'id', $user_id );

		if ( ! $user ) {
			return new WP_Error(
				'invalid_grant',
				__( 'User not found.', 'jwt-authenticator' ),
				[ 'status' => 401 ]
			);
		}

		if ( method_exists( $manager, 'generate_token_pair' ) ) {
			$pair = $manager->generate_token_pair( $user );
		} elseif ( method_exists( $manager, 'generate_token' ) ) {
			$pair = [ 'access_token' => $manager->generate_token( $user ), 'refresh_token' => null ];
		} else {
			return new WP_Error(
				'server_error',
				__( 'Token generation is not available.', 'jwt-authenticator' ),
				[ 'status' => 500 ]
			);
		}

		if ( is_wp_error( $pair ) ) {
			return $pair;
		}

		$expires_in = (int) get_option( 'jwt_auth_expire', 7 * DAY_IN_SECONDS );

		$response = [
			'access_token' => $pair['access_token'] ?? '',
			'token_type'   => 'Bearer',
			'expires_in'   => $expires_in,
			'scope'        => $scope,
		];

		if ( $with_refresh && ! empty( $pair['refresh_token'] ) ) {
			$response['refresh_token'] = $pair['refresh_token'];
		}

		return $response;
	}
}
