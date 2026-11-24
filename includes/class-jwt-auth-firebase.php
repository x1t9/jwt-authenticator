<?php
/**
 * Firebase Authentication Integration
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
 * Class Jwt_Auth_Firebase
 *
 * Handles Firebase Authentication token verification and WordPress user management.
 */
class Jwt_Auth_Firebase {

	/**
	 * Singleton instance.
	 *
	 * @var Jwt_Auth_Firebase|null
	 */
	private static ?Jwt_Auth_Firebase $instance = null;

	/**
	 * Firebase public keys endpoint.
	 *
	 * @var string
	 */
	private const FIREBASE_PUBLIC_KEYS_URL = 'https://www.googleapis.com/robot/v1/metadata/x509/securetoken@system.gserviceaccount.com';

	/**
	 * Get singleton instance.
	 *
	 * @return Jwt_Auth_Firebase
	 */
	public static function get_instance(): Jwt_Auth_Firebase {
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
		add_action( 'rest_api_init', [ $this, 'register_routes' ] );
		add_filter( 'authenticate', [ $this, 'enforce_login_mode' ], 30, 3 );
		add_filter( 'login_redirect', [ $this, 'custom_login_redirect' ], 10, 3 );
		add_filter( 'logout_redirect', [ $this, 'custom_logout_redirect' ], 10, 3 );
	}

	// -------------------------------------------------------------------------
	// REST Route Registration
	// -------------------------------------------------------------------------

	/**
	 * Register REST API routes.
	 *
	 * @return void
	 */
	public function register_routes(): void {
		register_rest_route(
			'jwt-auth/v1',
			'/auth/firebase',
			[
				'methods'             => WP_REST_Server::CREATABLE,
				'callback'            => [ $this, 'handle_firebase_auth_endpoint' ],
				'permission_callback' => '__return_true',
				'args'                => [
					'firebase_token' => [
						'required'          => true,
						'type'              => 'string',
						'sanitize_callback' => 'sanitize_text_field',
					],
					'provider'       => [
						'required'          => false,
						'type'              => 'string',
						'default'           => 'firebase',
						'sanitize_callback' => 'sanitize_text_field',
					],
				],
			]
		);

		register_rest_route(
			'jwt-auth/v1',
			'/auth/firebase/session',
			[
				'methods'             => WP_REST_Server::CREATABLE,
				'callback'            => [ $this, 'handle_firebase_session_endpoint' ],
				'permission_callback' => '__return_true',
				'args'                => [
					'firebase_token' => [
						'required'          => true,
						'type'              => 'string',
						'sanitize_callback' => 'sanitize_text_field',
					],
				],
			]
		);

		register_rest_route(
			'jwt-auth/v1',
			'/auth/firebase/config',
			[
				'methods'             => WP_REST_Server::READABLE,
				'callback'            => [ $this, 'handle_firebase_config_endpoint' ],
				'permission_callback' => '__return_true',
			]
		);
	}

	// -------------------------------------------------------------------------
	// REST Endpoint Handlers
	// -------------------------------------------------------------------------

	/**
	 * Handle POST /jwt-auth/v1/auth/firebase
	 *
	 * @param WP_REST_Request $request Incoming request.
	 * @return array|WP_Error
	 */
	public function handle_firebase_auth_endpoint( WP_REST_Request $request ) {
		if ( ! $this->is_enabled() ) {
			return new WP_Error( 'firebase_disabled', __( 'Firebase authentication is not enabled.', 'jwt-authenticator' ), [ 'status' => 403 ] );
		}

		$firebase_token = $request->get_param( 'firebase_token' );
		$provider       = $request->get_param( 'provider' ) ?? 'firebase';

		/**
		 * Fires before a Firebase ID token is verified.
		 *
		 * @param string $firebase_token The raw Firebase ID token.
		 */
		do_action( 'jwt_auth_firebase_before_token_verify', $firebase_token );

		$payload = $this->verify_firebase_token( $firebase_token );
		if ( is_wp_error( $payload ) ) {
			return $payload;
		}

		$user_result = $this->get_or_create_wp_user( $payload, $provider );
		if ( is_wp_error( $user_result ) ) {
			return $user_result;
		}

		$user_id    = $user_result['user_id'];
		$is_new     = $user_result['is_new_user'];
		$wp_user    = get_userdata( $user_id );

		if ( ! $wp_user ) {
			return new WP_Error( 'firebase_user_fetch_failed', __( 'Failed to retrieve WordPress user.', 'jwt-authenticator' ), [ 'status' => 500 ] );
		}

		// Generate JWT token pair.
		$token_manager = Jwt_Auth_Token_Manager::get_instance();
		$token_pair    = $token_manager->generate_token_pair( $wp_user );

		if ( is_wp_error( $token_pair ) ) {
			return $token_pair;
		}

		$user_data = [
			'token'              => $token_pair['access_token'] ?? '',
			'refresh_token'      => $token_pair['refresh_token'] ?? '',
			'user_email'         => $wp_user->user_email,
			'user_nicename'      => $wp_user->user_nicename,
			'user_display_name'  => $wp_user->display_name,
			'firebase_uid'       => $payload['sub'] ?? '',
			'is_new_user'        => $is_new,
		];

		/**
		 * Filters the user data returned from Firebase auth.
		 *
		 * @param array $user_data     The assembled response data.
		 * @param array $payload Firebase ID token payload.
		 */
		return apply_filters( 'jwt_auth_firebase_user_data', $user_data, $payload );
	}

	/**
	 * Handle POST /jwt-auth/v1/auth/firebase/session
	 *
	 * Creates a WordPress cookie-based login session from a Firebase JWT.
	 *
	 * @param WP_REST_Request $request Incoming request.
	 * @return array|WP_Error
	 */
	public function handle_firebase_session_endpoint( WP_REST_Request $request ) {
		if ( ! $this->is_enabled() ) {
			return new WP_Error( 'firebase_disabled', __( 'Firebase authentication is not enabled.', 'jwt-authenticator' ), [ 'status' => 403 ] );
		}

		$firebase_token = $request->get_param( 'firebase_token' );

		do_action( 'jwt_auth_firebase_before_token_verify', $firebase_token );

		$payload = $this->verify_firebase_token( $firebase_token );
		if ( is_wp_error( $payload ) ) {
			return $payload;
		}

		$user_result = $this->get_or_create_wp_user( $payload, 'firebase' );
		if ( is_wp_error( $user_result ) ) {
			return $user_result;
		}

		$user_id = $user_result['user_id'];
		wp_set_auth_cookie( $user_id, true );

		return [
			'success'      => true,
			'user_id'      => $user_id,
			'firebase_uid' => $payload['sub'] ?? '',
		];
	}

	/**
	 * Handle GET /jwt-auth/v1/auth/firebase/config
	 *
	 * Returns public Firebase configuration for the front-end SDK.
	 *
	 * @return array
	 */
	public function handle_firebase_config_endpoint(): array {
		$project_id        = get_option( 'jwt_auth_firebase_project_id', '' );
		$web_api_key       = get_option( 'jwt_auth_firebase_web_api_key', '' );
		$enabled_providers = json_decode( get_option( 'jwt_auth_firebase_enabled_providers', '[]' ), true );

		if ( ! is_array( $enabled_providers ) ) {
			$enabled_providers = [];
		}

		return [
			'project_id'        => $project_id,
			'web_api_key'       => $web_api_key,
			'enabled_providers' => $enabled_providers,
			'auth_domain'       => $project_id ? "{$project_id}.firebaseapp.com" : '',
		];
	}

	// -------------------------------------------------------------------------
	// Core: Token Verification
	// -------------------------------------------------------------------------

	/**
	 * Verify a Firebase ID token.
	 *
	 * @param string $id_token Firebase ID token (JWT string).
	 * @return array|WP_Error Decoded payload on success, WP_Error on failure.
	 */
	public function verify_firebase_token( string $id_token ) {
		$project_id = get_option( 'jwt_auth_firebase_project_id', '' );
		if ( empty( $project_id ) ) {
			return new WP_Error( 'firebase_no_project_id', __( 'Firebase project ID is not configured.', 'jwt-authenticator' ), [ 'status' => 500 ] );
		}

		// Split the JWT into its three parts.
		$parts = explode( '.', $id_token );
		if ( 3 !== count( $parts ) ) {
			return new WP_Error( 'firebase_invalid_token', __( 'Invalid Firebase ID token format.', 'jwt-authenticator' ), [ 'status' => 401 ] );
		}

		[ $header_b64, $payload_b64, $signature_b64 ] = $parts;

		// Decode header.
		$header = json_decode( $this->base64url_decode( $header_b64 ), true );
		if ( ! is_array( $header ) || empty( $header['kid'] ) ) {
			return new WP_Error( 'firebase_invalid_header', __( 'Firebase token header is invalid or missing kid.', 'jwt-authenticator' ), [ 'status' => 401 ] );
		}

		$kid = $header['kid'];

		// Fetch and cache public keys.
		$public_keys = $this->get_firebase_public_keys();
		if ( is_wp_error( $public_keys ) ) {
			return $public_keys;
		}

		if ( ! isset( $public_keys[ $kid ] ) ) {
			return new WP_Error( 'firebase_unknown_kid', __( 'Firebase public key not found for the given kid.', 'jwt-authenticator' ), [ 'status' => 401 ] );
		}

		$certificate = $public_keys[ $kid ];

		// Extract public key from X.509 PEM certificate.
		$public_key_resource = openssl_pkey_get_public( $certificate );
		if ( false === $public_key_resource ) {
			return new WP_Error( 'firebase_key_parse_error', __( 'Failed to parse Firebase public key certificate.', 'jwt-authenticator' ), [ 'status' => 500 ] );
		}

		// Verify signature.
		$signing_input = $header_b64 . '.' . $payload_b64;
		$signature     = $this->base64url_decode( $signature_b64 );

		$verify_result = openssl_verify( $signing_input, $signature, $public_key_resource, OPENSSL_ALGO_SHA256 );

		// Free the key resource (PHP 8+ frees automatically, but good practice for 7.4).
		if ( is_resource( $public_key_resource ) ) {
			openssl_free_key( $public_key_resource );
		}

		if ( 1 !== $verify_result ) {
			return new WP_Error( 'firebase_invalid_signature', __( 'Firebase token signature verification failed.', 'jwt-authenticator' ), [ 'status' => 401 ] );
		}

		// Decode payload.
		$payload = json_decode( $this->base64url_decode( $payload_b64 ), true );
		if ( ! is_array( $payload ) ) {
			return new WP_Error( 'firebase_invalid_payload', __( 'Failed to decode Firebase token payload.', 'jwt-authenticator' ), [ 'status' => 401 ] );
		}

		// Validate standard claims.
		$expected_iss = "https://securetoken.google.com/{$project_id}";
		if ( ( $payload['iss'] ?? '' ) !== $expected_iss ) {
			return new WP_Error( 'firebase_invalid_issuer', __( 'Firebase token issuer is invalid.', 'jwt-authenticator' ), [ 'status' => 401 ] );
		}

		if ( ( $payload['aud'] ?? '' ) !== $project_id ) {
			return new WP_Error( 'firebase_invalid_audience', __( 'Firebase token audience is invalid.', 'jwt-authenticator' ), [ 'status' => 401 ] );
		}

		$now = time();

		if ( isset( $payload['exp'] ) && (int) $payload['exp'] <= $now ) {
			return new WP_Error( 'firebase_token_expired', __( 'Firebase token has expired.', 'jwt-authenticator' ), [ 'status' => 401 ] );
		}

		if ( isset( $payload['iat'] ) && (int) $payload['iat'] > $now ) {
			return new WP_Error( 'firebase_token_future', __( 'Firebase token was issued in the future.', 'jwt-authenticator' ), [ 'status' => 401 ] );
		}

		if ( empty( $payload['sub'] ) ) {
			return new WP_Error( 'firebase_missing_uid', __( 'Firebase token is missing the user subject (UID).', 'jwt-authenticator' ), [ 'status' => 401 ] );
		}

		return $payload;
	}

	/**
	 * Fetch Firebase public keys, using a transient cache.
	 *
	 * @return array|WP_Error Associative array of kid => PEM certificate.
	 */
	private function get_firebase_public_keys() {
		$cached = get_transient( 'jwt_auth_firebase_public_keys' );
		if ( is_array( $cached ) && ! empty( $cached ) ) {
			return $cached;
		}

		$response = wp_remote_get(
			self::FIREBASE_PUBLIC_KEYS_URL,
			[
				'timeout' => 10,
				'headers' => [ 'Accept' => 'application/json' ],
			]
		);

		if ( is_wp_error( $response ) ) {
			return new WP_Error(
				'firebase_keys_fetch_failed',
				__( 'Failed to fetch Firebase public keys.', 'jwt-authenticator' ),
				[ 'status' => 503, 'original_error' => $response->get_error_message() ]
			);
		}

		$status_code = wp_remote_retrieve_response_code( $response );
		if ( 200 !== (int) $status_code ) {
			return new WP_Error(
				'firebase_keys_bad_response',
				/* translators: %d is the HTTP status code returned by Google's Firebase public-key endpoint. */
				sprintf( __( 'Firebase public key endpoint returned HTTP %d.', 'jwt-authenticator' ), $status_code ),
				[ 'status' => 503 ]
			);
		}

		$body = wp_remote_retrieve_body( $response );
		$keys = json_decode( $body, true );

		if ( ! is_array( $keys ) || empty( $keys ) ) {
			return new WP_Error( 'firebase_keys_parse_failed', __( 'Failed to parse Firebase public keys.', 'jwt-authenticator' ), [ 'status' => 503 ] );
		}

		// Determine cache TTL from Cache-Control header.
		$cache_control = wp_remote_retrieve_header( $response, 'cache-control' );
		$ttl           = 3600; // Default 1 hour.
		if ( $cache_control && preg_match( '/max-age=(\d+)/', $cache_control, $matches ) ) {
			$ttl = (int) $matches[1];
		}

		set_transient( 'jwt_auth_firebase_public_keys', $keys, $ttl );

		return $keys;
	}

	// -------------------------------------------------------------------------
	// Core: User Management
	// -------------------------------------------------------------------------

	/**
	 * Get or create a WordPress user from a Firebase token payload.
	 *
	 * @param array  $firebase_payload Decoded Firebase token payload.
	 * @param string $provider         Auth provider identifier.
	 * @return array|WP_Error Array with 'user_id' and 'is_new_user' keys.
	 */
	public function get_or_create_wp_user( array $firebase_payload, string $provider = 'firebase' ) {
		$uid     = $firebase_payload['sub']     ?? '';
		$email   = $firebase_payload['email']   ?? '';
		$name    = $firebase_payload['name']    ?? '';
		$picture = $firebase_payload['picture'] ?? '';

		// Try to find existing user by Firebase UID in usermeta.
		$existing_user = null;

		if ( ! empty( $uid ) ) {
			$users_by_uid = get_users(
				[
					'meta_key'   => 'firebase_uid',
					'meta_value' => $uid,
					'number'     => 1,
					'fields'     => 'ids',
				]
			);
			if ( ! empty( $users_by_uid ) ) {
				$existing_user = get_userdata( (int) $users_by_uid[0] );
			}
		}

		// Fall back to lookup by email.
		if ( ! $existing_user && ! empty( $email ) ) {
			$existing_user = get_user_by( 'email', $email );
		}

		$is_new_user = false;

		if ( ! $existing_user ) {
			// User does not exist — create if allowed.
			$auto_create = (bool) get_option( 'jwt_auth_firebase_auto_create_users', true );
			if ( ! $auto_create ) {
				return new WP_Error(
					'firebase_user_not_found',
					__( 'No WordPress account found and auto-creation is disabled.', 'jwt-authenticator' ),
					[ 'status' => 403 ]
				);
			}

			// Generate a stable username.
			if ( ! empty( $name ) ) {
				$username_base = sanitize_user( str_replace( ' ', '_', strtolower( $name ) ), true );
			} elseif ( ! empty( $email ) ) {
				$username_base = sanitize_user( strstr( $email, '@', true ), true );
			} else {
				$username_base = 'firebase_' . substr( $uid, 0, 12 );
			}

			// Ensure username uniqueness.
			$username = $username_base;
			$counter  = 1;
			while ( username_exists( $username ) ) {
				$username = $username_base . '_' . $counter;
				++$counter;
			}

			// Use placeholder email if none provided.
			if ( empty( $email ) ) {
				$email = "firebase_{$uid}@placeholder.local";
			}

			$new_user_id = wp_create_user( $username, wp_generate_password( 32, true, true ), $email );
			if ( is_wp_error( $new_user_id ) ) {
				return $new_user_id;
			}

			// Update display name if available.
			if ( ! empty( $name ) ) {
				wp_update_user(
					[
						'ID'           => $new_user_id,
						'display_name' => sanitize_text_field( $name ),
						'first_name'   => sanitize_text_field( strstr( $name, ' ', true ) ?: $name ),
					]
				);
			}

			// Set role.
			$default_role = apply_filters( 'jwt_auth_firebase_default_role', get_option( 'jwt_auth_firebase_default_role', 'subscriber' ), $firebase_payload );
			$wp_user_obj  = new WP_User( $new_user_id );
			$wp_user_obj->set_role( sanitize_text_field( $default_role ) );

			// Store Firebase metadata.
			update_user_meta( $new_user_id, 'firebase_uid', $uid );
			update_user_meta( $new_user_id, 'firebase_provider', $provider );
			if ( ! empty( $picture ) ) {
				update_user_meta( $new_user_id, 'firebase_picture', esc_url_raw( $picture ) );
			}

			/**
			 * Fires after a new WordPress user is created from Firebase auth.
			 *
			 * @param int    $new_user_id     New user ID.
			 * @param array  $firebase_payload Firebase token payload.
			 * @param string $provider        Auth provider identifier.
			 */
			do_action( 'jwt_auth_firebase_user_created', $new_user_id, $firebase_payload, $provider );

			$is_new_user = true;
			$user_id     = $new_user_id;
		} else {
			// Existing user found.
			$user_id = $existing_user->ID;

			// Sync Firebase UID if enabled.
			if ( (bool) get_option( 'jwt_auth_firebase_sync_uid', true ) ) {
				update_user_meta( $user_id, 'firebase_uid', $uid );
				update_user_meta( $user_id, 'firebase_provider', $provider );
			}

			/**
			 * Fires when an existing WordPress user logs in via Firebase.
			 *
			 * @param int   $user_id         WordPress user ID.
			 * @param array $firebase_payload Firebase token payload.
			 */
			do_action( 'jwt_auth_firebase_user_logged_in', $user_id, $firebase_payload );
		}

		return [
			'user_id'    => $user_id,
			'is_new_user' => $is_new_user,
		];
	}

	// -------------------------------------------------------------------------
	// WordPress Login Mode & Redirect Hooks
	// -------------------------------------------------------------------------

	/**
	 * Enforce Firebase-only login mode on the WP login form.
	 *
	 * @param WP_User|WP_Error|null $user     Current authentication result.
	 * @param string                $username Username attempted.
	 * @param string                $password Password attempted.
	 * @return WP_User|WP_Error|null
	 */
	public function enforce_login_mode( $user, string $username, string $password ) {
		if ( ! $this->is_enabled() ) {
			return $user;
		}

		$mode = get_option( 'jwt_auth_firebase_login_mode', 'both' );

		if ( 'firebase_only' === $mode && ! empty( $username ) ) {
			return new WP_Error(
				'firebase_only',
				__( 'Please log in with Firebase.', 'jwt-authenticator' )
			);
		}

		return $user;
	}

	/**
	 * Apply custom login redirect if configured.
	 *
	 * @param string  $redirect_to  The redirect URL.
	 * @param string  $requested    The originally requested URL.
	 * @param WP_User $user         The logged-in user.
	 * @return string
	 */
	public function custom_login_redirect( string $redirect_to, string $requested, $user ): string {
		$custom = get_option( 'jwt_auth_firebase_redirect_login', '' );
		if ( ! empty( $custom ) && $user instanceof WP_User ) {
			return esc_url_raw( $custom );
		}
		return $redirect_to;
	}

	/**
	 * Apply custom logout redirect if configured.
	 *
	 * @param string  $redirect_to  The redirect URL.
	 * @param string  $requested    The originally requested URL.
	 * @param WP_User $user         The user being logged out.
	 * @return string
	 */
	public function custom_logout_redirect( string $redirect_to, string $requested, $user ): string {
		$custom = get_option( 'jwt_auth_firebase_redirect_logout', '' );
		if ( ! empty( $custom ) ) {
			return esc_url_raw( $custom );
		}
		return $redirect_to;
	}

	// -------------------------------------------------------------------------
	// Helpers
	// -------------------------------------------------------------------------

	/**
	 * Check whether Firebase integration is enabled.
	 *
	 * @return bool
	 */
	private function is_enabled(): bool {
		return (bool) get_option( 'jwt_auth_firebase_enabled', false );
	}

	/**
	 * Base64URL decode (RFC 4648 §5).
	 *
	 * @param string $input Base64URL encoded string.
	 * @return string Decoded binary string.
	 */
	private function base64url_decode( string $input ): string {
		$remainder = strlen( $input ) % 4;
		if ( $remainder ) {
			$input .= str_repeat( '=', 4 - $remainder );
		}
		return base64_decode( strtr( $input, '-_', '+/' ) );
	}
}
