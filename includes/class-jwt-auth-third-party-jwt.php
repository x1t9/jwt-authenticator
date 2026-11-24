<?php
/**
 * JWT Authenticator — Third-Party JWT Authentication
 *
 * Validates JWT tokens issued by external providers (e.g., Auth0, Firebase,
 * Cognito), optionally auto-creates WordPress users, and issues local JWTs.
 *
 * JWKS keys are fetched via wp_remote_get() and cached as transients for 1 hour.
 *
 * @package    JWT_Authenticator
 * @subpackage JWT_Authenticator/includes
 * @license    MIT https://opensource.org/licenses/MIT
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Class Jwt_Auth_Third_Party_Jwt
 *
 * Singleton. Register hooks via register_hooks().
 */
class Jwt_Auth_Third_Party_Jwt {

	/**
	 * Singleton instance.
	 *
	 * @var Jwt_Auth_Third_Party_Jwt|null
	 */
	private static ?Jwt_Auth_Third_Party_Jwt $instance = null;

	/**
	 * Private constructor — use get_instance().
	 */
	private function __construct() {}

	/**
	 * Returns the singleton instance.
	 *
	 * @return Jwt_Auth_Third_Party_Jwt
	 */
	public static function get_instance(): Jwt_Auth_Third_Party_Jwt {
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
		add_filter( 'determine_current_user', [ $this, 'authenticate_with_third_party_jwt' ], 25 );
		add_action( 'rest_api_init', [ $this, 'register_routes' ] );
	}

	// -------------------------------------------------------------------------
	// REST route registration
	// -------------------------------------------------------------------------

	/**
	 * Register third-party JWT REST routes.
	 *
	 * @return void
	 */
	public function register_routes(): void {
		if ( ! $this->is_enabled() ) {
			return;
		}

		register_rest_route(
			'jwt-auth/v1',
			'/auth/third-party',
			[
				'methods'             => WP_REST_Server::CREATABLE,
				'callback'            => [ $this, 'rest_exchange_token' ],
				'permission_callback' => '__return_true',
				'args'                => [
					'provider' => [
						'required'          => true,
						'type'              => 'string',
						'sanitize_callback' => 'sanitize_text_field',
					],
					'token'    => [
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
	 * Exchange a third-party JWT for a local WordPress JWT.
	 *
	 * @param WP_REST_Request $request Request object.
	 * @return WP_REST_Response|WP_Error
	 */
	public function rest_exchange_token( WP_REST_Request $request ) {
		$provider_name = $request->get_param( 'provider' );
		$token         = $request->get_param( 'token' );

		$provider = $this->find_provider_by_name( $provider_name );
		if ( ! $provider ) {
			return new WP_Error(
				'jwt_auth_unknown_provider',
				__( 'Unknown third-party provider.', 'jwt-authenticator' ),
				[ 'status' => 400 ]
			);
		}

		$payload = $this->validate_third_party_token( $token, $provider );
		if ( is_wp_error( $payload ) ) {
			return $payload;
		}

		$user_id = $this->resolve_or_create_user( $payload, $provider );
		if ( is_wp_error( $user_id ) ) {
			return $user_id;
		}

		$user = get_user_by( 'id', $user_id );
		if ( ! $user ) {
			return new WP_Error(
				'jwt_auth_user_not_found',
				__( 'User could not be loaded.', 'jwt-authenticator' ),
				[ 'status' => 500 ]
			);
		}

		// Issue a local JWT for the resolved user.
		$local_token = $this->issue_local_token( $user );
		if ( is_wp_error( $local_token ) ) {
			return $local_token;
		}

		return rest_ensure_response( array_merge( $local_token, [
			'user_id'      => $user->ID,
			'user_email'   => $user->user_email,
			'display_name' => $user->display_name,
		] ) );
	}

	// -------------------------------------------------------------------------
	// Core authentication filter
	// -------------------------------------------------------------------------

	/**
	 * Attempt to authenticate the request using a third-party JWT.
	 *
	 * Hooked into determine_current_user at priority 25.
	 *
	 * @param int|false $user Existing resolved user ID (or false).
	 * @return int|false|WP_Error
	 */
	public function authenticate_with_third_party_jwt( $user ) {
		if ( $user ) {
			return $user;
		}

		if ( ! $this->is_enabled() ) {
			return $user;
		}

		$token = $this->extract_bearer_token();
		if ( null === $token ) {
			return $user;
		}

		// Decode header+payload WITHOUT signature verification to inspect `iss`.
		$unverified = $this->decode_token_unverified( $token );
		if ( null === $unverified ) {
			return $user;
		}

		$iss = $unverified->iss ?? '';

		// Match against configured providers.
		$provider = $this->find_provider_by_issuer( $iss );
		if ( ! $provider ) {
			// Not a known third-party issuer — let other handlers deal with it.
			return $user;
		}

		$payload = $this->validate_third_party_token( $token, $provider );
		if ( is_wp_error( $payload ) ) {
			return $payload;
		}

		$user_id = $this->resolve_or_create_user( $payload, $provider );
		if ( is_wp_error( $user_id ) ) {
			return $user_id;
		}

		return $user_id;
	}

	// -------------------------------------------------------------------------
	// Validation helpers
	// -------------------------------------------------------------------------

	/**
	 * Validate a JWT against a provider's public key or JWKS endpoint.
	 *
	 * @param string $token    Raw JWT string.
	 * @param array  $provider Provider configuration array.
	 * @return object|WP_Error Decoded payload object or error.
	 */
	private function validate_third_party_token( string $token, array $provider ) {
		$parts = explode( '.', $token );
		if ( count( $parts ) !== 3 ) {
			return new WP_Error(
				'jwt_auth_malformed_token',
				__( 'Malformed JWT token.', 'jwt-authenticator' ),
				[ 'status' => 401 ]
			);
		}

		[ $header_b64, $payload_b64, $signature_b64 ] = $parts;

		$header  = json_decode( $this->base64url_decode( $header_b64 ) );
		$payload = json_decode( $this->base64url_decode( $payload_b64 ) );

		if ( ! $header || ! $payload ) {
			return new WP_Error(
				'jwt_auth_malformed_token',
				__( 'Cannot decode JWT segments.', 'jwt-authenticator' ),
				[ 'status' => 401 ]
			);
		}

		// Check expiry.
		if ( isset( $payload->exp ) && $payload->exp < time() ) {
			return new WP_Error(
				'jwt_auth_token_expired',
				__( 'Third-party token has expired.', 'jwt-authenticator' ),
				[ 'status' => 401 ]
			);
		}

		// Check issuer.
		$expected_issuer = $provider['issuer'] ?? '';
		if ( $expected_issuer && ( ! isset( $payload->iss ) || $payload->iss !== $expected_issuer ) ) {
			return new WP_Error(
				'jwt_auth_invalid_issuer',
				__( 'Token issuer does not match provider configuration.', 'jwt-authenticator' ),
				[ 'status' => 401 ]
			);
		}

		// Check audience if configured.
		$expected_aud = $provider['audience'] ?? '';
		if ( $expected_aud && isset( $payload->aud ) ) {
			$audiences = is_array( $payload->aud ) ? $payload->aud : [ $payload->aud ];
			if ( ! in_array( $expected_aud, $audiences, true ) ) {
				return new WP_Error(
					'jwt_auth_invalid_audience',
					__( 'Token audience does not match provider configuration.', 'jwt-authenticator' ),
					[ 'status' => 401 ]
				);
			}
		}

		// Verify signature.
		$alg = $header->alg ?? 'RS256';
		$sig_verified = $this->verify_signature( $token, $header, $provider, $alg );
		if ( is_wp_error( $sig_verified ) ) {
			return $sig_verified;
		}

		if ( ! $sig_verified ) {
			return new WP_Error(
				'jwt_auth_invalid_signature',
				__( 'Third-party token signature is invalid.', 'jwt-authenticator' ),
				[ 'status' => 401 ]
			);
		}

		return $payload;
	}

	/**
	 * Verify the JWT signature.
	 *
	 * Supports RS256 (RSA + SHA-256) using either a PEM public key or JWKS.
	 *
	 * @param string $token    Full raw JWT.
	 * @param object $header   Decoded JWT header.
	 * @param array  $provider Provider config.
	 * @param string $alg      Algorithm from header.
	 * @return bool|WP_Error
	 */
	private function verify_signature( string $token, object $header, array $provider, string $alg ) {
		$parts      = explode( '.', $token );
		$signing_input = $parts[0] . '.' . $parts[1];
		$signature     = $this->base64url_decode( $parts[2] );

		$public_key_pem = null;

		if ( ! empty( $provider['jwks_uri'] ) ) {
			// Fetch and cache JWKS.
			$kid        = $header->kid ?? null;
			$public_key_pem = $this->get_public_key_from_jwks( $provider['jwks_uri'], $kid );
			if ( is_wp_error( $public_key_pem ) ) {
				return $public_key_pem;
			}
		} elseif ( ! empty( $provider['public_key'] ) ) {
			$public_key_pem = $provider['public_key'];
		}

		if ( empty( $public_key_pem ) ) {
			return new WP_Error(
				'jwt_auth_no_public_key',
				__( 'No public key or JWKS URI configured for this provider.', 'jwt-authenticator' ),
				[ 'status' => 500 ]
			);
		}

		$pkey = openssl_pkey_get_public( $public_key_pem );
		if ( false === $pkey ) {
			return new WP_Error(
				'jwt_auth_invalid_public_key',
				__( 'Provider public key is invalid.', 'jwt-authenticator' ),
				[ 'status' => 500 ]
			);
		}

		// Map algorithm to OpenSSL constant.
		$openssl_alg = $this->map_alg_to_openssl( $alg );
		if ( false === $openssl_alg ) {
			return new WP_Error(
				'jwt_auth_unsupported_algorithm',
				/* translators: %s: algorithm name */
				sprintf( __( 'Unsupported JWT algorithm: %s.', 'jwt-authenticator' ), esc_html( $alg ) ),
				[ 'status' => 400 ]
			);
		}

		$result = openssl_verify( $signing_input, $signature, $pkey, $openssl_alg );
		return 1 === $result;
	}

	/**
	 * Fetch a public key from a JWKS endpoint, with 1-hour transient caching.
	 *
	 * @param string      $jwks_uri JWKS URL.
	 * @param string|null $kid      Key ID to match (optional).
	 * @return string|WP_Error PEM-encoded public key or error.
	 */
	private function get_public_key_from_jwks( string $jwks_uri, ?string $kid = null ) {
		$cache_key = 'jwt_auth_jwks_' . md5( $jwks_uri );
		$cached    = get_transient( $cache_key );

		if ( false === $cached ) {
			$response = wp_remote_get( $jwks_uri, [
				'timeout'    => 10,
				'user-agent' => 'JWT-Authenticator/' . ( defined( 'JWT_AUTH_VERSION' ) ? JWT_AUTH_VERSION : '2.0.0' ),
			] );

			if ( is_wp_error( $response ) ) {
				return new WP_Error(
					'jwt_auth_jwks_fetch_failed',
					/* translators: %s: error message */
					sprintf( __( 'Failed to fetch JWKS: %s', 'jwt-authenticator' ), $response->get_error_message() ),
					[ 'status' => 500 ]
				);
			}

			$body = wp_remote_retrieve_body( $response );
			$jwks = json_decode( $body, true );

			if ( ! isset( $jwks['keys'] ) ) {
				return new WP_Error(
					'jwt_auth_jwks_invalid',
					__( 'Invalid JWKS response from provider.', 'jwt-authenticator' ),
					[ 'status' => 500 ]
				);
			}

			set_transient( $cache_key, $jwks, HOUR_IN_SECONDS );
			$cached = $jwks;
		}

		// Find the matching key.
		$keys = $cached['keys'] ?? [];
		$matching_jwk = null;

		foreach ( $keys as $jwk ) {
			if ( null === $kid || ( isset( $jwk['kid'] ) && $jwk['kid'] === $kid ) ) {
				$matching_jwk = $jwk;
				break;
			}
		}

		if ( ! $matching_jwk ) {
			// If we have only one key and no kid, use it.
			if ( ! empty( $keys ) && null === $kid ) {
				$matching_jwk = $keys[0];
			} else {
				return new WP_Error(
					'jwt_auth_jwks_key_not_found',
					__( 'Could not find a matching key in JWKS.', 'jwt-authenticator' ),
					[ 'status' => 401 ]
				);
			}
		}

		return $this->jwk_to_pem( $matching_jwk );
	}

	/**
	 * Convert a JWK (RSA) to a PEM-encoded public key string.
	 *
	 * @param array $jwk JSON Web Key array.
	 * @return string|WP_Error PEM string or error.
	 */
	private function jwk_to_pem( array $jwk ) {
		if ( ! isset( $jwk['n'], $jwk['e'] ) ) {
			return new WP_Error(
				'jwt_auth_invalid_jwk',
				__( 'JWK is missing required RSA parameters.', 'jwt-authenticator' ),
				[ 'status' => 500 ]
			);
		}

		$modulus  = $this->base64url_decode( $jwk['n'] );
		$exponent = $this->base64url_decode( $jwk['e'] );

		// Build an RSA public key using openssl_pkey_get_public with an array (PHP 8+).
		// For PHP 7.4 compatibility, construct the DER manually.
		$rsa_key = openssl_pkey_get_public( [
			'n' => $modulus,
			'e' => $exponent,
		] );

		if ( $rsa_key ) {
			$key_details = openssl_pkey_get_details( $rsa_key );
			return $key_details['key'] ?? new WP_Error( 'jwt_auth_jwk_convert_failed', __( 'Failed to convert JWK to PEM.', 'jwt-authenticator' ), [ 'status' => 500 ] );
		}

		// Fallback: construct DER encoding manually for PHP 7.4.
		$pem = $this->rsa_jwk_to_pem_manual( $modulus, $exponent );
		if ( null === $pem ) {
			return new WP_Error(
				'jwt_auth_jwk_convert_failed',
				__( 'Failed to convert JWK to PEM.', 'jwt-authenticator' ),
				[ 'status' => 500 ]
			);
		}

		return $pem;
	}

	/**
	 * Manually construct a PEM-encoded RSA public key from modulus and exponent bytes.
	 *
	 * @param string $modulus  Binary modulus.
	 * @param string $exponent Binary exponent.
	 * @return string|null PEM string or null on failure.
	 */
	private function rsa_jwk_to_pem_manual( string $modulus, string $exponent ): ?string {
		// DER encode an ASN.1 INTEGER.
		$encode_int = static function ( string $bytes ): string {
			// Add leading zero byte if high bit is set (to keep it positive).
			if ( ord( $bytes[0] ) > 0x7F ) {
				$bytes = "\x00" . $bytes;
			}
			return "\x02" . self::der_length( strlen( $bytes ) ) . $bytes;
		};

		$n_der = $encode_int( $modulus );
		$e_der = $encode_int( $exponent );

		// SEQUENCE { INTEGER n, INTEGER e }.
		$seq_inner = "\x30" . self::der_length( strlen( $n_der ) + strlen( $e_der ) ) . $n_der . $e_der;

		// RSA OID: 1.2.840.113549.1.1.1 + NULL.
		$rsa_oid    = "\x30\x0d\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x01\x01\x05\x00";
		$bit_string = "\x03" . self::der_length( strlen( $seq_inner ) + 1 ) . "\x00" . $seq_inner;
		$der        = "\x30" . self::der_length( strlen( $rsa_oid ) + strlen( $bit_string ) ) . $rsa_oid . $bit_string;

		$b64 = chunk_split( base64_encode( $der ), 64, "\n" );
		return "-----BEGIN PUBLIC KEY-----\n{$b64}-----END PUBLIC KEY-----\n";
	}

	/**
	 * DER-encode a length value.
	 *
	 * @param int $length Length to encode.
	 * @return string DER-encoded length bytes.
	 */
	private static function der_length( int $length ): string {
		if ( $length < 0x80 ) {
			return chr( $length );
		}
		$len_bytes = '';
		$tmp = $length;
		while ( $tmp > 0 ) {
			$len_bytes = chr( $tmp & 0xFF ) . $len_bytes;
			$tmp >>= 8;
		}
		return chr( 0x80 | strlen( $len_bytes ) ) . $len_bytes;
	}

	// -------------------------------------------------------------------------
	// User resolution
	// -------------------------------------------------------------------------

	/**
	 * Resolve an existing WP user or create one from the JWT payload.
	 *
	 * @param object $payload  Decoded JWT payload.
	 * @param array  $provider Provider configuration.
	 * @return int|WP_Error WordPress user ID or error.
	 */
	private function resolve_or_create_user( object $payload, array $provider ) {
		$email_claim = $provider['email_claim'] ?? 'email';
		$email       = $payload->$email_claim ?? null;

		if ( empty( $email ) || ! is_email( $email ) ) {
			return new WP_Error(
				'jwt_auth_no_email',
				__( 'Third-party token does not contain a valid email address.', 'jwt-authenticator' ),
				[ 'status' => 400 ]
			);
		}

		$existing = get_user_by( 'email', $email );
		if ( $existing ) {
			return $existing->ID;
		}

		$auto_create = isset( $provider['auto_create_users'] ) ? (bool) $provider['auto_create_users'] : false;

		if ( ! $auto_create ) {
			return new WP_Error(
				'jwt_auth_user_not_found',
				__( 'No WordPress user found for this email address. Auto-creation is disabled.', 'jwt-authenticator' ),
				[ 'status' => 401 ]
			);
		}

		// Extract display name.
		$name_claim   = $provider['name_claim'] ?? 'name';
		$display_name = $payload->$name_claim ?? '';
		$username     = $this->generate_unique_username( $email, $display_name );
		$password     = wp_generate_password( 24, true, true );

		$user_id = wp_create_user( $username, $password, $email );

		if ( is_wp_error( $user_id ) ) {
			return $user_id;
		}

		// Optionally set user role.
		$role = $provider['role'] ?? get_option( 'default_role', 'subscriber' );
		$user = new WP_User( $user_id );
		$user->set_role( $role );

		// Update display name if available.
		if ( $display_name ) {
			wp_update_user( [
				'ID'           => $user_id,
				'display_name' => sanitize_text_field( $display_name ),
			] );
		}

		return $user_id;
	}

	/**
	 * Generate a unique WordPress username derived from email and display name.
	 *
	 * @param string $email        User email address.
	 * @param string $display_name User display name.
	 * @return string Unique username.
	 */
	private function generate_unique_username( string $email, string $display_name ): string {
		// Prefer display_name, fall back to email local part.
		$base = $display_name
			? sanitize_user( strtolower( str_replace( ' ', '_', $display_name ) ), true )
			: sanitize_user( strstr( $email, '@', true ), true );

		if ( empty( $base ) ) {
			$base = 'user';
		}

		$username = $base;
		$suffix   = 1;

		while ( username_exists( $username ) ) {
			$username = $base . '_' . $suffix;
			$suffix++;
		}

		return $username;
	}

	// -------------------------------------------------------------------------
	// Provider lookup helpers
	// -------------------------------------------------------------------------

	/**
	 * Check whether third-party JWT auth is enabled.
	 *
	 * @return bool
	 */
	private function is_enabled(): bool {
		return (bool) get_option( 'jwt_auth_third_party_enabled', false );
	}

	/**
	 * Get all configured third-party providers.
	 *
	 * @return array
	 */
	private function get_providers(): array {
		$raw    = get_option( 'jwt_auth_third_party_providers', '[]' );
		$parsed = json_decode( $raw, true );
		return is_array( $parsed ) ? $parsed : [];
	}

	/**
	 * Find a provider by name.
	 *
	 * @param string $name Provider name.
	 * @return array|null Provider config or null if not found.
	 */
	private function find_provider_by_name( string $name ): ?array {
		foreach ( $this->get_providers() as $provider ) {
			if ( isset( $provider['name'] ) && $provider['name'] === $name ) {
				return $provider;
			}
		}
		return null;
	}

	/**
	 * Find a provider by its configured issuer URL.
	 *
	 * @param string $iss Issuer string from JWT payload.
	 * @return array|null Provider config or null if not found.
	 */
	private function find_provider_by_issuer( string $iss ): ?array {
		foreach ( $this->get_providers() as $provider ) {
			if ( isset( $provider['issuer'] ) && $provider['issuer'] === $iss ) {
				return $provider;
			}
		}
		return null;
	}

	// -------------------------------------------------------------------------
	// Token / JWT helpers
	// -------------------------------------------------------------------------

	/**
	 * Extract a Bearer token from the Authorization header.
	 *
	 * @return string|null Plaintext token or null if not present.
	 */
	private function extract_bearer_token(): ?string {
		$auth_header = '';
		if ( ! empty( $_SERVER['HTTP_AUTHORIZATION'] ) ) {
			$auth_header = wp_unslash( $_SERVER['HTTP_AUTHORIZATION'] );
		} elseif ( function_exists( 'apache_request_headers' ) ) {
			$headers = apache_request_headers();
			if ( ! empty( $headers['Authorization'] ) ) {
				$auth_header = $headers['Authorization'];
			}
		}

		if ( ! $auth_header || substr( $auth_header, 0, 7 ) !== 'Bearer ' ) {
			return null;
		}

		return trim( substr( $auth_header, 7 ) );
	}

	/**
	 * Decode a JWT's header and payload WITHOUT verifying the signature.
	 *
	 * Used only to inspect the `iss` claim before full validation.
	 *
	 * @param string $token Raw JWT.
	 * @return object|null Decoded payload or null on failure.
	 */
	private function decode_token_unverified( string $token ): ?object {
		$parts = explode( '.', $token );
		if ( count( $parts ) < 2 ) {
			return null;
		}
		$payload = json_decode( $this->base64url_decode( $parts[1] ) );
		return is_object( $payload ) ? $payload : null;
	}

	/**
	 * Base64URL-decode a string (no padding required).
	 *
	 * @param string $input Base64URL-encoded string.
	 * @return string Decoded binary string.
	 */
	private function base64url_decode( string $input ): string {
		$remainder = strlen( $input ) % 4;
		if ( $remainder ) {
			$input .= str_repeat( '=', 4 - $remainder );
		}
		return base64_decode( strtr( $input, '-_', '+/' ) );
	}

	/**
	 * Map a JWT algorithm string to an OpenSSL constant.
	 *
	 * @param string $alg JWT algorithm (e.g., 'RS256').
	 * @return int|false OpenSSL constant or false if unsupported.
	 */
	private function map_alg_to_openssl( string $alg ) {
		$map = [
			'RS256' => OPENSSL_ALGO_SHA256,
			'RS384' => OPENSSL_ALGO_SHA384,
			'RS512' => OPENSSL_ALGO_SHA512,
		];
		return $map[ $alg ] ?? false;
	}

	/**
	 * Issue a local JWT (and optionally refresh token) for a WordPress user.
	 *
	 * @param WP_User $user WordPress user object.
	 * @return array|WP_Error Token response or error.
	 */
	private function issue_local_token( WP_User $user ) {
		if ( ! class_exists( 'Jwt_Auth_Token_Manager' ) ) {
			return new WP_Error(
				'server_error',
				__( 'Token manager is not available.', 'jwt-authenticator' ),
				[ 'status' => 500 ]
			);
		}

		$manager = Jwt_Auth_Token_Manager::get_instance();

		if ( method_exists( $manager, 'generate_token_pair' ) ) {
			return $manager->generate_token_pair( $user );
		}

		if ( method_exists( $manager, 'generate_token' ) ) {
			return [ 'token' => $manager->generate_token( $user ) ];
		}

		return new WP_Error(
			'server_error',
			__( 'Token generation is not available.', 'jwt-authenticator' ),
			[ 'status' => 500 ]
		);
	}
}
