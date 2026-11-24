<?php

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}
/**
 * The public-facing functionality of the JWT Authenticator plugin.
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
 * @since   1.0.0
 */

use JwtAuthenticator\Firebase\JWT\JWT;
use JwtAuthenticator\Firebase\JWT\Key;

/**
 * The public-facing functionality of the plugin.
 *
 * Defines the plugin name, version, and hooks for the public-facing side.
 *
 * @since 1.0.0
 * @since 2.0.0 Added email login, custom header, configurable expiry,
 *              token storage, and revocation check.
 */
class Jwt_Auth_Public {

	/**
	 * The ID of this plugin.
	 *
	 * @since 1.0.0
	 * @var string
	 */
	private string $plugin_name;

	/**
	 * The version of this plugin.
	 *
	 * @since 1.0.0
	 * @var string
	 */
	private string $version;

	/**
	 * The namespace for REST API calls.
	 *
	 * @var string
	 */
	private string $namespace;

	/**
	 * Store errors to display if the JWT is wrong.
	 *
	 * @var WP_Error|null
	 */
	private ?WP_Error $jwt_error = null;

	/**
	 * Supported algorithms to sign the token.
	 *
	 * @since 1.3.1
	 * @see   https://www.rfc-editor.org/rfc/rfc7518#section-3
	 * @var   string[]
	 */
	private array $supported_algorithms = [
		'HS256',
		'HS384',
		'HS512',
		'RS256',
		'RS384',
		'RS512',
		'ES256',
		'ES384',
		'ES512',
		'PS256',
		'PS384',
		'PS512',
	];

	/**
	 * Initialize the class and set its properties.
	 *
	 * @since 1.0.0
	 *
	 * @param string $plugin_name The name of the plugin.
	 * @param string $version     The version of this plugin.
	 */
	public function __construct( string $plugin_name, string $version ) {
		$this->plugin_name = $plugin_name;
		$this->version     = $version;
		$this->namespace   = $this->plugin_name . '/v' . intval( $this->version );
	}

	// -------------------------------------------------------------------------
	// REST route registration
	// -------------------------------------------------------------------------

	/**
	 * Add the endpoints to the API.
	 */
	public function add_api_routes(): void {
		register_rest_route(
			$this->namespace,
			'token',
			[
				'methods'             => 'POST',
				'callback'            => [ $this, 'generate_token' ],
				'permission_callback' => '__return_true',
				'args'                => [
					'username' => [
						'required'          => false,
						'sanitize_callback' => 'sanitize_text_field',
						'description'       => 'WordPress username or email address.',
					],
					'email'    => [
						'required'          => false,
						'sanitize_callback' => 'sanitize_email',
						'description'       => 'Email address (alias for username).',
					],
					'password' => [
						'required'          => true,
						'sanitize_callback' => function ( $value ) {
							// Do NOT strip slashes from passwords.
							return (string) $value;
						},
					],
				],
			]
		);

		register_rest_route(
			$this->namespace,
			'token/validate',
			[
				'methods'             => 'POST',
				'callback'            => [ $this, 'validate_token' ],
				'permission_callback' => '__return_true',
			]
		);
	}

	// -------------------------------------------------------------------------
	// CORS
	// -------------------------------------------------------------------------

	/**
	 * Add CORS support to the request.
	 */
	public function add_cors_support(): void {
		$enable_cors = defined( 'JWT_AUTH_CORS_ENABLE' ) && JWT_AUTH_CORS_ENABLE;
		if ( $enable_cors ) {
			$headers = apply_filters(
				'jwt_auth_cors_allow_headers',
				'Access-Control-Allow-Headers, Content-Type, Authorization'
			);
			header( sprintf( 'Access-Control-Allow-Headers: %s', $headers ) );
		}
	}

	// -------------------------------------------------------------------------
	// Token generation
	// -------------------------------------------------------------------------

	/**
	 * Get the user and password in the request body and generate a JWT.
	 *
	 * Enhancements (v2.0.0):
	 * - Accepts `email` parameter as alias for `username`.
	 * - Supports email-based login (bypasses wp_authenticate when email found).
	 * - Uses configurable expiry via `jwt_auth_access_token_expiry` option.
	 * - Adds `jti` claim and stores the token via Jwt_Auth_Token_Manager.
	 *
	 * @since 1.0.0
	 * @since 2.0.0 Added email login, jti, configurable expiry, token storage.
	 *
	 * @param WP_REST_Request $request Incoming REST request.
	 * @return mixed|WP_Error
	 */
	public function generate_token( WP_REST_Request $request ) {
		$secret_key = defined( 'JWT_AUTH_SECRET_KEY' ) ? JWT_AUTH_SECRET_KEY : false;

		// `email` is an accepted alias for `username`.
		$username = $request->get_param( 'username' ) ?? $request->get_param( 'email' ) ?? '';
		$username = sanitize_text_field( (string) $username );
		$password = (string) $request->get_param( 'password' );

		/** First thing, check the secret key; if not present return an error. */
		if ( ! $secret_key ) {
			return new WP_Error(
				'jwt_auth_bad_config',
				__( 'JWT is not configured properly, please contact the admin', 'jwt-authenticator' ),
				[ 'status' => 403 ]
			);
		}

		// -----------------------------------------------------------------
		// (a) Email login support
		// -----------------------------------------------------------------
		$user = false;
		$allow_email_login = (bool) get_option( 'jwt_auth_allow_email_login', true );

		if ( $allow_email_login && false !== strpos( $username, '@' ) ) {
			$user_by_email = get_user_by( 'email', $username );
			if ( $user_by_email && wp_check_password( $password, $user_by_email->user_pass, $user_by_email->ID ) ) {
				$user = $user_by_email;
			} elseif ( $user_by_email ) {
				// Email found but password wrong.
				return new WP_Error(
					'[jwt_auth] incorrect_password',
					__( 'The password you entered for the email address is incorrect.', 'jwt-authenticator' ),
					[ 'status' => 403 ]
				);
			}
			// If no user found by email, fall through to wp_authenticate (which will also fail gracefully).
		}

		if ( ! $user ) {
			/** Try to authenticate the user with the passed credentials. */
			$user = wp_authenticate( $username, $password );

			/** If the authentication fails return an error. */
			if ( is_wp_error( $user ) ) {
				$error_code = $user->get_error_code();

				return new WP_Error(
					'[jwt_auth] ' . $error_code,
					$user->get_error_message( $error_code ),
					[ 'status' => 403 ]
				);
			}
		}

		/** Valid credentials — build the token payload. */
		$issuedAt  = time();
		$notBefore = apply_filters( 'jwt_auth_not_before', $issuedAt, $issuedAt );

		// -----------------------------------------------------------------
		// (c) Configurable token expiry
		// -----------------------------------------------------------------
		$expiry_seconds = (int) get_option( 'jwt_auth_access_token_expiry', 3600 );
		$expire         = apply_filters( 'jwt_auth_expire', $issuedAt + $expiry_seconds, $issuedAt );

		// -----------------------------------------------------------------
		// (d) Add jti claim before encoding
		// -----------------------------------------------------------------
		$jti = Jwt_Auth_Helpers::generate_jti();

		$token = [
			'iss'  => get_bloginfo( 'url' ),
			'iat'  => $issuedAt,
			'nbf'  => $notBefore,
			'exp'  => $expire,
			'jti'  => $jti,
			'data' => [
				'user' => [
					'id' => $user->data->ID,
				],
			],
		];

		/** Let the user modify the token data before the sign. */
		$algorithm = $this->get_algorithm();

		if ( false === $algorithm ) {
			return new WP_Error(
				'jwt_auth_unsupported_algorithm',
				__( 'Algorithm not supported, see https://www.rfc-editor.org/rfc/rfc7518#section-3', 'jwt-authenticator' ),
				[ 'status' => 403 ]
			);
		}

		$token_string = JWT::encode(
			apply_filters( 'jwt_auth_token_before_sign', $token, $user ),
			$secret_key,
			$algorithm
		);

		// -----------------------------------------------------------------
		// (d) Store token in DB via Token Manager
		// -----------------------------------------------------------------
		if ( class_exists( 'Jwt_Auth_Token_Manager' ) ) {
			Jwt_Auth_Token_Manager::get_instance()->store_token(
				(int) $user->data->ID,
				$token_string,
				'access',
				$expire,
				$jti
			);
		}

		/** The token is signed — now create the response object. */
		$data = [
			'token'             => $token_string,
			'user_email'        => $user->data->user_email,
			'user_nicename'     => $user->data->user_nicename,
			'user_display_name' => $user->data->display_name,
		];

		/** Let the user modify the data before dispatching. */
		return apply_filters( 'jwt_auth_token_before_dispatch', $data, $user );
	}

	// -------------------------------------------------------------------------
	// Current user determination
	// -------------------------------------------------------------------------

	/**
	 * Middleware: authenticate the user via the JWT Bearer token.
	 *
	 * Enhancements (v2.0.0):
	 * - Also reads a custom server header configured by `jwt_auth_custom_header`.
	 *
	 * @since 1.0.0
	 * @since 2.0.0 Added custom header support.
	 *
	 * @param int|bool $user Logged user ID (from earlier filters).
	 * @return int|bool
	 */
	public function determine_current_user( $user ) {
		/**
		 * Only run on REST API requests to determine whether the token (if any)
		 * is valid. For any other call (e.g. wp-admin/*) return $user as-is.
		 *
		 * @since 1.2.3
		 */
		$rest_api_slug = rest_get_url_prefix();
		$requested_url = isset( $_SERVER['REQUEST_URI'] )
			? sanitize_url( wp_unslash( $_SERVER['REQUEST_URI'] ) )
			: '';

		$is_rest_request_constant_defined = defined( 'REST_REQUEST' ) && REST_REQUEST;
		$is_rest_request                  = $is_rest_request_constant_defined || ( false !== strpos( $requested_url, $rest_api_slug ) );

		if ( $is_rest_request && $user ) {
			return $user;
		}

		/*
		 * Skip token validation on the /token/validate endpoint to avoid
		 * double calls.
		 */
		if ( false !== strpos( $requested_url, 'token/validate' ) ) {
			return $user;
		}

		/**
		 * Grab the Authorization header.
		 *
		 * Order of preference:
		 *  1. HTTP_AUTHORIZATION
		 *  2. REDIRECT_HTTP_AUTHORIZATION (mod_rewrite on some servers)
		 *  3. Custom header configured via jwt_auth_custom_header option
		 */
		$auth_header = ! empty( $_SERVER['HTTP_AUTHORIZATION'] )
			? sanitize_text_field( wp_unslash( $_SERVER['HTTP_AUTHORIZATION'] ) )
			: false;

		if ( ! $auth_header ) {
			$auth_header = ! empty( $_SERVER['REDIRECT_HTTP_AUTHORIZATION'] )
				? sanitize_text_field( wp_unslash( $_SERVER['REDIRECT_HTTP_AUTHORIZATION'] ) )
				: false;
		}

		// -----------------------------------------------------------------
		// (b) Custom header support
		// -----------------------------------------------------------------
		$custom_header = get_option( 'jwt_auth_custom_header', '' );
		if ( $custom_header ) {
			$server_key = 'HTTP_' . strtoupper( str_replace( '-', '_', $custom_header ) );
			$auth_header = ! empty( $_SERVER[ $server_key ] )
				? sanitize_text_field( wp_unslash( $_SERVER[ $server_key ] ) )
				: $auth_header;
		}

		if ( ! $auth_header ) {
			return $user;
		}

		/** If the Authorization header is not Bearer, pass through. */
		if ( strpos( $auth_header, 'Bearer' ) !== 0 ) {
			return $user;
		}

		/** Validate the token. */
		$token = $this->validate_token( new WP_REST_Request(), $auth_header );

		if ( is_wp_error( $token ) ) {
			if ( 'jwt_auth_no_auth_header' !== $token->get_error_code() ) {
				/** Store the error so rest_pre_dispatch can return it. */
				$this->jwt_error = $token;
			}

			return $user;
		}

		/** Token valid — return the user ID stored in it. */
		return $token->data->user->id;
	}

	// -------------------------------------------------------------------------
	// Token validation
	// -------------------------------------------------------------------------

	/**
	 * Validate a JWT token.
	 *
	 * Used by both the /token/validate endpoint and determine_current_user().
	 *
	 * Enhancements (v2.0.0):
	 * - Checks token revocation via Jwt_Auth_Token_Manager::is_revoked().
	 *
	 * @since 1.0.0
	 * @since 2.0.0 Added revocation check.
	 *
	 * @param WP_REST_Request $request      Incoming REST request.
	 * @param bool|string     $custom_token Raw "Bearer <token>" string when called
	 *                                      outside a REST endpoint context.
	 * @return WP_Error|object|array
	 */
	public function validate_token( WP_REST_Request $request, $custom_token = false ) {
		/*
		 * Locate the Authorization header.
		 *
		 * Two paths:
		 *  1. via WP_REST_Request (get_header checks HTTP_AUTHORIZATION /
		 *     REDIRECT_HTTP_AUTHORIZATION automatically)
		 *  2. via $custom_token when called from determine_current_user()
		 *
		 * @see https://core.trac.wordpress.org/ticket/47077
		 */
		$auth_header = $custom_token ?: $request->get_header( 'Authorization' );

		if ( ! $auth_header ) {
			return new WP_Error(
				'jwt_auth_no_auth_header',
				'Authorization header not found.',
				[ 'status' => 403 ]
			);
		}

		/** Extract the raw token string from "Bearer <token>". */
		[ $token ] = sscanf( $auth_header, 'Bearer %s' );

		if ( ! $token ) {
			return new WP_Error(
				'jwt_auth_bad_auth_header',
				'Authorization header malformed.',
				[ 'status' => 403 ]
			);
		}

		/** Retrieve the secret key. */
		$secret_key = defined( 'JWT_AUTH_SECRET_KEY' ) ? JWT_AUTH_SECRET_KEY : false;
		if ( ! $secret_key ) {
			return new WP_Error(
				'jwt_auth_bad_config',
				'JWT is not configured properly, please contact the admin',
				[ 'status' => 403 ]
			);
		}

		/** Decode and validate the token. */
		try {
			$algorithm = $this->get_algorithm();
			if ( false === $algorithm ) {
				return new WP_Error(
					'jwt_auth_unsupported_algorithm',
					__( 'Algorithm not supported, see https://www.rfc-editor.org/rfc/rfc7518#section-3', 'jwt-authenticator' ),
					[ 'status' => 403 ]
				);
			}

			$decoded = JWT::decode( $token, new Key( $secret_key, $algorithm ) );

			/** Validate issuer. */
			if ( $decoded->iss !== get_bloginfo( 'url' ) ) {
				return new WP_Error(
					'jwt_auth_bad_iss',
					'The iss do not match with this server',
					[ 'status' => 403 ]
				);
			}

			/** Validate user ID present. */
			if ( ! isset( $decoded->data->user->id ) ) {
				return new WP_Error(
					'jwt_auth_bad_request',
					'User ID not found in the token',
					[ 'status' => 403 ]
				);
			}

			// -----------------------------------------------------------------
			// (e) Revocation check
			// -----------------------------------------------------------------
			if (
				isset( $decoded->jti ) &&
				class_exists( 'Jwt_Auth_Token_Manager' ) &&
				Jwt_Auth_Token_Manager::get_instance()->is_revoked( $decoded->jti )
			) {
				return new WP_Error(
					'jwt_auth_revoked_token',
					'Token has been revoked.',
					[ 'status' => 401 ]
				);
			}

			/** For the /token/validate endpoint, return a success response. */
			if ( ! $custom_token ) {
				return [
					'code' => 'jwt_auth_valid_token',
					'data' => [
						'status' => 200,
					],
				];
			}

			/** For middleware usage, return the decoded token object. */
			return $decoded;

		} catch ( Exception $e ) {
			return new WP_Error(
				'jwt_auth_invalid_token',
				$e->getMessage(),
				[ 'status' => 403 ]
			);
		}
	}

	// -------------------------------------------------------------------------
	// REST pre-dispatch
	// -------------------------------------------------------------------------

	/**
	 * Filter hooked to rest_pre_dispatch.
	 *
	 * If a JWT error was captured during determine_current_user(), propagate it
	 * so the REST response carries the proper error.
	 *
	 * @param mixed $request Original dispatch value.
	 * @return mixed|WP_Error
	 */
	public function rest_pre_dispatch( $request ) {
		if ( is_wp_error( $this->jwt_error ) ) {
			return $this->jwt_error;
		}

		return $request;
	}

	// -------------------------------------------------------------------------
	// Helpers
	// -------------------------------------------------------------------------

	/**
	 * Get the signing algorithm via the jwt_auth_algorithm filter.
	 *
	 * Returns false when the filtered value is not in the supported list.
	 *
	 * @return string|false
	 */
	private function get_algorithm() {
		$algorithm = apply_filters( 'jwt_auth_algorithm', 'HS256' );
		if ( ! in_array( $algorithm, $this->supported_algorithms, true ) ) {
			return false;
		}

		return $algorithm;
	}
}
