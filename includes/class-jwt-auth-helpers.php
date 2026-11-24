<?php

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Static helper utilities for JWT Authenticator.
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
 * @since 2.0.0
 */

if ( ! defined( 'WPINC' ) ) {
	die;
}

/**
 * Class Jwt_Auth_Helpers
 *
 * A collection of static utility methods used throughout JWT Authenticator.
 *
 * @since 2.0.0
 */
class Jwt_Auth_Helpers {

	/**
	 * Retrieve the real client IP address.
	 *
	 * Checks the X-Forwarded-For header (common behind proxies / load balancers)
	 * before falling back to REMOTE_ADDR. Each candidate is validated with
	 * filter_var() so that spoofed header values cannot inject arbitrary strings.
	 *
	 * @since 2.0.0
	 * @return string Valid IP address string, or empty string when unavailable.
	 */
	public static function get_client_ip(): string {
		// Potential proxy headers, in order of trustworthiness.
		$proxy_headers = [
			'HTTP_X_FORWARDED_FOR',
			'HTTP_X_REAL_IP',
			'HTTP_CLIENT_IP',
			'HTTP_CF_CONNECTING_IP', // Cloudflare.
		];

		foreach ( $proxy_headers as $header ) {
			if ( empty( $_SERVER[ $header ] ) ) {
				continue;
			}

			// X-Forwarded-For may contain a comma-separated list; the left-most
			// entry is the original client IP.
			$ips = explode( ',', sanitize_text_field( wp_unslash( $_SERVER[ $header ] ) ) );

			foreach ( $ips as $ip ) {
				$ip = trim( $ip );

				if ( filter_var( $ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE ) ) {
					return $ip;
				}
			}
		}

		// Fall back to REMOTE_ADDR (may be a proxy IP in hosted environments).
		if ( ! empty( $_SERVER['REMOTE_ADDR'] ) ) {
			$ip = sanitize_text_field( wp_unslash( $_SERVER['REMOTE_ADDR'] ) );

			if ( filter_var( $ip, FILTER_VALIDATE_IP ) ) {
				return $ip;
			}
		}

		return '';
	}

	/**
	 * Generate a unique JWT ID (jti) using WordPress's UUID v4 helper.
	 *
	 * @since 2.0.0
	 * @return string UUID v4 string.
	 */
	public static function generate_jti(): string {
		return wp_generate_uuid4();
	}

	/**
	 * Produce a SHA-256 hex digest of a JWT token string.
	 *
	 * Used when storing tokens in the DB so the raw token is never persisted.
	 *
	 * @since 2.0.0
	 * @param string $token Raw JWT string.
	 * @return string 64-character hex string.
	 */
	public static function hash_token( string $token ): string {
		return hash( 'sha256', $token );
	}

	/**
	 * Produce a SHA-256 hex digest of an API key.
	 *
	 * Used when storing API keys in the DB so the raw key is never persisted.
	 *
	 * @since 2.0.0
	 * @param string $key Raw API key string.
	 * @return string 64-character hex string.
	 */
	public static function hash_api_key( string $key ): string {
		return hash( 'sha256', $key );
	}

	/**
	 * Generate a new, cryptographically random API key.
	 *
	 * Format: `jwta_` followed by 48 hex characters (24 random bytes).
	 *
	 * @since 2.0.0
	 * @return string
	 * @throws \Exception When random_bytes() cannot gather sufficient entropy.
	 */
	public static function generate_api_key(): string {
		return 'jwta_' . bin2hex( random_bytes( 24 ) );
	}

	/**
	 * Check whether a REST route matches any pattern in a whitelist array.
	 *
	 * Each whitelist entry may be a literal string or a regex-style pattern
	 * prefixed with `~` (e.g. `~/wp/v2/posts/\d+~`).
	 *
	 * @since 2.0.0
	 * @param string   $route     The REST route to test, e.g. `/wp/v2/posts`.
	 * @param string[] $whitelist Array of allowed route patterns.
	 * @return bool True when the route is whitelisted.
	 */
	public static function is_route_whitelisted( string $route, array $whitelist ): bool {
		$route = self::sanitize_route( $route );

		foreach ( $whitelist as $pattern ) {
			$pattern = (string) $pattern;

			// Regex pattern detection: patterns starting and ending with `~`.
			if ( isset( $pattern[0] ) && '~' === $pattern[0] ) {
				if ( preg_match( $pattern, $route ) ) {
					return true;
				}
				continue;
			}

			// Plain string comparison (case-insensitive, normalised).
			if ( self::sanitize_route( $pattern ) === $route ) {
				return true;
			}
		}

		return false;
	}

	/**
	 * Normalise a REST route string for reliable comparison.
	 *
	 * - Strips leading/trailing whitespace.
	 * - Ensures exactly one leading slash.
	 * - Removes trailing slashes.
	 * - Lowercases the result.
	 *
	 * @since 2.0.0
	 * @param string $route Raw route string.
	 * @return string Sanitised route.
	 */
	public static function sanitize_route( string $route ): string {
		$route = trim( $route );
		$route = '/' . ltrim( $route, '/' );
		$route = rtrim( $route, '/' );

		return strtolower( $route );
	}
}
