<?php
/**
 * Geo-IP Location Service
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
 * Class Jwt_Auth_Geo_IP
 *
 * Provides Geo-IP location lookups for analytics enrichment.
 * No WordPress hooks are registered directly — this class is called by the Analytics class.
 */
class Jwt_Auth_Geo_IP {

	/**
	 * Singleton instance.
	 *
	 * @var Jwt_Auth_Geo_IP|null
	 */
	private static ?Jwt_Auth_Geo_IP $instance = null;

	/**
	 * Transient TTL for cached lookups (24 hours).
	 *
	 * @var int
	 */
	private const CACHE_TTL = DAY_IN_SECONDS;

	/**
	 * Empty location result.
	 *
	 * @var array
	 */
	private const EMPTY_LOCATION = [
		'country_code' => '',
		'country_name' => '',
		'city'         => '',
		'lat'          => null,
		'lon'          => null,
	];

	/**
	 * Get singleton instance.
	 *
	 * @return Jwt_Auth_Geo_IP
	 */
	public static function get_instance(): Jwt_Auth_Geo_IP {
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
	 * Get geographic location data for the given IP address.
	 *
	 * Results are cached in a transient for 24 hours.
	 *
	 * @param string $ip IPv4 or IPv6 address to look up.
	 * @return array Location data with keys: country_code, country_name, city, lat, lon.
	 */
	public function get_location( string $ip ): array {
		if ( empty( $ip ) || ! filter_var( $ip, FILTER_VALIDATE_IP ) ) {
			return self::EMPTY_LOCATION;
		}

		// Check private/loopback ranges — no point querying a public API for them.
		if ( $this->is_private_ip( $ip ) ) {
			return self::EMPTY_LOCATION;
		}

		$provider = get_option( 'jwt_auth_geoip_provider', 'ip-api' );

		if ( 'none' === $provider ) {
			return self::EMPTY_LOCATION;
		}

		$transient_key = 'jwt_auth_geo_' . md5( $ip );
		$cached        = get_transient( $transient_key );

		if ( is_array( $cached ) ) {
			return $cached;
		}

		$location = $this->fetch_location( $ip, $provider );

		// Cache even on failure to avoid hammering the API on bad IPs.
		set_transient( $transient_key, $location, self::CACHE_TTL );

		return $location;
	}

	/**
	 * Fetch location from the configured provider.
	 *
	 * @param string $ip       IP address.
	 * @param string $provider Provider slug.
	 * @return array
	 */
	private function fetch_location( string $ip, string $provider ): array {
		switch ( $provider ) {
			case 'ip-api':
				return $this->fetch_ip_api( $ip );

			case 'ipapi':
				return $this->fetch_ipapi_co( $ip );

			case 'ipinfo':
				return $this->fetch_ipinfo( $ip );

			default:
				return self::EMPTY_LOCATION;
		}
	}

	/**
	 * Fetch location from ip-api.com (free, no key required).
	 *
	 * @param string $ip IP address.
	 * @return array
	 */
	private function fetch_ip_api( string $ip ): array {
		$url      = "http://ip-api.com/json/{$ip}?fields=status,country,countryCode,city,lat,lon";
		$response = wp_remote_get( $url, [ 'timeout' => 5 ] );

		if ( is_wp_error( $response ) ) {
			return self::EMPTY_LOCATION;
		}

		$body = json_decode( wp_remote_retrieve_body( $response ), true );

		if ( ! is_array( $body ) || ( $body['status'] ?? '' ) !== 'success' ) {
			return self::EMPTY_LOCATION;
		}

		return [
			'country_code' => sanitize_text_field( $body['countryCode'] ?? '' ),
			'country_name' => sanitize_text_field( $body['country']     ?? '' ),
			'city'         => sanitize_text_field( $body['city']        ?? '' ),
			'lat'          => isset( $body['lat'] ) ? (float) $body['lat'] : null,
			'lon'          => isset( $body['lon'] ) ? (float) $body['lon'] : null,
		];
	}

	/**
	 * Fetch location from ipapi.co.
	 *
	 * @param string $ip IP address.
	 * @return array
	 */
	private function fetch_ipapi_co( string $ip ): array {
		$api_key = get_option( 'jwt_auth_geoip_api_key', '' );
		$url     = "https://ipapi.co/{$ip}/json/";
		if ( ! empty( $api_key ) ) {
			$url = add_query_arg( 'key', $api_key, $url );
		}

		$response = wp_remote_get( $url, [ 'timeout' => 5 ] );

		if ( is_wp_error( $response ) ) {
			return self::EMPTY_LOCATION;
		}

		$body = json_decode( wp_remote_retrieve_body( $response ), true );

		if ( ! is_array( $body ) || isset( $body['error'] ) ) {
			return self::EMPTY_LOCATION;
		}

		return [
			'country_code' => sanitize_text_field( $body['country_code'] ?? '' ),
			'country_name' => sanitize_text_field( $body['country_name'] ?? '' ),
			'city'         => sanitize_text_field( $body['city']         ?? '' ),
			'lat'          => isset( $body['latitude'] )  ? (float) $body['latitude']  : null,
			'lon'          => isset( $body['longitude'] ) ? (float) $body['longitude'] : null,
		];
	}

	/**
	 * Fetch location from ipinfo.io.
	 *
	 * @param string $ip IP address.
	 * @return array
	 */
	private function fetch_ipinfo( string $ip ): array {
		$api_key = get_option( 'jwt_auth_geoip_api_key', '' );
		$url     = "https://ipinfo.io/{$ip}/json";
		if ( ! empty( $api_key ) ) {
			$url = add_query_arg( 'token', $api_key, $url );
		}

		$response = wp_remote_get( $url, [ 'timeout' => 5 ] );

		if ( is_wp_error( $response ) ) {
			return self::EMPTY_LOCATION;
		}

		$body = json_decode( wp_remote_retrieve_body( $response ), true );

		if ( ! is_array( $body ) || isset( $body['error'] ) ) {
			return self::EMPTY_LOCATION;
		}

		// ipinfo.io returns location as "lat,lon" string.
		$lat = null;
		$lon = null;
		if ( ! empty( $body['loc'] ) ) {
			$coords = explode( ',', $body['loc'] );
			if ( 2 === count( $coords ) ) {
				$lat = (float) $coords[0];
				$lon = (float) $coords[1];
			}
		}

		return [
			'country_code' => sanitize_text_field( $body['country'] ?? '' ),
			'country_name' => sanitize_text_field( $body['country'] ?? '' ), // ipinfo doesn't return full name.
			'city'         => sanitize_text_field( $body['city']    ?? '' ),
			'lat'          => $lat,
			'lon'          => $lon,
		];
	}

	/**
	 * Check if an IP address is in a private or loopback range.
	 *
	 * @param string $ip IP address.
	 * @return bool
	 */
	private function is_private_ip( string $ip ): bool {
		return ! filter_var(
			$ip,
			FILTER_VALIDATE_IP,
			FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE
		);
	}
}
