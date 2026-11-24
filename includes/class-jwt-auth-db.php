<?php

/**
 * Full database installer for JWT Authenticator.
 *
 * Creates and upgrades all plugin tables using dbDelta().
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
 * Class Jwt_Auth_DB
 *
 * Handles creation and upgrade of all JWT Authenticator database tables.
 *
 * @since 2.0.0
 */
class Jwt_Auth_DB {

	/**
	 * Current DB schema version.
	 *
	 * Bump this string whenever the schema changes to trigger a re-run of dbDelta().
	 *
	 * @since 2.0.0
	 * @var string
	 */
	private const DB_VERSION = '2.0.0';

	/**
	 * WordPress option key used to store the installed DB schema version.
	 *
	 * @since 2.0.0
	 * @var string
	 */
	private const DB_VERSION_OPTION = 'jwt_auth_db_version';

	// -------------------------------------------------------------------------
	// Public API
	// -------------------------------------------------------------------------

	/**
	 * Return the current (target) DB schema version string.
	 *
	 * @since 2.0.0
	 * @return string
	 */
	public static function get_db_version(): string {
		return self::DB_VERSION;
	}

	/**
	 * Run dbDelta() for all plugin tables when the installed version is outdated.
	 *
	 * Safe to call on every activation; it is a no-op when the schema is current.
	 *
	 * @since 2.0.0
	 * @return void
	 */
	public static function install(): void {
		$installed = get_option( self::DB_VERSION_OPTION, '' );

		if ( version_compare( $installed, self::DB_VERSION, '>=' ) ) {
			return;
		}

		require_once ABSPATH . 'wp-admin/includes/upgrade.php';

		self::create_tokens_table();
		self::create_api_keys_table();
		self::create_rate_limits_table();
		self::create_analytics_table();

		update_option( self::DB_VERSION_OPTION, self::DB_VERSION );
	}

	// -------------------------------------------------------------------------
	// Private table creators
	// -------------------------------------------------------------------------

	/**
	 * Create / upgrade the jwt_tokens table.
	 *
	 * Stores every issued access and refresh token so they can be revoked.
	 *
	 * @since 2.0.0
	 * @return void
	 */
	private static function create_tokens_table(): void {
		global $wpdb;

		$table      = $wpdb->prefix . 'jwt_tokens';
		$charset_collate = $wpdb->get_charset_collate();

		$sql = "CREATE TABLE {$table} (
			id BIGINT(20) UNSIGNED NOT NULL AUTO_INCREMENT,
			user_id BIGINT(20) UNSIGNED NOT NULL,
			token_hash VARCHAR(64) NOT NULL,
			token_type VARCHAR(20) NOT NULL DEFAULT 'access',
			jti VARCHAR(64) NOT NULL,
			issued_at DATETIME NOT NULL,
			expires_at DATETIME NOT NULL,
			revoked TINYINT(1) NOT NULL DEFAULT 0,
			revoked_at DATETIME DEFAULT NULL,
			ip_address VARCHAR(45) DEFAULT NULL,
			user_agent TEXT DEFAULT NULL,
			PRIMARY KEY  (id),
			UNIQUE KEY idx_jti (jti),
			KEY idx_user_id (user_id),
			KEY idx_token_hash (token_hash)
		) {$charset_collate};";

		dbDelta( $sql );
	}

	/**
	 * Create / upgrade the jwt_api_keys table.
	 *
	 * Stores hashed API keys and their metadata.
	 *
	 * @since 2.0.0
	 * @return void
	 */
	private static function create_api_keys_table(): void {
		global $wpdb;

		$table           = $wpdb->prefix . 'jwt_api_keys';
		$charset_collate = $wpdb->get_charset_collate();

		$sql = "CREATE TABLE {$table} (
			id BIGINT(20) UNSIGNED NOT NULL AUTO_INCREMENT,
			user_id BIGINT(20) UNSIGNED DEFAULT NULL,
			api_key VARCHAR(64) NOT NULL,
			key_hash VARCHAR(64) NOT NULL,
			name VARCHAR(255) NOT NULL,
			permissions TEXT DEFAULT NULL,
			last_used DATETIME DEFAULT NULL,
			expires_at DATETIME DEFAULT NULL,
			active TINYINT(1) NOT NULL DEFAULT 1,
			created_at DATETIME NOT NULL,
			PRIMARY KEY  (id),
			UNIQUE KEY idx_key_hash (key_hash),
			KEY idx_user_id (user_id),
			KEY idx_api_key (api_key)
		) {$charset_collate};";

		dbDelta( $sql );
	}

	/**
	 * Create / upgrade the jwt_rate_limits table.
	 *
	 * Tracks per-identifier, per-endpoint request counts inside a sliding window.
	 *
	 * @since 2.0.0
	 * @return void
	 */
	private static function create_rate_limits_table(): void {
		global $wpdb;

		$table           = $wpdb->prefix . 'jwt_rate_limits';
		$charset_collate = $wpdb->get_charset_collate();

		$sql = "CREATE TABLE {$table} (
			id BIGINT(20) UNSIGNED NOT NULL AUTO_INCREMENT,
			identifier VARCHAR(128) NOT NULL,
			endpoint VARCHAR(255) NOT NULL,
			requests INT UNSIGNED NOT NULL DEFAULT 1,
			window_start DATETIME NOT NULL,
			PRIMARY KEY  (id),
			KEY idx_identifier_endpoint (identifier, endpoint),
			KEY idx_window_start (window_start)
		) {$charset_collate};";

		dbDelta( $sql );
	}

	/**
	 * Create / upgrade the jwt_analytics table.
	 *
	 * Logs auth events for the analytics dashboard.
	 *
	 * @since 2.0.0
	 * @return void
	 */
	private static function create_analytics_table(): void {
		global $wpdb;

		$table           = $wpdb->prefix . 'jwt_analytics';
		$charset_collate = $wpdb->get_charset_collate();

		$sql = "CREATE TABLE {$table} (
			id BIGINT(20) UNSIGNED NOT NULL AUTO_INCREMENT,
			event_type VARCHAR(50) NOT NULL,
			user_id BIGINT(20) UNSIGNED DEFAULT NULL,
			endpoint VARCHAR(255) DEFAULT NULL,
			auth_method VARCHAR(50) DEFAULT NULL,
			ip_address VARCHAR(45) DEFAULT NULL,
			country_code VARCHAR(2) DEFAULT NULL,
			country_name VARCHAR(100) DEFAULT NULL,
			user_agent TEXT DEFAULT NULL,
			metadata TEXT DEFAULT NULL,
			created_at DATETIME NOT NULL,
			PRIMARY KEY  (id),
			KEY idx_event_type (event_type),
			KEY idx_user_id (user_id),
			KEY idx_created_at (created_at),
			KEY idx_auth_method (auth_method)
		) {$charset_collate};";

		dbDelta( $sql );
	}
}
