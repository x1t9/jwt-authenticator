<?php
/**
 * Unit tests for Jwt_Auth_Admin::sanitize_settings() (pure sanitizer).
 */

use PHPUnit\Framework\TestCase;

class SettingsSanitizerTest extends TestCase {

	public function test_empty_input_returns_empty_array(): void {
		$this->assertSame( [], Jwt_Auth_Admin::sanitize_settings( [] ) );
	}

	public function test_unknown_keys_are_ignored(): void {
		$r = Jwt_Auth_Admin::sanitize_settings( [ 'bogus_key' => 'x', 'oauth_enabled' => true ] );
		$this->assertArrayNotHasKey( 'bogus_key', $r );
		$this->assertTrue( $r['oauth_enabled'] );
	}

	public function test_int_is_clamped_to_minimum(): void {
		$r = Jwt_Auth_Admin::sanitize_settings( [ 'access_token_expiry' => 10 ] );
		$this->assertSame( 60, $r['access_token_expiry'] );
	}

	public function test_int_accepts_valid_value(): void {
		$r = Jwt_Auth_Admin::sanitize_settings( [ 'rate_limit_requests' => 250 ] );
		$this->assertSame( 250, $r['rate_limit_requests'] );
	}

	public function test_bool_is_cast(): void {
		$r = Jwt_Auth_Admin::sanitize_settings( [ 'oauth_enabled' => 0, 'firebase_enabled' => 1 ] );
		$this->assertFalse( $r['oauth_enabled'] );
		$this->assertTrue( $r['firebase_enabled'] );
	}

	public function test_enum_falls_back_to_first_value_when_invalid(): void {
		$r = Jwt_Auth_Admin::sanitize_settings( [ 'protection_mode' => 'bogus' ] );
		$this->assertSame( 'disabled', $r['protection_mode'] );
	}

	public function test_enum_accepts_valid_value(): void {
		$r = Jwt_Auth_Admin::sanitize_settings( [ 'protection_mode' => 'full', 'firebase_login_mode' => 'firebase_only' ] );
		$this->assertSame( 'full', $r['protection_mode'] );
		$this->assertSame( 'firebase_only', $r['firebase_login_mode'] );
	}

	public function test_lines_split_string_and_drop_blanks(): void {
		$r = Jwt_Auth_Admin::sanitize_settings( [ 'whitelisted_routes' => "/wp/v2/posts\n  /jwt-auth/v1/token  \n\n" ] );
		$this->assertSame( [ '/wp/v2/posts', '/jwt-auth/v1/token' ], $r['whitelisted_routes'] );
	}

	public function test_lines_accept_array_and_drop_blanks(): void {
		$r = Jwt_Auth_Admin::sanitize_settings( [ 'disabled_endpoints' => [ '/wp/v2/users', '   ', '/wc/v3/*' ] ] );
		$this->assertSame( [ '/wp/v2/users', '/wc/v3/*' ], $r['disabled_endpoints'] );
	}

	public function test_providers_are_filtered_to_allowed_set(): void {
		$r = Jwt_Auth_Admin::sanitize_settings( [ 'firebase_enabled_providers' => [ 'google', 'bogus', 'github', 'phone' ] ] );
		$this->assertSame( [ 'google', 'github', 'phone' ], $r['firebase_enabled_providers'] );
	}

	public function test_providers_non_array_yields_empty(): void {
		$r = Jwt_Auth_Admin::sanitize_settings( [ 'firebase_enabled_providers' => 'google' ] );
		$this->assertSame( [], $r['firebase_enabled_providers'] );
	}

	public function test_text_is_sanitized(): void {
		$r = Jwt_Auth_Admin::sanitize_settings( [ 'custom_header' => '  <b>X-Auth-Token</b>  ' ] );
		$this->assertSame( 'X-Auth-Token', $r['custom_header'] );
	}
}
