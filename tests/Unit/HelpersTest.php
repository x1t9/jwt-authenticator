<?php
/**
 * Unit tests for Jwt_Auth_Helpers pure-logic methods.
 */

use PHPUnit\Framework\TestCase;

class HelpersTest extends TestCase {

	public function test_sanitize_route_normalizes_slashes_and_case(): void {
		$this->assertSame( '/wp/v2/posts', Jwt_Auth_Helpers::sanitize_route( 'wp/v2/posts/' ) );
		$this->assertSame( '/wp/v2/posts', Jwt_Auth_Helpers::sanitize_route( '  /WP/V2/Posts  ' ) );
		$this->assertSame( '/jwt-auth/v1/token', Jwt_Auth_Helpers::sanitize_route( '///jwt-auth/v1/token///' ) );
	}

	public function test_is_route_whitelisted_plain_match(): void {
		$this->assertTrue( Jwt_Auth_Helpers::is_route_whitelisted( '/wp/v2/posts', [ '/wp/v2/posts' ] ) );
		$this->assertFalse( Jwt_Auth_Helpers::is_route_whitelisted( '/wp/v2/pages', [ '/wp/v2/posts' ] ) );
	}

	public function test_is_route_whitelisted_regex_pattern(): void {
		$this->assertTrue( Jwt_Auth_Helpers::is_route_whitelisted( '/wp/v2/posts/42', [ '~/wp/v2/posts/\d+~' ] ) );
		$this->assertFalse( Jwt_Auth_Helpers::is_route_whitelisted( '/wp/v2/posts/abc', [ '~/wp/v2/posts/\d+~' ] ) );
	}

	public function test_hash_token_is_sha256_hex(): void {
		$this->assertSame( hash( 'sha256', 'abc' ), Jwt_Auth_Helpers::hash_token( 'abc' ) );
		$this->assertSame( 64, strlen( Jwt_Auth_Helpers::hash_token( 'abc' ) ) );
	}

	public function test_hash_api_key_is_sha256_hex(): void {
		$this->assertSame( hash( 'sha256', 'secret' ), Jwt_Auth_Helpers::hash_api_key( 'secret' ) );
	}

	public function test_generate_api_key_format(): void {
		$key = Jwt_Auth_Helpers::generate_api_key();
		$this->assertStringStartsWith( 'jwta_', $key );
		$this->assertMatchesRegularExpression( '/^jwta_[0-9a-f]{48}$/', $key );
	}

	public function test_generate_api_key_is_unique(): void {
		$this->assertNotSame( Jwt_Auth_Helpers::generate_api_key(), Jwt_Auth_Helpers::generate_api_key() );
	}
}
