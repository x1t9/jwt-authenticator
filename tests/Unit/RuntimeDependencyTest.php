<?php

use PHPUnit\Framework\TestCase;
use JwtAuthenticator\Firebase\JWT\JWT;
use JwtAuthenticator\Firebase\JWT\Key;

require_once __DIR__ . '/../../includes/vendor/autoload.php';
require_once __DIR__ . '/../../includes/class-jwt-namespace-wrapper.php';

final class RuntimeDependencyTest extends TestCase {
	public function test_bundled_jwt_library_signs_and_verifies_a_token(): void {
		$secret = str_repeat( 'k', 32 );
		$token  = JWT::encode(
			[
				'sub' => 'release-smoke-test',
				'iat' => time(),
				'exp' => time() + 60,
			],
			$secret,
			'HS256'
		);

		$decoded = JWT::decode( $token, new Key( $secret, 'HS256' ) );

		$this->assertSame( 'release-smoke-test', $decoded->sub );
	}
}
