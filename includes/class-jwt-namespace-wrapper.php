<?php

/**
 * Define a `wrapper namespace` to load the Firebase's JWT & Key classes
 * and prevent conflicts with other plugins using the same library
 * with different versions.
 *
 * @link       https://github.com/x1t9/jwt-authenticator
 * @since      1.3.2
 * @author     x1t9
 */

namespace JwtAuthenticator\Firebase\JWT;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class JWT extends \Firebase\JWT\JWT {
}

class Key extends \Firebase\JWT\Key {
}
