<?php
/**
 * PHPUnit bootstrap for JWT Authenticator.
 *
 * Defines the minimum WordPress stubs needed to load the pure-logic classes
 * under test, without booting WordPress. Only functions actually invoked by
 * the tested code are stubbed.
 */

if ( ! defined( 'WPINC' ) ) {
	define( 'WPINC', 'wp-includes' );
}
if ( ! defined( 'ABSPATH' ) ) {
	define( 'ABSPATH', __DIR__ . '/../' );
}

if ( ! function_exists( 'wp_strip_all_tags' ) ) {
	function wp_strip_all_tags( $text ) {
		$text = is_scalar( $text ) ? (string) $text : '';
		return trim( (string) preg_replace( '/<[^>]*>/', '', $text ) );
	}
}

if ( ! function_exists( 'sanitize_text_field' ) ) {
	/**
	 * Faithful-enough stub of WordPress' sanitize_text_field() for tests.
	 *
	 * @param mixed $str Input.
	 * @return string
	 */
	function sanitize_text_field( $str ) {
		$str = is_scalar( $str ) ? (string) $str : '';
		$str = wp_strip_all_tags( $str );
		$str = preg_replace( '/[\r\n\t]+/', ' ', $str );
		return trim( $str );
	}
}

require __DIR__ . '/../includes/class-jwt-auth-helpers.php';
require __DIR__ . '/../admin/class-jwt-auth-admin.php';
