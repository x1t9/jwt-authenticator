<?php
/**
 * WooCommerce + Firebase Integration
 *
 * MIT License
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
 * @since   2.0.0
 */

if ( ! defined( 'ABSPATH' ) ) { exit; }

class Jwt_Auth_WooCommerce {

    private static ?Jwt_Auth_WooCommerce $instance = null;

    public static function get_instance(): self {
        if ( null === self::$instance ) { self::$instance = new self(); }
        return self::$instance;
    }

    private function __construct() {}

    public function register_hooks(): void {
        if ( ! class_exists( 'WooCommerce' ) ) { return; }

        if ( get_option( 'jwt_auth_woo_firebase_checkout', false ) ) {
            add_action( 'woocommerce_before_checkout_form', [ $this, 'add_firebase_login_to_checkout' ], 5 );
        }

        if ( get_option( 'jwt_auth_woo_firebase_myaccount', false ) ) {
            add_action( 'woocommerce_before_customer_login_form', [ $this, 'add_firebase_login_to_myaccount' ], 5 );
        }

        if ( get_option( 'jwt_auth_woo_sync_to_firebase', false ) ) {
            add_action( 'woocommerce_created_customer', [ $this, 'sync_new_customer_to_firebase' ], 10, 3 );
        }
    }

    public function add_firebase_login_to_checkout(): void {
        if ( is_user_logged_in() ) { return; }
        $redirect = function_exists( 'wc_get_checkout_url' ) ? wc_get_checkout_url() : home_url( '/checkout/' );
        echo do_shortcode( '[firebase_login redirect_url="' . esc_url( $redirect ) . '" show_social="true"]' );
    }

    public function add_firebase_login_to_myaccount(): void {
        if ( is_user_logged_in() ) { return; }
        $redirect = function_exists( 'wc_get_account_endpoint_url' ) ? wc_get_account_endpoint_url( 'dashboard' ) : home_url( '/my-account/' );
        echo do_shortcode( '[firebase_login redirect_url="' . esc_url( $redirect ) . '" show_social="true"]' );
    }

    public function sync_new_customer_to_firebase( int $customer_id, array $new_customer_data, bool $password_generated ): void {
        $web_api_key = get_option( 'jwt_auth_firebase_web_api_key', '' );
        if ( empty( $web_api_key ) ) {
            return;
        }

        $user = get_userdata( $customer_id );
        if ( ! $user ) { return; }

        $email    = $user->user_email;
        $password = $new_customer_data['user_pass'] ?? wp_generate_password( 16, true, true );

        $response = wp_remote_post(
            'https://identitytoolkit.googleapis.com/v1/accounts:signUp?key=' . rawurlencode( $web_api_key ),
            [
                'timeout' => 15,
                'headers' => [ 'Content-Type' => 'application/json' ],
                'body'    => wp_json_encode( [
                    'email'             => $email,
                    'password'          => $password,
                    'returnSecureToken' => false,
                ] ),
            ]
        );

        if ( is_wp_error( $response ) ) {
            return;
        }

        $body = json_decode( wp_remote_retrieve_body( $response ), true );
        if ( ! empty( $body['localId'] ) ) {
            update_user_meta( $customer_id, 'firebase_uid', sanitize_text_field( $body['localId'] ) );
            do_action( 'jwt_auth_woo_customer_synced_to_firebase', $customer_id, $body );
        } else {
        }
    }
}
