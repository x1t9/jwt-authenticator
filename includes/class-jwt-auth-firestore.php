<?php
/**
 * Firestore Sync Integration
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

class Jwt_Auth_Firestore {

    private static ?Jwt_Auth_Firestore $instance = null;
    private string $access_token_transient = 'jwt_auth_firestore_access_token';

    public static function get_instance(): self {
        if ( null === self::$instance ) { self::$instance = new self(); }
        return self::$instance;
    }

    private function __construct() {}

    public function register_hooks(): void {
        if ( ! get_option( 'jwt_auth_firestore_enabled', false ) ) { return; }

        if ( get_option( 'jwt_auth_firestore_sync_user_meta', false ) ) {
            add_action( 'updated_user_meta', [ $this, 'sync_user_meta' ], 10, 4 );
            add_action( 'added_user_meta',   [ $this, 'sync_user_meta' ], 10, 4 );
        }

        if ( class_exists( 'WooCommerce' ) ) {
            if ( get_option( 'jwt_auth_firestore_sync_woo_products', false ) ) {
                add_action( 'woocommerce_update_product', [ $this, 'sync_product' ], 10, 1 );
                add_action( 'save_post_product',          [ $this, 'sync_product_on_save' ], 10, 3 );
            }
            if ( get_option( 'jwt_auth_firestore_sync_woo_orders', false ) ) {
                add_action( 'woocommerce_order_status_changed', [ $this, 'sync_order' ], 10, 4 );
            }
        }
    }

    /**
     * @return string|WP_Error
     */
    private function get_access_token() {
        $cached = get_transient( $this->access_token_transient );
        if ( $cached ) { return $cached; }

        $service_account_json = get_option( 'jwt_auth_firebase_service_account', '' );
        if ( empty( $service_account_json ) ) {
            return new WP_Error( 'firestore_no_service_account', 'Firebase service account not configured.' );
        }

        $sa = json_decode( $service_account_json, true );
        if ( ! isset( $sa['client_email'], $sa['private_key'] ) ) {
            return new WP_Error( 'firestore_bad_service_account', 'Invalid service account JSON.' );
        }

        $now     = time();
        $header  = base64_encode( json_encode( [ 'alg' => 'RS256', 'typ' => 'JWT' ] ) );
        $payload = base64_encode( json_encode( [
            'iss'   => $sa['client_email'],
            'sub'   => $sa['client_email'],
            'aud'   => 'https://oauth2.googleapis.com/token',
            'iat'   => $now,
            'exp'   => $now + 3600,
            'scope' => 'https://www.googleapis.com/auth/datastore',
        ] ) );

        $data_to_sign = $header . '.' . $payload;
        $signature    = '';
        openssl_sign( $data_to_sign, $signature, $sa['private_key'], OPENSSL_ALGO_SHA256 );
        $jwt = $data_to_sign . '.' . base64_encode( $signature );

        $response = wp_remote_post( 'https://oauth2.googleapis.com/token', [
            'timeout' => 15,
            'body'    => [
                'grant_type' => 'urn:ietf:params:oauth:grant-type:jwt-bearer',
                'assertion'  => $jwt,
            ],
        ] );

        if ( is_wp_error( $response ) ) { return $response; }

        $body  = json_decode( wp_remote_retrieve_body( $response ), true );
        $token = $body['access_token'] ?? '';
        if ( empty( $token ) ) {
            return new WP_Error( 'firestore_token_error', 'Failed to obtain Firestore access token.' );
        }

        set_transient( $this->access_token_transient, $token, 3000 ); // cache 50 min
        return $token;
    }

    /**
     * @param mixed $value
     */
    private function to_firestore_value( $value ): array {
        if ( is_int( $value ) )    return [ 'integerValue'  => (string) $value ];
        if ( is_float( $value ) )  return [ 'doubleValue'   => $value ];
        if ( is_bool( $value ) )   return [ 'booleanValue'  => $value ];
        if ( is_null( $value ) )   return [ 'nullValue'     => null ];
        if ( is_array( $value ) )  return [ 'stringValue'   => json_encode( $value ) ];
        return [ 'stringValue' => (string) $value ];
    }

    /**
     * @return array|WP_Error
     */
    private function firestore_request( string $method, string $collection, string $doc_id, array $data = [] ) {
        $token = $this->get_access_token();
        if ( is_wp_error( $token ) ) { return $token; }

        $project_id = get_option( 'jwt_auth_firestore_project_id', get_option( 'jwt_auth_firebase_project_id', '' ) );
        if ( empty( $project_id ) ) {
            return new WP_Error( 'firestore_no_project', 'Firestore project ID not configured.' );
        }

        $url    = "https://firestore.googleapis.com/v1/projects/{$project_id}/databases/(default)/documents/{$collection}/{$doc_id}";
        $fields = [];
        foreach ( $data as $key => $value ) {
            $fields[ $key ] = $this->to_firestore_value( $value );
        }

        $response = wp_remote_request( $url, [
            'method'  => $method,
            'timeout' => 15,
            'headers' => [
                'Authorization' => 'Bearer ' . $token,
                'Content-Type'  => 'application/json',
            ],
            'body' => $method !== 'GET' ? wp_json_encode( [ 'fields' => $fields ] ) : null,
        ] );

        if ( is_wp_error( $response ) ) { return $response; }

        return json_decode( wp_remote_retrieve_body( $response ), true ) ?: [];
    }

    public function sync_user_meta( int $meta_id, int $user_id, string $meta_key, $meta_value ): void {
        // Skip internal WP meta unless explicitly allowed
        $allowed_fields = json_decode( get_option( 'jwt_auth_firestore_user_meta_fields', '[]' ), true );
        if ( ! empty( $allowed_fields ) && ! in_array( $meta_key, $allowed_fields, true ) ) { return; }
        if ( empty( $allowed_fields ) && ( strpos( $meta_key, '_' ) === 0 ) ) { return; }

        $user = get_userdata( $user_id );
        if ( ! $user ) { return; }

        $data = [
            'wp_user_id'    => $user_id,
            'display_name'  => $user->display_name,
            'user_email'    => $user->user_email,
            'user_login'    => $user->user_login,
            'roles'         => implode( ',', $user->roles ),
            $meta_key       => is_array( $meta_value ) ? json_encode( $meta_value ) : (string) $meta_value,
        ];

        $this->firestore_request( 'PATCH', 'wp_users', (string) $user_id, $data );
    }

    public function sync_product( int $product_id ): void {
        if ( ! function_exists( 'wc_get_product' ) ) { return; }
        $product = wc_get_product( $product_id );
        if ( ! $product ) { return; }

        $data = [
            'wp_product_id' => $product_id,
            'name'          => $product->get_name(),
            'sku'           => $product->get_sku(),
            'price'         => $product->get_price(),
            'stock_status'  => $product->get_stock_status(),
            'status'        => $product->get_status(),
            'permalink'     => get_permalink( $product_id ),
        ];

        $this->firestore_request( 'PATCH', 'wc_products', (string) $product_id, $data );
    }

    public function sync_product_on_save( int $post_id, \WP_Post $post, bool $update ): void {
        if ( $update ) { $this->sync_product( $post_id ); }
    }

    public function sync_order( int $order_id, string $old_status, string $new_status, $order ): void {
        if ( ! is_a( $order, 'WC_Abstract_Order' ) ) { return; }

        $data = [
            'wp_order_id'    => $order_id,
            'status'         => $new_status,
            'old_status'     => $old_status,
            'total'          => $order->get_total(),
            'currency'       => $order->get_currency(),
            'customer_id'    => $order->get_customer_id(),
            'customer_email' => $order->get_billing_email(),
            'item_count'     => $order->get_item_count(),
        ];

        $this->firestore_request( 'PATCH', 'wc_orders', (string) $order_id, $data );
    }
}
