<?php
/**
 * Firebase Shortcodes
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

class Jwt_Auth_Shortcodes {

    private static ?Jwt_Auth_Shortcodes $instance = null;

    public static function get_instance(): self {
        if ( null === self::$instance ) { self::$instance = new self(); }
        return self::$instance;
    }

    private function __construct() {}

    public function register_hooks(): void {
        add_action( 'init', [ $this, 'register_shortcodes' ] );
        add_action( 'wp_enqueue_scripts', [ $this, 'enqueue_firebase_assets' ] );
    }

    public function register_shortcodes(): void {
        add_shortcode( 'firebase_login', [ $this, 'render_login_form' ] );
        add_shortcode( 'firebase_register', [ $this, 'render_register_form' ] );
        add_shortcode( 'firebase_social_login', [ $this, 'render_social_buttons' ] );
    }

    public function enqueue_firebase_assets(): void {
        global $post;
        $has_shortcode = is_a( $post, 'WP_Post' ) && (
            has_shortcode( $post->post_content, 'firebase_login' ) ||
            has_shortcode( $post->post_content, 'firebase_register' ) ||
            has_shortcode( $post->post_content, 'firebase_social_login' )
        );
        if ( ! $has_shortcode ) { return; }

        // Firebase SDK modules are loaded only by the local UI script when needed.
        wp_enqueue_script(
            'jwt-auth-firebase-ui',
            plugin_dir_url( dirname( __FILE__ ) ) . 'public/js/firebase-ui.js',
            [],
            '2.0.0',
            true
        );
        wp_enqueue_style(
            'jwt-auth-firebase-ui',
            plugin_dir_url( dirname( __FILE__ ) ) . 'public/css/firebase-ui.css',
            [],
            '2.0.0'
        );
        wp_localize_script( 'jwt-auth-firebase-ui', 'jwtAuthFirebase', [
            'apiKeyEndpoint'     => rest_url( 'jwt-auth/v1/auth/firebase' ),
            'sessionEndpoint'    => rest_url( 'jwt-auth/v1/auth/firebase/session' ),
            'configEndpoint'     => rest_url( 'jwt-auth/v1/auth/firebase/config' ),
            'nonce'              => wp_create_nonce( 'wp_rest' ),
            'redirectUrl'        => get_option( 'jwt_auth_firebase_redirect_login', home_url() ),
            'ajaxUrl'            => admin_url( 'admin-ajax.php' ),
        ] );
    }

    public function render_login_form( array $atts ): string {
        $atts = shortcode_atts( [
            'redirect_url' => '',
            'show_social'  => 'false',
            'class'        => '',
        ], $atts, 'firebase_login' );

        $class       = esc_attr( $atts['class'] );
        $redirect    = esc_url( $atts['redirect_url'] ?: get_option( 'jwt_auth_firebase_redirect_login', home_url() ) );
        $show_social = filter_var( $atts['show_social'], FILTER_VALIDATE_BOOLEAN );

        ob_start();
        ?>
        <div class="jwt-auth-firebase-login <?php echo esc_attr( $class ); ?>" data-redirect="<?php echo esc_url( $redirect ); ?>">
            <form class="jwt-auth-firebase-login-form" novalidate>
                <?php wp_nonce_field( 'firebase_login_nonce', '_firebase_nonce' ); ?>
                <div class="jwt-auth-field">
                    <label for="firebase-email"><?php esc_html_e( 'Email', 'jwt-authenticator' ); ?></label>
                    <input type="email" id="firebase-email" name="firebase_email" required autocomplete="email" placeholder="<?php esc_attr_e( 'you@example.com', 'jwt-authenticator' ); ?>">
                </div>
                <div class="jwt-auth-field">
                    <label for="firebase-password"><?php esc_html_e( 'Password', 'jwt-authenticator' ); ?></label>
                    <input type="password" id="firebase-password" name="firebase_password" required autocomplete="current-password" placeholder="••••••••">
                </div>
                <div class="jwt-auth-error" role="alert" aria-live="polite" style="display:none"></div>
                <button type="submit" class="jwt-auth-btn jwt-auth-btn-primary">
                    <span class="jwt-auth-btn-text"><?php esc_html_e( 'Login with Firebase', 'jwt-authenticator' ); ?></span>
                    <span class="jwt-auth-btn-loading" style="display:none">…</span>
                </button>
                <?php if ( $show_social ) : ?>
                <div class="jwt-auth-divider"><span><?php esc_html_e( 'or', 'jwt-authenticator' ); ?></span></div>
                <div class="jwt-auth-social-buttons" data-providers="google,facebook,github"></div>
                <?php endif; ?>
            </form>
        </div>
        <?php
        return ob_get_clean();
    }

    public function render_register_form( array $atts ): string {
        $atts = shortcode_atts( [
            'redirect_url' => '',
            'default_role' => get_option( 'jwt_auth_firebase_default_role', 'subscriber' ),
            'class'        => '',
        ], $atts, 'firebase_register' );

        $class    = esc_attr( $atts['class'] );
        $redirect = esc_url( $atts['redirect_url'] ?: home_url() );
        $role     = esc_attr( $atts['default_role'] );

        ob_start();
        ?>
        <div class="jwt-auth-firebase-register <?php echo esc_attr( $class ); ?>" data-redirect="<?php echo esc_url( $redirect ); ?>" data-role="<?php echo esc_attr( $role ); ?>">
            <form class="jwt-auth-firebase-register-form" novalidate>
                <?php wp_nonce_field( 'firebase_register_nonce', '_firebase_nonce' ); ?>
                <div class="jwt-auth-field">
                    <label for="firebase-reg-name"><?php esc_html_e( 'Full Name', 'jwt-authenticator' ); ?></label>
                    <input type="text" id="firebase-reg-name" name="firebase_name" autocomplete="name" placeholder="<?php esc_attr_e( 'John Doe', 'jwt-authenticator' ); ?>">
                </div>
                <div class="jwt-auth-field">
                    <label for="firebase-reg-email"><?php esc_html_e( 'Email', 'jwt-authenticator' ); ?></label>
                    <input type="email" id="firebase-reg-email" name="firebase_email" required autocomplete="email" placeholder="<?php esc_attr_e( 'you@example.com', 'jwt-authenticator' ); ?>">
                </div>
                <div class="jwt-auth-field">
                    <label for="firebase-reg-password"><?php esc_html_e( 'Password', 'jwt-authenticator' ); ?></label>
                    <input type="password" id="firebase-reg-password" name="firebase_password" required autocomplete="new-password" placeholder="<?php esc_attr_e( 'Min 6 characters', 'jwt-authenticator' ); ?>">
                </div>
                <div class="jwt-auth-field">
                    <label for="firebase-reg-confirm"><?php esc_html_e( 'Confirm Password', 'jwt-authenticator' ); ?></label>
                    <input type="password" id="firebase-reg-confirm" name="firebase_confirm" required autocomplete="new-password" placeholder="••••••••">
                </div>
                <div class="jwt-auth-error" role="alert" aria-live="polite" style="display:none"></div>
                <button type="submit" class="jwt-auth-btn jwt-auth-btn-primary">
                    <span class="jwt-auth-btn-text"><?php esc_html_e( 'Create Account', 'jwt-authenticator' ); ?></span>
                    <span class="jwt-auth-btn-loading" style="display:none">…</span>
                </button>
            </form>
        </div>
        <?php
        return ob_get_clean();
    }

    public function render_social_buttons( array $atts ): string {
        $atts = shortcode_atts( [
            'providers'    => 'google,facebook,github',
            'redirect_url' => '',
            'class'        => '',
            'button_style' => 'default',
        ], $atts, 'firebase_social_login' );

        $providers    = array_map( 'trim', explode( ',', $atts['providers'] ) );
        $class        = esc_attr( $atts['class'] );
        $redirect     = esc_url( $atts['redirect_url'] ?: get_option( 'jwt_auth_firebase_redirect_login', home_url() ) );
        $button_style = esc_attr( $atts['button_style'] );

        $provider_meta = [
            'google'    => 'Google',
            'facebook'  => 'Facebook',
            'apple'     => 'Apple',
            'twitter'   => 'Twitter',
            'github'    => 'GitHub',
            'yahoo'     => 'Yahoo',
            'microsoft' => 'Microsoft',
        ];

        ob_start();
        ?>
        <div class="jwt-auth-social-login <?php echo esc_attr( $class ); ?> jwt-auth-style-<?php echo esc_attr( $button_style ); ?>" data-redirect="<?php echo esc_url( $redirect ); ?>">
        <?php foreach ( $providers as $provider ) :
            if ( ! isset( $provider_meta[ $provider ] ) ) continue;
            $label = $provider_meta[ $provider ];
        ?>
            <button
                type="button"
                class="jwt-auth-social-btn jwt-auth-social-<?php echo esc_attr( $provider ); ?>"
                data-provider="<?php echo esc_attr( $provider ); ?>"
                aria-label="<?php
                    /* translators: %s is the name of the social login provider. */
                    printf( esc_attr__( 'Continue with %s', 'jwt-authenticator' ), esc_attr( $label ) );
                ?>"
            >
                <span class="jwt-auth-social-icon" aria-hidden="true"><?php echo wp_kses( $this->get_provider_icon( $provider ), $this->get_svg_allowed_tags() ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped ?></span>
                <span class="jwt-auth-social-label"><?php
                    /* translators: %s is the name of the social login provider. */
                    printf( esc_html__( 'Continue with %s', 'jwt-authenticator' ), esc_html( $label ) );
                ?></span>
            </button>
        <?php endforeach; ?>
            <div class="jwt-auth-error" role="alert" aria-live="polite" style="display:none"></div>
        </div>
        <?php
        return ob_get_clean();
    }

    private function get_svg_allowed_tags(): array {
        return [
            'svg'  => [
                'width'   => true,
                'height'  => true,
                'viewbox' => true,
                'xmlns'   => true,
            ],
            'path' => [
                'd'    => true,
                'fill' => true,
            ],
            'rect' => [
                'x'      => true,
                'y'      => true,
                'width'  => true,
                'height' => true,
                'fill'   => true,
            ],
        ];
    }

    private function get_provider_icon( string $provider ): string {
        $icons = [
            'google'    => '<svg width="18" height="18" viewBox="0 0 18 18" xmlns="http://www.w3.org/2000/svg"><path d="M17.64 9.2c0-.637-.057-1.251-.164-1.84H9v3.481h4.844c-.209 1.125-.843 2.078-1.796 2.717v2.258h2.908c1.702-1.567 2.684-3.875 2.684-6.615z" fill="#4285F4"/><path d="M9 18c2.43 0 4.467-.806 5.956-2.18l-2.908-2.259c-.806.54-1.837.86-3.048.86-2.344 0-4.328-1.584-5.036-3.711H.957v2.332A8.997 8.997 0 009 18z" fill="#34A853"/><path d="M3.964 10.71A5.41 5.41 0 013.682 9c0-.593.102-1.17.282-1.71V4.958H.957A8.996 8.996 0 000 9c0 1.452.348 2.827.957 4.042l3.007-2.332z" fill="#FBBC05"/><path d="M9 3.58c1.321 0 2.508.454 3.44 1.345l2.582-2.58C13.463.891 11.426 0 9 0A8.997 8.997 0 00.957 4.958L3.964 7.29C4.672 5.163 6.656 3.58 9 3.58z" fill="#EA4335"/></svg>',
            'facebook'  => '<svg width="18" height="18" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg"><path d="M24 12.073C24 5.405 18.627 0 12 0S0 5.405 0 12.073C0 18.1 4.388 23.094 10.125 24v-8.437H7.078v-3.49h3.047V9.41c0-3.025 1.792-4.697 4.533-4.697 1.312 0 2.686.236 2.686.236v2.97h-1.513c-1.491 0-1.956.93-1.956 1.886v2.267h3.328l-.532 3.49h-2.796V24C19.612 23.094 24 18.1 24 12.073z" fill="#fff"/></svg>',
            'apple'     => '<svg width="18" height="18" viewBox="0 0 814 1000" xmlns="http://www.w3.org/2000/svg"><path d="M788.1 340.9c-5.8 4.5-108.2 62.2-108.2 190.5 0 148.4 130.3 200.9 134.2 202.2-.6 3.2-20.7 71.9-68.7 141.9-42.8 61.6-87.5 123.1-155.5 123.1s-85.5-39.5-164-39.5c-76.5 0-103.7 40.8-165.9 40.8s-105.7-57.2-155.5-127.4C46 790.7 0 663 0 541.8c0-207.3 136.1-317 270.1-317 70.8 0 129.9 46.4 173.9 46.4 42.8 0 109.7-49 192.6-49 30.8 0 108.2 2.6 168.5 80.1zm-80.4-167.3c0 2.6-.9 4.5-1.3 7.2-23.5 65.5-72.2 113.6-124.4 113.6-5.4 0-11.3-.9-16.2-2.6C551.2 268 532 198.3 532 136.3c0-6.4.6-12.9 1.3-19.3 48.4-8.3 89.2 23.5 115.5 73.9 13.5 25.1 20.4 52.4 20.4 79.4 0 1.9-.4 3.8-.4 5.7l-.6-1.4z" fill="#fff"/></svg>',
            'twitter'   => '<svg width="18" height="18" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg"><path d="M23.953 4.57a10 10 0 01-2.825.775 4.958 4.958 0 002.163-2.723c-.951.555-2.005.959-3.127 1.184a4.92 4.92 0 00-8.384 4.482C7.69 8.095 4.067 6.13 1.64 3.162a4.822 4.822 0 00-.666 2.475c0 1.71.87 3.213 2.188 4.096a4.904 4.904 0 01-2.228-.616v.06a4.923 4.923 0 003.946 4.827 4.996 4.996 0 01-2.212.085 4.936 4.936 0 004.604 3.417 9.867 9.867 0 01-6.102 2.105c-.39 0-.779-.023-1.17-.067a13.995 13.995 0 007.557 2.209c9.053 0 13.998-7.496 13.998-13.985 0-.21 0-.42-.015-.63A9.935 9.935 0 0024 4.59l-.047-.02z" fill="#fff"/></svg>',
            'github'    => '<svg width="18" height="18" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg"><path d="M12 .297c-6.63 0-12 5.373-12 12 0 5.303 3.438 9.8 8.205 11.385.6.113.82-.258.82-.577 0-.285-.01-1.04-.015-2.04-3.338.724-4.042-1.61-4.042-1.61C4.422 18.07 3.633 17.7 3.633 17.7c-1.087-.744.084-.729.084-.729 1.205.084 1.838 1.236 1.838 1.236 1.07 1.835 2.809 1.305 3.495.998.108-.776.417-1.305.76-1.605-2.665-.3-5.466-1.332-5.466-5.93 0-1.31.465-2.38 1.235-3.22-.135-.303-.54-1.523.105-3.176 0 0 1.005-.322 3.3 1.23.96-.267 1.98-.399 3-.405 1.02.006 2.04.138 3 .405 2.28-1.552 3.285-1.23 3.285-1.23.645 1.653.24 2.873.12 3.176.765.84 1.23 1.91 1.23 3.22 0 4.61-2.805 5.625-5.475 5.92.42.36.81 1.096.81 2.22 0 1.606-.015 2.896-.015 3.286 0 .315.21.69.825.57C20.565 22.092 24 17.592 24 12.297c0-6.627-5.373-12-12-12" fill="#fff"/></svg>',
            'yahoo'     => '<svg width="18" height="18" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg"><path d="M24 0H0v24h24V0z" fill="#6001D2"/><path d="M14.308 0H24v7H14.308L9.231 7V0h5.077zM0 0h9.231v7L4.615 15H0V0zm4.615 15h4.616v9H4.615v-9z" fill="#fff"/></svg>',
            'microsoft' => '<svg width="18" height="18" viewBox="0 0 23 23" xmlns="http://www.w3.org/2000/svg"><rect x="0" y="0" width="11" height="11" fill="#f25022"/><rect x="12" y="0" width="11" height="11" fill="#7fba00"/><rect x="0" y="12" width="11" height="11" fill="#00a4ef"/><rect x="12" y="12" width="11" height="11" fill="#ffb900"/></svg>',
        ];
        return $icons[ $provider ] ?? '';
    }
}
