<?php

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * The file that defines the core plugin class.
 *
 * A class definition that includes attributes and functions used across both the
 * public-facing side of the site and the admin area.
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
 * @since 1.0.0
 */

/**
 * The core plugin class.
 *
 * This is used to define internationalization, admin-specific hooks, and
 * public-facing site hooks.
 *
 * Also maintains the unique identifier of this plugin as well as the current
 * version of the plugin.
 *
 * @since 1.0.0
 * @since 2.0.0 Removed REMOTE_API_URL const; added wiring for all new modules.
 *
 * @author x1t9
 */
class Jwt_Auth {

	/**
	 * The loader that's responsible for maintaining and registering all hooks that power
	 * the plugin.
	 *
	 * @since 1.0.0
	 * @var Jwt_Auth_Loader Maintains and registers all hooks for the plugin.
	 */
	protected $loader;

	/**
	 * The unique identifier of this plugin.
	 *
	 * @since 1.0.0
	 * @var string The string used to uniquely identify this plugin.
	 */
	protected $plugin_name;

	/**
	 * The current version of the plugin.
	 *
	 * @since 1.0.0
	 * @var string The current version of the plugin.
	 */
	protected $version;

	/**
	 * Define the core functionality of the plugin.
	 *
	 * Set the plugin name and the plugin version that can be used throughout the plugin.
	 * Load the dependencies, define the locale, and set the hooks for the admin area and
	 * the public-facing side of the site.
	 *
	 * @since 1.0.0
	 */
	public function __construct() {
		$this->plugin_name = 'jwt-authenticator';
		$this->version     = '1.3.0';

		$this->load_dependencies();
		$this->define_public_hooks();
		$this->define_admin_hooks();
	}

	/**
	 * Load the required dependencies for this plugin.
	 *
	 * Include the following files that make up the plugin:
	 *
	 * - Jwt_Auth_Loader.      Orchestrates the hooks of the plugin.
	 * - Jwt_Auth_Admin.       Defines all hooks for the admin area.
	 * - Jwt_Auth_Public.      Defines all hooks for the public side of the site.
	 * - Jwt_Auth_DB.          Database installer / upgrader.
	 * - Jwt_Auth_Helpers.     Static utility helpers.
	 * - New feature modules.
	 *
	 * @since 1.0.0
	 * @since 2.0.0 Added all new module requires.
	 */
	private function load_dependencies() {

		$base = plugin_dir_path( dirname( __FILE__ ) );

		/**
		 * Load dependencies managed by composer.
		 */
		require_once $base . 'includes/vendor/autoload.php';

		/**
		 * The class responsible for orchestrating the actions and filters of the core plugin.
		 */
		require_once $base . 'includes/class-jwt-auth-loader.php';

		/**
		 * Class responsible for creating a `wrapper namespace` to load the Firebase's JWT & Key
		 * classes and prevent conflicts with other plugins using the same library with different versions.
		 */
		require_once $base . 'includes/class-jwt-namespace-wrapper.php';

		/**
		 * The class responsible for defining all actions that occur in the public-facing side of the site.
		 */
		require_once $base . 'public/class-jwt-auth-public.php';

		/**
		 * The class responsible for defining all actions that occur in the admin-facing side of the site.
		 */
		require_once $base . 'admin/class-jwt-auth-admin.php';

		// -----------------------------------------------------------------
		// Foundation modules (always loaded).
		// -----------------------------------------------------------------

		/** Database installer. */
		require_once $base . 'includes/class-jwt-auth-db.php';

		/** Static helper utilities. */
		require_once $base . 'includes/class-jwt-auth-helpers.php';

		/** Token lifecycle management (issue, refresh, revoke). */
		require_once $base . 'includes/class-jwt-auth-token-manager.php';

		/** API key authentication. */
		require_once $base . 'includes/class-jwt-auth-api-keys.php';

		/** OAuth 2.0 provider integration. */
		require_once $base . 'includes/class-jwt-auth-oauth.php';

		/** REST API route protection. */
		require_once $base . 'includes/class-jwt-auth-protection.php';

		/** Rate limiter. */
		require_once $base . 'includes/class-jwt-auth-rate-limiter.php';

		/** Geo-IP lookup. */
		require_once $base . 'includes/class-jwt-auth-geo-ip.php';

		/** Analytics event logger. */
		require_once $base . 'includes/class-jwt-auth-analytics.php';

		/** Firebase authentication. */
		require_once $base . 'includes/class-jwt-auth-firebase.php';

		/** Frontend shortcodes. */
		require_once $base . 'includes/class-jwt-auth-shortcodes.php';

		/** Third-party JWT provider exchange. */
		require_once $base . 'includes/class-jwt-auth-third-party-jwt.php';

		/** Firestore sync. */
		require_once $base . 'includes/class-jwt-auth-firestore.php';

		// -----------------------------------------------------------------
		// Optional / conditional modules.
		// -----------------------------------------------------------------

		/** WooCommerce integration — only loaded when WooCommerce is active. */
		if ( class_exists( 'WooCommerce' ) ) {
			require_once $base . 'includes/class-jwt-auth-woocommerce.php';
		}

		$this->loader = new Jwt_Auth_Loader();
	}

	/**
	 * Register all the hooks related to the public-facing functionality of the plugin.
	 *
	 * @since 1.0.0
	 * @since 2.0.0 Added protection, rate-limiter, analytics, API keys, token manager,
	 *              Firebase and shortcode hooks.
	 */
	private function define_public_hooks() {

		// Legacy public class (JWT token generation endpoint, CORS, auth filter).
		$plugin_public = new Jwt_Auth_Public( $this->get_plugin_name(), $this->get_version() );
		$this->loader->add_action( 'rest_api_init', $plugin_public, 'add_api_routes' );
		$this->loader->add_filter( 'rest_api_init', $plugin_public, 'add_cors_support' );
		$this->loader->add_filter( 'rest_pre_dispatch', $plugin_public, 'rest_pre_dispatch', 10, 2 );
		$this->loader->add_filter( 'determine_current_user', $plugin_public, 'determine_current_user' );

		// REST API route protection (allow-list / block-list enforcement).
		$protection = Jwt_Auth_Protection::get_instance();
		$this->loader->add_filter( 'rest_pre_dispatch', $protection, 'check_protection', 5, 3 );
		$this->loader->add_action( 'rest_api_init', $protection, 'register_admin_routes' );

		// Rate limiter.
		$rate_limiter = Jwt_Auth_Rate_Limiter::get_instance();
		$this->loader->add_filter( 'rest_pre_dispatch', $rate_limiter, 'check_rate_limit', 8, 3 );
		$this->loader->add_action( 'rest_api_init', $rate_limiter, 'register_admin_routes' );

		// Analytics event logger.
		$analytics = Jwt_Auth_Analytics::get_instance();
		$this->loader->add_action( 'rest_api_init', $analytics, 'register_analytics_routes' );
		$this->loader->add_filter( 'rest_post_dispatch', $analytics, 'track_request', 10, 3 );

		// API key authentication.
		$api_keys = Jwt_Auth_Api_Keys::get_instance();
		$this->loader->add_filter( 'determine_current_user', $api_keys, 'authenticate_with_api_key', 20 );
		$this->loader->add_action( 'rest_api_init', $api_keys, 'register_api_key_routes' );

		// Token manager (refresh / revoke endpoints).
		$token_manager = Jwt_Auth_Token_Manager::get_instance();
		$this->loader->add_action( 'rest_api_init', $token_manager, 'add_api_routes' );
		$this->loader->add_filter( 'determine_current_user', $token_manager, 'check_revoked_on_determine', 25 );

		// OAuth 2.0 server.
		$oauth = Jwt_Auth_OAuth::get_instance();
		$this->loader->add_action( 'rest_api_init', $oauth, 'register_routes' );

		// Third-party JWT exchange (create WP user from external JWT).
		$third_party = Jwt_Auth_Third_Party_Jwt::get_instance();
		$this->loader->add_action( 'rest_api_init', $third_party, 'register_routes' );
		$this->loader->add_filter( 'determine_current_user', $third_party, 'authenticate_with_third_party_jwt', 30 );

		// Firebase authentication.
		$firebase = Jwt_Auth_Firebase::get_instance();
		$this->loader->add_action( 'rest_api_init', $firebase, 'register_routes' );
		$this->loader->add_filter( 'authenticate', $firebase, 'enforce_login_mode', 20, 3 );
		$this->loader->add_filter( 'login_redirect', $firebase, 'custom_login_redirect', 10, 3 );
		$this->loader->add_filter( 'logout_redirect', $firebase, 'custom_logout_redirect', 10, 3 );

		// Frontend shortcodes.
		$shortcodes = Jwt_Auth_Shortcodes::get_instance();
		$this->loader->add_action( 'init', $shortcodes, 'register_shortcodes' );
		$this->loader->add_action( 'wp_enqueue_scripts', $shortcodes, 'enqueue_firebase_assets' );

		// Firestore sync.
		$firestore = Jwt_Auth_Firestore::get_instance();
		$this->loader->add_action( 'updated_user_meta', $firestore, 'sync_user_meta', 10, 4 );
		$this->loader->add_action( 'save_post', $firestore, 'sync_product_on_save', 10, 3 );
		$this->loader->add_action( 'woocommerce_order_status_changed', $firestore, 'sync_order', 10, 4 );

		// WooCommerce integration (conditional).
		if ( class_exists( 'WooCommerce' ) ) {
			$woocommerce = Jwt_Auth_WooCommerce::get_instance();
			$this->loader->add_action( 'woocommerce_checkout_before_order_review', $woocommerce, 'add_firebase_login_to_checkout' );
			$this->loader->add_action( 'woocommerce_account_content', $woocommerce, 'add_firebase_login_to_myaccount' );
			$this->loader->add_action( 'woocommerce_created_customer', $woocommerce, 'sync_new_customer_to_firebase', 10, 3 );
		}
	}

	/**
	 * Register all the hooks related to the admin-facing functionality of the plugin.
	 *
	 * @since 1.3.4
	 * @since 2.0.0 Added analytics admin REST routes.
	 */
	private function define_admin_hooks() {

		$plugin_admin = new Jwt_Auth_Admin( $this->get_plugin_name(), $this->get_version() );
		$this->loader->add_action( 'admin_menu', $plugin_admin, 'register_menu_page' );
		$this->loader->add_action( 'admin_enqueue_scripts', $plugin_admin, 'enqueue_plugin_assets' );
		$this->loader->add_action( 'admin_init', $plugin_admin, 'register_plugin_settings' );
		$this->loader->add_action( 'rest_api_init', $plugin_admin, 'register_plugin_settings' );
		$this->loader->add_action( 'rest_api_init', $plugin_admin, 'register_admin_rest_routes' );
		$this->loader->add_action( 'admin_notices', $plugin_admin, 'display_all_notices' );
		$this->loader->add_filter( 'plugin_action_links_jwt-authenticator/jwt-authenticator.php', $plugin_admin, 'add_action_link', 10, 2 );
	}

	/**
	 * Run the loader to execute all the hooks with WordPress.
	 *
	 * @since 1.0.0
	 */
	public function run() {
		$this->loader->run();
	}

	/**
	 * The name of the plugin used to uniquely identify it within the context of
	 * WordPress and to define internationalization functionality.
	 *
	 * @since  1.0.0
	 * @return string The name of the plugin.
	 */
	public function get_plugin_name() {
		return $this->plugin_name;
	}

	/**
	 * The reference to the class that orchestrates the hooks with the plugin.
	 *
	 * @since  1.0.0
	 * @return Jwt_Auth_Loader Orchestrates the hooks of the plugin.
	 */
	public function get_loader() {
		return $this->loader;
	}

	/**
	 * Retrieve the version number of the plugin.
	 *
	 * @since  1.0.0
	 * @return string The version number of the plugin.
	 */
	public function get_version() {
		return $this->version;
	}
}
