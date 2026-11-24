<?php

/**
 * The plugin bootstrap file.
 *
 * This file is read by WordPress to generate the plugin information in the plugin
 * admin area. This file also includes all the dependencies used by the plugin,
 * registers the activation and deactivation functions, and defines a function
 * that starts the plugin.
 *
 * @wordpress-plugin
 * Plugin Name: JWT Authenticator
 * Plugin URI:  https://github.com/x1t9/jwt-authenticator
 * Description: Complete JWT + Firebase + OAuth + API Key authentication for WordPress REST API. All features free under MIT license.
 * Version:     1.3.3
 * Requires PHP: 8.0
 * Author:      x1t9
 * Author URI:  https://github.com/x1t9
 * License:     MIT
 * License URI: https://opensource.org/licenses/MIT
 * Text Domain:       jwt-authenticator
 * Domain Path: /languages
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
 */

// If this file is called directly, abort.
if ( ! defined( 'WPINC' ) ) {
	die;
}

/**
 * Load the DB class early so it is available during plugin activation.
 */
require plugin_dir_path( __FILE__ ) . 'includes/vendor/autoload.php';
require plugin_dir_path( __FILE__ ) . 'includes/class-jwt-auth-db.php';

/**
 * The core plugin class that is used to define internationalization,
 * admin-specific hooks, and public-facing site hooks.
 */
require plugin_dir_path( __FILE__ ) . 'includes/class-jwt-auth.php';

/**
 * Run on plugin activation.
 *
 * Records install date and runs DB installer.
 */
function activate_jwt_auth() {
	if ( ! get_option( 'jwt_auth_install_date', false ) ) {
		update_option( 'jwt_auth_install_date', time() );
	}

	Jwt_Auth_DB::install();
}

/**
 * Run on plugin deactivation.
 */
function deactivate_jwt_auth() {
	// Future cleanup logic here.
}

register_activation_hook( __FILE__, 'activate_jwt_auth' );
register_deactivation_hook( __FILE__, 'deactivate_jwt_auth' );

/**
 * Begins execution of the plugin.
 *
 * Since everything within the plugin is registered via hooks,
 * then kicking off the plugin from this point in the file does
 * not affect the page life cycle.
 *
 * @since 2.0.0
 */
function run_jwt_auth() {
	$plugin = new Jwt_Auth();
	$plugin->run();
}

run_jwt_auth();
