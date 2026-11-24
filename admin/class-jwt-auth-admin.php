<?php

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * The admin-facing functionality of the plugin.
 *
 * Defines the plugin name, version
 *
 * @author     x1t9
 *
 * @since      1.3.4
 */

// ---------------------------------------------------------------------------
// Compatibility stubs — replaces legacy PRO/telemetry helper functions so the
// plugin works as a fully free MIT-licensed product with no upsells.
// ---------------------------------------------------------------------------

if ( ! function_exists( 'jwt_auth_should_show_upsell' ) ) {
	/**
	 * Always returns false — all features are free; no upsell UI is shown.
	 *
	 * @return bool
	 */
	function jwt_auth_should_show_upsell() {
		return false;
	}
}

if ( ! function_exists( 'jwt_auth_get_upsell_metrics' ) ) {
	/**
	 * Returns neutral upsell metrics (no upsell shown).
	 *
	 * @return array
	 */
	function jwt_auth_get_upsell_metrics() {
		return array(
			'shouldShowUpsell' => false,
			'daysActive'       => 0,
			'tokensCreated'    => (int) get_option( 'jwt_auth_tokens_created', 0 ),
		);
	}
}

if ( ! function_exists( 'jwt_auth_track_install_date' ) ) {
	/**
	 * Tracks install date in a WP option (no remote telemetry).
	 *
	 * @return void
	 */
	function jwt_auth_track_install_date() {
		if ( ! get_option( 'jwt_auth_install_date' ) ) {
			update_option( 'jwt_auth_install_date', time() );
		}
	}
}

class Jwt_Auth_Admin
{
    /**
     * The ID of this plugin.
     *
     * @since    1.3.4
     *
     * @var string The ID of this plugin.
     */
    private $plugin_name;

    /**
     * The version of this plugin.
     *
     * @since    1.3.4
     *
     * @var string The current version of this plugin.
     */
    private $version;

    /**
     * Initialize the class and set its properties.
     *
     * @param  string  $plugin_name  The name of the plugin.
     * @param  string  $version  The version of this plugin.
     *
     * @since    1.3.4
     */
    public function __construct(string $plugin_name, string $version)
    {
        $this->plugin_name = $plugin_name;
        $this->version = $version;
    }

    /**
     * Register admin REST API endpoints.
     *
     * @return void
     *
     * @since 1.3.4
     */
    public function register_admin_rest_routes()
    {
        $namespace = 'jwt-auth/v1';

        register_rest_route(
            $namespace,
            'admin/settings',
            [
                'methods' => ['GET', 'POST'],
                'callback' => [$this, 'handle_settings'],
                'permission_callback' => [$this, 'settings_permission_check'],
            ]
        );

        register_rest_route(
            $namespace,
            'admin/status',
            [
                'methods' => 'GET',
                'callback' => [$this, 'get_configuration_status'],
                'permission_callback' => [$this, 'settings_permission_check'],
            ]
        );

        register_rest_route(
            $namespace,
            'admin/survey',
            [
                'methods' => 'POST',
                'callback' => [$this, 'handle_survey_submission'],
                'permission_callback' => [$this, 'settings_permission_check'],
            ]
        );

        register_rest_route(
            $namespace,
            'admin/survey/status',
            [
                'methods' => 'GET',
                'callback' => [$this, 'get_survey_status'],
                'permission_callback' => [$this, 'settings_permission_check'],
            ]
        );

        register_rest_route(
            $namespace,
            'admin/survey/complete',
            [
                'methods' => 'POST',
                'callback' => [$this, 'mark_survey_completed'],
                'permission_callback' => [$this, 'settings_permission_check'],
            ]
        );

        register_rest_route(
            $namespace,
            'admin/survey/dismissal',
            [
                'methods' => ['GET', 'POST'],
                'callback' => [$this, 'handle_survey_dismissal'],
                'permission_callback' => [$this, 'settings_permission_check'],
            ]
        );

        register_rest_route(
            $namespace,
            'admin/dashboard',
            [
                'methods' => 'GET',
                'callback' => [$this, 'get_dashboard_data'],
                'permission_callback' => [$this, 'settings_permission_check'],
            ]
        );

        register_rest_route(
            $namespace,
            'admin/notices/dismiss',
            [
                'methods' => 'POST',
                'callback' => [$this, 'handle_notice_dismissal'],
                'permission_callback' => [$this, 'settings_permission_check'],
                'args' => [
                    'notice_id' => [
                        'required' => true,
                        'type' => 'string',
                        'description' => 'The ID of the notice to dismiss',
                        'validate_callback' => function ($param) {
                            return is_string($param) && ! empty($param);
                        },
                    ],
                ],
            ]
        );
    }

    /**
     * Check permissions for settings endpoint.
     *
     * @return bool
     */
    public function settings_permission_check()
    {
        return current_user_can('manage_options');
    }

    /**
     * Handle settings GET and POST requests.
     *
     * @return WP_REST_Response|WP_Error
     */
    public function handle_settings(WP_REST_Request $request)
    {
        if ($request->get_method() === 'GET') {
            $settings = get_option(
                'jwt_auth_options',
                [
                    'share_data' => false,
                ]
            );

            return new WP_REST_Response(
                [
                    'jwt_auth_options' => $settings,
                ],
                200
            );
        }

        if ($request->get_method() === 'POST') {
            $settings = $request->get_param('jwt_auth_options');

            if (! $settings || ! is_array($settings)) {
                return new WP_Error(
                    'jwt_auth_invalid_settings',
                    'Invalid settings data provided.',
                    ['status' => 400]
                );
            }

            // Sanitize every submitted field using the pure, unit-tested
            // sanitizer, then persist each value to its own option.
            $sanitized_settings = self::sanitize_settings( $settings );

            foreach ( $sanitized_settings as $key => $value ) {
                if ( is_array( $value ) ) {
                    update_option( 'jwt_auth_' . $key, wp_json_encode( $value ) );
                } else {
                    update_option( 'jwt_auth_' . $key, $value );
                }
            }

            // Keep the legacy aggregate option in sync (read by the cron job).
            $existing_settings = get_option('jwt_auth_options', []);
            $updated_settings   = array_merge($existing_settings, $sanitized_settings);

            $success = update_option('jwt_auth_options', $updated_settings);

            // update_option returns false if the value hasn't changed, so we need to check differently
            if ($success === false && get_option('jwt_auth_options') !== $updated_settings) {
                return new WP_Error(
                    'jwt_auth_settings_update_failed',
                    'Failed to update settings.',
                    ['status' => 500]
                );
            }

            return new WP_REST_Response(
                [
                    'jwt_auth_options' => $updated_settings,
                ],
                200
            );
        }

        return new WP_Error(
            'jwt_auth_method_not_allowed',
            'Method not allowed.',
            ['status' => 405]
        );
    }

    /**
     * Sanitize a settings payload into typed, storable values.
     *
     * Pure (no WordPress I/O) so it is unit-testable. Each known field is
     * coerced to its expected type; unknown keys are ignored.
     *
     * @since  2.1.0
     * @param  array $input Raw settings keyed by field name.
     * @return array Sanitized settings, keyed identically.
     */
    public static function sanitize_settings( array $input ): array {
        $field_defs = [
            'access_token_expiry'        => ['type' => 'int', 'min' => 60],
            'refresh_token_expiry'       => ['type' => 'int', 'min' => 3600],
            'custom_header'              => ['type' => 'text'],
            'allow_email_login'          => ['type' => 'bool'],
            'protection_mode'            => ['type' => 'enum', 'values' => ['disabled', 'selective', 'full']],
            'disable_rest_for_guests'    => ['type' => 'bool'],
            'disable_rest_api'           => ['type' => 'bool'],
            'whitelisted_routes'         => ['type' => 'lines'],
            'protected_routes'           => ['type' => 'lines'],
            'disabled_endpoints'         => ['type' => 'lines'],
            'rate_limit_enabled'         => ['type' => 'bool'],
            'rate_limit_requests'        => ['type' => 'int', 'min' => 1],
            'rate_limit_window'          => ['type' => 'int', 'min' => 10],
            'rate_limit_per_user'        => ['type' => 'bool'],
            'geoip_provider'             => ['type' => 'enum', 'values' => ['none', 'ip-api', 'ipapi', 'ipinfo']],
            'geoip_api_key'              => ['type' => 'text'],
            'api_key_header'             => ['type' => 'text'],
            'api_key_user_id'            => ['type' => 'int', 'min' => 1],
            'oauth_enabled'              => ['type' => 'bool'],
            'firebase_enabled'           => ['type' => 'bool'],
            'firebase_project_id'        => ['type' => 'text'],
            'firebase_web_api_key'       => ['type' => 'text'],
            'firebase_enabled_providers' => ['type' => 'providers'],
            'firebase_login_mode'        => ['type' => 'enum', 'values' => ['both', 'firebase_only']],
            'firebase_auto_create_users' => ['type' => 'bool'],
            'woo_firebase_checkout'      => ['type' => 'bool'],
            'woo_firebase_myaccount'     => ['type' => 'bool'],
            'woo_sync_to_firebase'       => ['type' => 'bool'],
            'firestore_enabled'          => ['type' => 'bool'],
            'firestore_sync_user_meta'   => ['type' => 'bool'],
        ];

        $allowed_providers = ['google', 'facebook', 'apple', 'twitter', 'github', 'yahoo', 'microsoft', 'phone'];
        $sanitized         = [];

        foreach ( $field_defs as $key => $def ) {
            if ( ! array_key_exists( $key, $input ) ) {
                continue;
            }

            $v = $input[ $key ];

            switch ( $def['type'] ) {
                case 'int':
                    $sanitized[ $key ] = max( isset( $def['min'] ) ? $def['min'] : 0, (int) $v );
                    break;
                case 'bool':
                    $sanitized[ $key ] = (bool) $v;
                    break;
                case 'enum':
                    $sanitized[ $key ] = in_array( $v, $def['values'], true ) ? $v : $def['values'][0];
                    break;
                case 'lines':
                    $rows              = is_array( $v ) ? $v : preg_split( '/\r\n|\r|\n/', (string) $v );
                    $sanitized[ $key ] = array_values( array_filter( array_map( 'sanitize_text_field', $rows ) ) );
                    break;
                case 'providers':
                    $raw               = is_array( $v ) ? $v : [];
                    $sanitized[ $key ] = array_values( array_intersect( array_map( 'sanitize_text_field', $raw ), $allowed_providers ) );
                    break;
                case 'text':
                default:
                    $sanitized[ $key ] = sanitize_text_field( (string) $v );
                    break;
            }
        }

        return $sanitized;
    }

    /**
     * Get real configuration status for the dashboard.
     *
     * @return WP_REST_Response
     */
    public function get_configuration_status()
    {
        $secret_key = defined('JWT_AUTH_SECRET_KEY') ? JWT_AUTH_SECRET_KEY : false;
        $cors_enabled = defined('JWT_AUTH_CORS_ENABLE') ? JWT_AUTH_CORS_ENABLE : false;
        $dev_mode = defined('JWT_AUTH_DEV_MODE') ? JWT_AUTH_DEV_MODE : false;

        // Check if JWT secret key is configured
        $secret_key_configured = ! empty($secret_key);

        // Check PHP version compatibility
        $php_version = PHP_VERSION;
        $php_compatible = version_compare($php_version, '8.0', '>=');

        // WordPress version
        $wp_version = get_bloginfo('version');

        // MySQL version
        global $wpdb;
        $mysql_version = $wpdb->get_var('SELECT VERSION()') ?: 'Unknown';

        // PHP Memory Limit
        $memory_limit = ini_get('memory_limit');

        // PHP Post Max Size
        $post_max_size = ini_get('post_max_size');

        // Configuration method detection
        $config_method = $secret_key_configured ? 'wp-config.php' : 'Not configured';

        $status = [
            'configuration' => [
                'method' => $config_method,
                'secret_key_configured' => $secret_key_configured,
                'cors_enabled' => $cors_enabled,
                'dev_mode' => $dev_mode,
            ],
            'system' => [
                'php_version' => $php_version,
                'php_compatible' => $php_compatible,
                'free_version' => true,
                'wordpress_version' => $wp_version,
                'mysql_version' => $mysql_version,
                'php_memory_limit' => $memory_limit,
                'post_max_size' => $post_max_size,
            ],
        ];

        return new WP_REST_Response($status, 200);
    }

    /**
     * Register a new settings page under Settings main menu
     * .
     *
     * @return void
     *
     * @since 1.3.4
     */
    public function register_menu_page()
    {
        add_submenu_page(
            'options-general.php',
            __('JWT Authenticator', 'jwt-authenticator'),
            __('JWT Authenticator', 'jwt-authenticator'),
            'manage_options',
            'jwt_authenticator',
            [$this, 'render_admin_page']
        );
    }

    /**
     * Ensure install date tracking exists.
     *
     * @since 1.5.0
     * @return void
     */
    public function track_install_date()
    {
        jwt_auth_track_install_date();
    }

    /**
     * Admin notices system storage.
     *
     * @var array
     *
     * @since 1.3.8
     */
    private $admin_notices = [];

    /**
     * Register a new admin notice to be displayed.
     *
     * @param  string  $id  Unique notice identifier
     * @param  string  $message  Notice message
     * @param  string  $type  Notice type (success, error, warning, info)
     * @param  string  $cta_text  Call to action button text (optional)
     * @param  string  $cta_link  Call to action button link (optional)
     * @param  bool  $dismissible  Whether the notice is dismissible
     * @return void
     *
     * @since 1.3.8
     */
    public function register_admin_notice($id, $message, $type = 'info', $cta_text = '', $cta_link = '', $dismissible = true)
    {
        $this->admin_notices[$id] = [
            'id' => $id,
            'message' => $message,
            'type' => $type,
            'cta_text' => $cta_text,
            'cta_link' => $cta_link,
            'dismissible' => $dismissible,
        ];
    }

    /**
     * Display all admin notices (registers and displays them).
     *
     * @return void
     *
     * @since 1.3.8
     */
    public function display_all_notices()
    {
        // First register all notices
        $this->register_system_notices();

        // Check if we have notices to display
        $has_notices = false;
        foreach ($this->admin_notices as $notice) {
            if ($this->should_display_notice($notice['id'])) {
                $this->render_admin_notice($notice);
                $has_notices = true;
            }
        }

        // Only enqueue dismissal script if we have notices
        if ($has_notices) {
            $this->enqueue_notice_dismissal_script();
        }
    }

    /**
     * Register system notices (configuration, welcome, etc.).
     *
     * @return void
     *
     * @since 1.3.8
     */
    private function register_system_notices()
    {
        // Welcome notice for new installations - show until dismissed or CTA clicked
        $this->register_admin_notice(
            'jwt_auth_welcome',
            __('JWT Authentication installed successfully! Configure your settings to enable REST API authentication.', 'jwt-authenticator'),
            'success',
            __('Configure JWT Authentication →', 'jwt-authenticator'),
            admin_url('options-general.php?page=jwt_authenticator')
        );
    }

    /**
     * Check if a notice should be displayed.
     *
     * @param  string  $notice_id
     * @return bool
     *
     * @since 1.3.8
     */
    private function should_display_notice($notice_id)
    {
        // Check if user has appropriate permissions
        if (! current_user_can('manage_options')) {
            return false;
        }

        // Check if notice has been dismissed
        $dismissed_notices = get_option('jwt_auth_dismissed_notices', []);
        if (in_array($notice_id, $dismissed_notices, true)) {
            return false;
        }

        return true;
    }

    /**
     * Render a single admin notice.
     *
     * @param  array  $notice  Notice configuration
     * @return void
     *
     * @since 1.3.8
     */
    private function render_admin_notice($notice)
    {
        $notice_class = 'notice notice-'.esc_attr($notice['type']);
        if ($notice['dismissible']) {
            $notice_class .= ' is-dismissible';
        }
        ?>
        <div class="<?php echo esc_attr($notice_class); ?>" data-notice-id="<?php echo esc_attr($notice['id']); ?>">
            <p>
                <?php echo wp_kses_post($notice['message']); ?>
                <?php if (! empty($notice['cta_text']) && ! empty($notice['cta_link'])) { ?>
                    <a href="<?php echo esc_url($notice['cta_link']); ?>"
                        class="button button-primary"
                        style="margin-left: 10px;">
                        <?php echo esc_html($notice['cta_text']); ?>
                    </a>
                <?php } ?>
            </p>
        </div>
    <?php
    }

    /**
     * Dismiss a notice permanently.
     *
     * @param  string  $notice_id
     * @return bool
     *
     * @since 1.3.8
     */
    public function dismiss_notice($notice_id)
    {
        $dismissed_notices = get_option('jwt_auth_dismissed_notices', []);

        if (! in_array($notice_id, $dismissed_notices, true)) {
            $dismissed_notices[] = $notice_id;

            return update_option('jwt_auth_dismissed_notices', $dismissed_notices);
        }

        return true;
    }

    /**
     * Display a generic success notice.
     *
     * @param  string  $id  Notice ID
     * @param  string  $message  Notice message
     * @param  string  $cta_text  CTA button text
     * @param  string  $cta_link  CTA button link
     * @return void
     *
     * @since 1.3.8
     */
    public function display_success_notice($id, $message, $cta_text = '', $cta_link = '')
    {
        $this->register_admin_notice($id, $message, 'success', $cta_text, $cta_link);
    }

    /**
     * Display a generic info notice.
     *
     * @param  string  $id  Notice ID
     * @param  string  $message  Notice message
     * @param  string  $cta_text  CTA button text
     * @param  string  $cta_link  CTA button link
     * @return void
     *
     * @since 1.3.8
     */
    public function display_info_notice($id, $message, $cta_text = '', $cta_link = '')
    {
        $this->register_admin_notice($id, $message, 'info', $cta_text, $cta_link);
    }

    /**
     * Display a generic warning notice.
     *
     * @param  string  $id  Notice ID
     * @param  string  $message  Notice message
     * @param  string  $cta_text  CTA button text
     * @param  string  $cta_link  CTA button link
     * @return void
     *
     * @since 1.3.8
     */
    public function display_warning_notice($id, $message, $cta_text = '', $cta_link = '')
    {
        $this->register_admin_notice($id, $message, 'warning', $cta_text, $cta_link);
    }

    /**
     * Display a generic error notice.
     *
     * @param  string  $id  Notice ID
     * @param  string  $message  Notice message
     * @param  string  $cta_text  CTA button text
     * @param  string  $cta_link  CTA button link
     * @return void
     *
     * @since 1.3.8
     */
    public function display_error_notice($id, $message, $cta_text = '', $cta_link = '')
    {
        $this->register_admin_notice($id, $message, 'error', $cta_text, $cta_link);
    }

    /**
     * Enqueue the plugin assets only on the plugin settings page.
     *
     * @param  string  $suffix
     * @return void|null
     *
     * @since 1.3.4
     */
    public function enqueue_plugin_assets($suffix = '')
    {
        // Check if $suffix is empty or null
        if (empty($suffix)) {
            return; // Exit early to prevent further execution
        }

        if ($suffix !== 'settings_page_jwt_authenticator') {
            return null;
        }

        // Bootstrap 5 CSS
        wp_enqueue_style(
            $this->plugin_name . '-bootstrap',
            plugins_url('css/bootstrap.min.css', __FILE__),
            [],
            '5.3.3'
        );

        // Bootstrap 5 JS Bundle (with Popper)
        wp_enqueue_script(
            $this->plugin_name . '-bootstrap-bundle',
            plugins_url('js/bootstrap.bundle.min.js', __FILE__),
            [],
            '5.3.3',
            true
        );

        // JWT Authenticator Bootstrap Admin Theme CSS
        wp_enqueue_style(
            $this->plugin_name . '-admin-theme',
            plugins_url('css/jwt-admin-theme.css', __FILE__),
            [$this->plugin_name . '-bootstrap'],
            $this->version
        );
    }

    /**
     * Enqueue notice dismissal JavaScript.
     *
     * @return void
     *
     * @since 1.3.8
     */
    private function enqueue_notice_dismissal_script()
    {
        if (! is_admin()) {
            return;
        }

        $script = "
        document.addEventListener('DOMContentLoaded', function() {
            // Function to dismiss a notice via AJAX
            function dismissNotice(noticeId, callback) {
                if (!noticeId) {
                    if (callback) callback();
                    return;
                }

                const formData = new FormData();
                formData.append('notice_id', noticeId);

                fetch('".rest_url('jwt-auth/v1/admin/notices/dismiss')."', {
                    method: 'POST',
                    headers: {
                        'X-WP-Nonce': '".wp_create_nonce('wp_rest')."'
                    },
                    body: formData
                })
                .then(response => response.json())
                .then(data => {
                    console.log('JWT Auth: Notice dismissed successfully', data);
                    if (callback) callback();
                })
                .catch(error => {
                    console.error('JWT Auth: Failed to dismiss notice', error);
                    if (callback) callback();
                });
            }

            // Handle dismiss button (X) clicks - only for JWT Auth notices
            document.addEventListener('click', function(e) {
                if (e.target.matches('.notice[data-notice-id^=\"jwt_auth_\"] .notice-dismiss')) {
                    const notice = e.target.closest('.notice[data-notice-id^=\"jwt_auth_\"]');
                    const noticeId = notice ? notice.dataset.noticeId : null;
                    dismissNotice(noticeId, function() {
                        // Reload page to let backend handle notice visibility
                        window.location.reload();
                    });
                }
            });

            // Handle CTA button clicks - only for JWT Auth notices
            document.addEventListener('click', function(e) {
                if (e.target.matches('.notice[data-notice-id^=\"jwt_auth_\"] .button')) {
                    const notice = e.target.closest('.notice[data-notice-id^=\"jwt_auth_\"]');
                    const noticeId = notice ? notice.dataset.noticeId : null;
                    const href = e.target.getAttribute('href');

                    if (noticeId && href) {
                        e.preventDefault();

                        // Dismiss notice first, then navigate
                        dismissNotice(noticeId, function() {
                            window.location.href = href;
                        });
                    }
                }
            });
        });
        ";

        wp_add_inline_script('wp-util', $script);
    }

    /**
     * Register the plugin settings.
     *
     * @return void
     *
     * @since 1.3.4
     */
    public function register_plugin_settings()
    {
        register_setting(
            'jwt_auth',
            'jwt_auth_options',
            [
                'type' => 'object',
                'default' => [
                    'share_data' => false,
                ],
                'show_in_rest' => [
                    'schema' => [
                        'type' => 'object',
                        'properties' => [
                            'share_data' => [
                                'type' => 'boolean',
                                'default' => false,
                            ],
                        ],
                    ],
                ],
            ]
        );
    }

    /**
     * Render the plugin settings page.
     * This is a React application that will be rendered on the admin page.
     *
     * @return void
     *
     * @since 1.3.4
     */
    public function render_admin_page()
    {
        require_once plugin_dir_path(__FILE__) . 'partials/jwt-auth-admin-dashboard.php';
    }

    /**
     * Add action links to the plugin entry on the plugins list page.
     *
     * @param  array   $links
     * @param  string  $file
     * @return array
     *
     * @since 1.3.5
     */
    public function add_action_link(array $links, string $file): array
    {
        $settings_link = sprintf(
            '<a href="%s">%s</a>',
            esc_url(admin_url('options-general.php?page=jwt_authenticator')),
            __('Settings', 'jwt-authenticator')
        );
        array_unshift($links, $settings_link);
        return $links;
    }

    /**
     * Handle survey submission.
     *
     * @return WP_REST_Response|WP_Error
     */
    public function handle_survey_submission(WP_REST_Request $request)
    {
        $survey_data = $request->get_json_params();

        if (! $survey_data) {
            return new WP_Error(
                'jwt_auth_invalid_survey_data',
                'Invalid survey data provided.',
                ['status' => 400]
            );
        }

        // Sanitize survey data
        $sanitized_data = [
            'useCase' => sanitize_text_field($survey_data['useCase'] ?? ''),
            'useCaseOther' => sanitize_textarea_field($survey_data['useCaseOther'] ?? ''),
            'projectTimeline' => sanitize_text_field($survey_data['projectTimeline'] ?? ''),
            'primaryChallenge' => sanitize_text_field($survey_data['primaryChallenge'] ?? ''),
            'primaryChallengeOther' => sanitize_textarea_field($survey_data['primaryChallengeOther'] ?? ''),
            'purchaseInterest' => sanitize_text_field($survey_data['purchaseInterest'] ?? ''),
            'email' => sanitize_email($survey_data['email'] ?? ''),
            'emailConsent' => (bool) ($survey_data['emailConsent'] ?? false),
            'submittedAt' => sanitize_text_field($survey_data['submittedAt'] ?? ''),
        ];

        // Send to webhook (non-blocking)
        $webhook_url = apply_filters( 'jwt_auth_survey_webhook_url', '' );
        $this->send_survey_to_webhook($sanitized_data, $webhook_url);

        return new WP_REST_Response(
            [
                'success' => true,
                'message' => 'Survey submitted successfully.',
            ],
            200
        );
    }

    /**
     * Get survey completion status for current user.
     *
     * @return WP_REST_Response
     */
    public function get_survey_status()
    {
        $user_id = get_current_user_id();
        $completed_at = get_user_meta($user_id, 'jwt_auth_survey_completed', true);

        return new WP_REST_Response(
            [
                'completed' => ! empty($completed_at),
                'completedAt' => $completed_at ?: null,
            ],
            200
        );
    }

    /**
     * Mark survey as completed for current user.
     *
     * @return WP_REST_Response
     */
    public function mark_survey_completed(WP_REST_Request $request)
    {
        $user_id = get_current_user_id();
        $completed_at = $request->get_param('completedAt') ?: current_time('mysql');

        $success = update_user_meta($user_id, 'jwt_auth_survey_completed', $completed_at);

        if (! $success) {
            return new WP_Error(
                'jwt_auth_survey_completion_failed',
                'Failed to mark survey as completed.',
                ['status' => 500]
            );
        }

        return new WP_REST_Response(
            [
                'success' => true,
                'completedAt' => $completed_at,
            ],
            200
        );
    }

    /**
     * Handle survey floating card dismissal tracking.
     *
     * @return WP_REST_Response|WP_Error
     */
    public function handle_survey_dismissal(WP_REST_Request $request)
    {
        $user_id = get_current_user_id();

        if ($request->get_method() === 'GET') {
            // Get dismissal data
            $dismissal_data = get_user_meta($user_id, 'jwt_auth_survey_dismissal', true);

            if (! $dismissal_data) {
                $dismissal_data = [
                    'count' => 0,
                    'lastDismissedAt' => null,
                    'hideUntil' => null,
                ];
            }

            // Check if we should show the card
            $now = time();
            $shouldShow = true;

            if ($dismissal_data['count'] >= 3) {
                $shouldShow = false;
            } elseif ($dismissal_data['hideUntil'] && $now < $dismissal_data['hideUntil']) {
                $shouldShow = false;
            }

            return new WP_REST_Response(
                [
                    'dismissalCount' => $dismissal_data['count'],
                    'lastDismissedAt' => $dismissal_data['lastDismissedAt'],
                    'shouldShow' => $shouldShow,
                ],
                200
            );
        }

        if ($request->get_method() === 'POST') {
            // Update dismissal data
            $dismissal_data = get_user_meta($user_id, 'jwt_auth_survey_dismissal', true) ?: [
                'count' => 0,
                'lastDismissedAt' => null,
                'hideUntil' => null,
            ];

            $dismissal_data['count']++;
            $dismissal_data['lastDismissedAt'] = current_time('mysql');

            // Hide for 14 days if not already at max dismissals
            if ($dismissal_data['count'] < 3) {
                $dismissal_data['hideUntil'] = time() + (14 * DAY_IN_SECONDS);
            }

            $success = update_user_meta($user_id, 'jwt_auth_survey_dismissal', $dismissal_data);

            if (! $success) {
                return new WP_Error(
                    'jwt_auth_dismissal_update_failed',
                    'Failed to update dismissal data.',
                    ['status' => 500]
                );
            }

            return new WP_REST_Response(
                [
                    'success' => true,
                    'dismissalCount' => $dismissal_data['count'],
                    'shouldShow' => $dismissal_data['count'] < 4,
                ],
                200
            );
        }

        return new WP_Error(
            'jwt_auth_method_not_allowed',
            'Method not allowed.',
            ['status' => 405]
        );
    }

    /**
     * Send survey data to webhook (non-blocking).
     *
     * @param  array  $survey_data
     * @param  string  $webhook_url
     * @return void
     */
    private function send_survey_to_webhook($survey_data, $webhook_url)
    {
        wp_remote_post(
            $webhook_url,
            [
                'timeout' => 5,
                'blocking' => false,
                // TODO: remove this once we have a valid SSL certificate
                'sslverify' => false,
                'headers' => [
                    'Content-Type' => 'application/json',
                    'User-Agent' => 'JWT-Auth-Plugin/'.$this->version,
                ],
                'body' => wp_json_encode($survey_data),
            ]
        );
    }

    /**
     * Get consolidated dashboard data.
     *
     * @param  WP_REST_Request  $request  The REST request object.
     * @return WP_REST_Response|WP_Error
     */
    public function get_dashboard_data($request)
    {
        // $request parameter is required for REST API compatibility but not used in this method
        unset($request);

        try {
            // Get settings data
            $settings_request = new WP_REST_Request('GET', '/jwt-auth/v1/admin/settings');
            $settings_response = $this->handle_settings($settings_request);

            if (is_wp_error($settings_response)) {
                return $settings_response;
            }

            $settings_data = $settings_response->get_data();

            // Get configuration status
            $status_response = $this->get_configuration_status();

            if (is_wp_error($status_response)) {
                return $status_response;
            }

            $status_data = $status_response->get_data();

            // Get survey status
            $survey_status_response = $this->get_survey_status();

            if (is_wp_error($survey_status_response)) {
                return $survey_status_response;
            }

            $survey_status_data = $survey_status_response->get_data();

            // Get survey dismissal status
            $dismissal_request = new WP_REST_Request('GET', '/jwt-auth/v1/admin/survey/dismissal');
            $dismissal_response = $this->handle_survey_dismissal($dismissal_request);

            if (is_wp_error($dismissal_response)) {
                return $dismissal_response;
            }

            $dismissal_data = $dismissal_response->get_data();
            $upsell_metrics = jwt_auth_get_upsell_metrics();

            // Return consolidated data
            return new WP_REST_Response(
                [
                    'settings' => $settings_data['jwt_auth_options'],
                    'jwtStatus' => $status_data,
                    'surveyStatus' => $survey_status_data,
                    'surveyDismissal' => $dismissal_data,
                    'upsell' => [
                        'shouldShowUpsell' => (bool) $upsell_metrics['shouldShowUpsell'],
                        'daysActive' => (int) $upsell_metrics['daysActive'],
                        'tokensCreated' => (int) $upsell_metrics['tokensCreated'],
                    ],
                ],
                200
            );
        } catch (Exception $e) {
            return new WP_Error(
                'jwt_auth_dashboard_error',
                'Failed to retrieve dashboard data: '.$e->getMessage(),
                ['status' => 500]
            );
        }
    }

    /**
     * Handle admin notice dismissal via REST API.
     *
     * @return WP_REST_Response|WP_Error
     *
     * @since 1.3.8
     */
    public function handle_notice_dismissal(WP_REST_Request $request)
    {
        $notice_id = $request->get_param('notice_id');

        if (empty($notice_id)) {
            return new WP_Error(
                'jwt_auth_missing_notice_id',
                'Notice ID is required.',
                ['status' => 400]
            );
        }

        $notice_id = sanitize_text_field($notice_id);

        $success = $this->dismiss_notice($notice_id);

        if (! $success) {
            return new WP_Error(
                'jwt_auth_notice_dismissal_failed',
                'Failed to dismiss notice.',
                ['status' => 500]
            );
        }

        return new WP_REST_Response(
            [
                'success' => true,
                'notice_id' => $notice_id,
                'message' => 'Notice dismissed successfully.',
            ],
            200
        );
    }
}
