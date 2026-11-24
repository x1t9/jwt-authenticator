=== JWT Authenticator ===

Contributors: x1t9
Tags: jwt, firebase, oauth, api-key, rest-api
Requires at least: 5.0
Tested up to: 7.1
Requires PHP: 8.0
Stable tag: 1.3.3
License: MIT
License URI: https://opensource.org/licenses/MIT

Complete JWT, Firebase, OAuth 2.0, and API Key authentication for the WordPress REST API. All features free under the MIT license.

== Description ==

JWT Authenticator is a full-featured, MIT-licensed authentication plugin for the WordPress REST API. Every feature is included at no cost — no "PRO" tier, no upsells, no telemetry.

= Core JWT Authentication =
* Standard JWT (RFC 7519) token generation via `POST /wp-json/jwt-auth/v1/token`
* Token validation, refresh, and revocation endpoints
* Token listing and per-token revocation by JTI
* Configurable access token expiry (default 1 hour) and refresh token expiry (default 30 days)
* Token revocation storage in a dedicated database table
* 11 signing algorithms: HS256/384/512, RS256/384/512, ES256/384/512, PS256/384/512

= Authentication Methods =
* **JWT Bearer Token** — Standard `Authorization: Bearer <token>` header
* **Basic Auth** — Username or email + password via `/token` endpoint
* **API Key Auth** — Universal server keys and per-user keys; delivered via `X-API-Key` header, `Authorization: ApiKey` header, or `?api_key` query param
* **OAuth 2.0** — Password, refresh_token, and client_credentials grant types
* **Firebase Auth** — Verify Firebase ID tokens and exchange for WordPress JWTs
* **Third-Party JWT** — Authenticate with tokens from Auth0, Okta, Cognito, etc. with auto user creation
* **Custom Header** — Configure any HTTP header as the JWT bearer header

= Firebase Integration =
* Verify Firebase ID tokens against Google's public keys
* Auto-create WordPress users from Firebase credentials
* Sync Firebase UID to WordPress user meta
* Configurable login mode: Firebase only, WordPress only, or both
* Support for 7 social providers: Google, Facebook, Apple, Twitter, GitHub, Yahoo, Microsoft
* Phone/OTP authentication via Firebase Phone Auth
* WordPress session creation from Firebase tokens (cookie-based)
* Custom login/logout redirect URLs (WooCommerce-aware)
* Developer action/filter hooks for all Firebase lifecycle events

= Firebase Shortcodes =
* `[firebase_login]` — Email/password login form with optional social buttons
* `[firebase_register]` — Registration form (creates Firebase + WP user simultaneously)
* `[firebase_social_login providers="google,facebook,github"]` — Social provider buttons
* Three display styles: default (icon + text), icon-only, text-only
* Lazy Firebase SDK loading (only enqueued on pages containing shortcodes)
* Fully responsive CSS with custom properties for easy theming

= WooCommerce Integration =
* Firebase login form injected above WooCommerce Checkout form
* Firebase login form on WooCommerce My Account page
* Auto-sync new WooCommerce customers to Firebase on registration (email + password)

= Firestore Sync =
* Sync WordPress user meta to Firestore `wp_users` collection
* Selective field sync (configure which meta keys to sync)
* Sync WooCommerce products to `wc_products` collection
* Sync WooCommerce orders to `wc_orders` collection
* Service-account-based server-to-server auth with token caching

= API Endpoint Protection =
* Three protection modes: Disabled, Selective, Full
* Wildcard route pattern matching (e.g. `/wp/v2/*`)
* Whitelist always-public routes
* Completely disable specific REST endpoints (return 404)
* Restrict all REST API access to authenticated users
* Role-based route control — map WordPress roles to sets of allowed routes
* Disable REST API entirely for non-admins

= Rate Limiting =
* Per-IP or per-user sliding window rate limiting
* Configurable request limit and window size
* Standard `X-RateLimit-Limit`, `X-RateLimit-Remaining`, `X-RateLimit-Reset` response headers
* 429 responses include `retry_after` seconds

= Analytics & Monitoring =
* Tracks token generation, auth failures, API key usage, OAuth and Firebase logins
* 30-day aggregated stats dashboard: auth method breakdown, top endpoints, daily trends
* Geo-IP country/city identification (ip-api.com, ipapi.co, or ipinfo.io — configurable)
* Admin REST endpoint: `GET /wp-json/jwt-auth/v1/admin/analytics`

= Developer Tools =
* `Jwt_Auth_Helpers` utility class (IP detection, key generation, secure hashing)
* Singleton pattern on all classes for safe cross-plugin access
* 15+ action hooks and filters
* Full documentation in `DOCUMENTATION.md` and `CHANGELOG.md`

== Requirements ==

= WordPress REST API =
This plugin extends the WP REST API (built into WordPress 4.7+).

= PHP =
Minimum PHP version: **8.0.0**

= HTTP Authorization Header =
Most shared hosting providers disable the HTTP Authorization Header by default.
To enable it, add to your `.htaccess`:

`
RewriteEngine on
RewriteCond %{HTTP:Authorization} ^(.*)
RewriteRule ^(.*) - [E=HTTP_AUTHORIZATION:%1]
`

For WPEngine hosting:
`
SetEnvIf Authorization "(.*)" HTTP_AUTHORIZATION=$1
`

== Installation ==

1. Upload the `jwt-authenticator` folder to `/wp-content/plugins/`
2. Activate the plugin in **Plugins → Installed Plugins**
3. Add your secret key to `wp-config.php`:
   `define('JWT_AUTH_SECRET_KEY', 'your-top-secret-key');`
   Generate a strong key: https://api.wordpress.org/secret-key/1.1/salt/
4. (Optional) Enable CORS: `define('JWT_AUTH_CORS_ENABLE', true);`
5. Visit **Settings → JWT Authenticator** to configure all options

== Configuration ==

= wp-config.php Constants =

* `JWT_AUTH_SECRET_KEY` **(required)** — Secret key for JWT signing
* `JWT_AUTH_CORS_ENABLE` *(optional)* — Enable CORS headers on REST responses

= WordPress Options (also configurable via admin UI) =

All settings are stored as WordPress options and can be set via the admin dashboard or programmatically with `update_option()`. See `DOCUMENTATION.md` for the complete reference table.

Key options:
* `jwt_auth_access_token_expiry` — Access token lifetime in seconds (default: 3600)
* `jwt_auth_refresh_token_expiry` — Refresh token lifetime in seconds (default: 2592000)
* `jwt_auth_protection_mode` — `disabled` / `selective` / `full`
* `jwt_auth_firebase_enabled` — Enable Firebase integration
* `jwt_auth_firebase_project_id` — Your Firebase project ID
* `jwt_auth_firebase_web_api_key` — Firebase Web API key
* `jwt_auth_rate_limit_enabled` — Enable rate limiting

== REST API Endpoints ==

= JWT Token =
* `POST /wp-json/jwt-auth/v1/token` — Generate access + refresh token
* `POST /wp-json/jwt-auth/v1/token/validate` — Validate a JWT
* `POST /wp-json/jwt-auth/v1/token/refresh` — Refresh access token
* `POST /wp-json/jwt-auth/v1/token/revoke` — Revoke current token
* `GET  /wp-json/jwt-auth/v1/tokens` — List user's active tokens
* `DELETE /wp-json/jwt-auth/v1/tokens/{jti}` — Revoke a specific token

= API Keys =
* `POST /wp-json/jwt-auth/v1/api-keys` — Create user API key
* `GET  /wp-json/jwt-auth/v1/api-keys` — List user's API keys
* `DELETE /wp-json/jwt-auth/v1/api-keys/{id}` — Delete an API key
* `POST /wp-json/jwt-auth/v1/api-keys/admin/universal` — Create universal key (admin)

= OAuth 2.0 =
* `POST /wp-json/jwt-auth/v1/oauth/token` — Token endpoint (password / refresh_token / client_credentials grants)
* `POST /wp-json/jwt-auth/v1/oauth/revoke` — Revoke an OAuth token

= Firebase =
* `POST /wp-json/jwt-auth/v1/auth/firebase` — Exchange Firebase ID token for WordPress JWT
* `POST /wp-json/jwt-auth/v1/auth/firebase/session` — Create WordPress session from Firebase token
* `GET  /wp-json/jwt-auth/v1/auth/firebase/config` — Get public Firebase config for front-end SDK
* `POST /wp-json/jwt-auth/v1/auth/third-party` — Authenticate with a third-party JWT

= Admin (require `manage_options`) =
* `GET/POST /wp-json/jwt-auth/v1/admin/settings` — Plugin settings
* `GET      /wp-json/jwt-auth/v1/admin/status` — Configuration health check
* `GET/POST /wp-json/jwt-auth/v1/admin/protection` — API protection settings
* `GET/POST /wp-json/jwt-auth/v1/admin/rate-limit` — Rate limit settings
* `GET      /wp-json/jwt-auth/v1/admin/analytics` — Analytics data

== Usage Examples ==

= Generate a token =
`
curl -X POST https://your-site.com/wp-json/jwt-auth/v1/token \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"your-password"}'
`

= Authenticate with an API key =
`
curl https://your-site.com/wp-json/wp/v2/posts \
  -H "X-API-Key: jwta_yourkeyhere"
`

= Authenticate with Firebase ID token =
`
curl -X POST https://your-site.com/wp-json/jwt-auth/v1/auth/firebase \
  -H "Content-Type: application/json" \
  -d '{"firebase_token":"FIREBASE_ID_TOKEN"}'
`

= Use a shortcode =
`
[firebase_login redirect_url="/dashboard" show_social="true"]
[firebase_social_login providers="google,apple,github"]
`

== Hooks & Filters ==

= Filters =
* `jwt_auth_expire` — Modify token expiry timestamp
* `jwt_auth_token_before_sign` — Modify JWT payload before signing
* `jwt_auth_token_before_dispatch` — Modify token response data
* `jwt_auth_algorithm` — Change signing algorithm
* `jwt_auth_cors_allow_headers` — Customize CORS headers
* `jwt_auth_whitelist` — Add routes to auth whitelist
* `jwt_auth_firebase_user_data` — Modify user data before WP user creation
* `jwt_auth_firebase_default_role` — Customize role for auto-created Firebase users

= Actions =
* `jwt_auth_firebase_user_created` — Fires when a new WP user is created from Firebase
* `jwt_auth_firebase_user_logged_in` — Fires on each Firebase login
* `jwt_auth_woo_customer_synced_to_firebase` — Fires after WC customer is synced to Firebase

For complete documentation see `DOCUMENTATION.md` in the plugin folder.

== Frequently Asked Questions ==

= Is this really completely free? =
Yes. All features — Firebase, OAuth 2.0, API Keys, rate limiting, analytics, Firestore sync — are included under the MIT license with no restrictions.

= What changed from version 1.x? =
Version 2.0.0 is a major rewrite adding Firebase, OAuth 2.0, API keys, rate limiting, analytics, and API protection. The token endpoint now returns a refresh token alongside the access token. See `CHANGELOG.md` for the full list.

= How do I set up Firebase? =
1. Create a project at console.firebase.google.com
2. Enable Authentication → Sign-in providers
3. Download a service account JSON key (Project Settings → Service accounts)
4. Enter your Project ID, Web API Key, and service account JSON in JWT Auth → Firebase settings

= Can I use email to log in? =
Yes. Pass an email address in the `username` field of `POST /wp-json/jwt-auth/v1/token`.

= How do I protect a custom REST endpoint? =
Either set `jwt_auth_protection_mode` to `full` (protects everything), use `selective` mode with your route pattern, or simply use `is_user_logged_in()` as your endpoint's `permission_callback` — the JWT middleware sets the current user automatically.

== Changelog ==

= 2.0.0 =
* Complete rewrite — see CHANGELOG.md for full details
* License changed to MIT
* Token refresh, revocation, and listing endpoints
* API Key authentication (universal + user-specific)
* OAuth 2.0 (password, refresh_token, client_credentials grants)
* Third-party JWT authentication with auto user creation
* Firebase Authentication integration (7 social providers + phone OTP)
* Firebase shortcodes: [firebase_login], [firebase_register], [firebase_social_login]
* WooCommerce Firebase checkout, My Account, and customer sync
* Firestore sync (users, products, orders)
* Selective API protection with role-based access control
* Rate limiting with standard headers
* Geo-IP identification
* Analytics dashboard
* Configurable token expiry
* Email login support
* Custom header support

= 1.5.1 =
* Security: Updated dependencies to latest secure versions
* Feature: Usage-based upgrade prompts

= 1.4.0 =
* Feature: Live API Explorer in admin dashboard
* Feature: React-based admin dashboard redesign

= 1.0.0 =
* Initial release — JWT token generation and validation

== Upgrade Notice ==

= 2.0.0 =
Major version. Run database upgrade on activation (creates 4 new tables). Token expiry changed from 7 days to 1 hour — update `jwt_auth_access_token_expiry` option if you need a longer default.
