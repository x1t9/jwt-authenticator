# Changelog

All notable changes to JWT Authenticator are documented in this file.

## [1.3.3] - 2026-11-24

### Initial Repository Release
- Establishes a clean, single-commit repository history.
- Includes the bundled JWT runtime dependency required for activation.
- Requires PHP 8.0 or newer.

## [1.3.2] - 2026-11-24

### Fixes
- Bundle the Firebase JWT runtime dependency so plugin activation and JWT endpoints work from GitHub release archives.
- Upgrade to php-jwt 7 to use the patched key-strength validation; PHP 8.0 is now required, and existing JWT signing keys must meet the selected algorithm's minimum strength.

## [1.3.1] - 2026-11-24

### Fixes
- Escaped Firebase shortcode output and added translator context for placeholder strings.
- Corrected the plugin text domain and sanitized/unslashed request server values.
- Added direct-access guards to PHP entry files and removed unused telemetry/debug code.
- Updated the WordPress.org readme metadata and test bootstrap.

## [2.1.0] — 2025

### Admin UI
- Redesigned the admin dashboard with a compact, neutral Bootstrap 5 design system (`jwt-admin-theme.css`), scoped to the plugin pages so it never affects the WordPress admin chrome.
- Rebuilt the Settings page so every control reads and writes the real backend option it controls (protection mode, route lists, rate limiting, Geo-IP, API keys, OAuth, Firebase, WooCommerce, Firestore). Saving now takes effect immediately.
- Added the missing Firebase Web API Key field and the accurate protection-mode vocabulary (`disabled` / `selective` / `full`).
- Token Manager page inherits the new design system; all token CRUD, generate, refresh, purge, statistics, and config-detection functions continue to work unchanged.
- Localized admin JavaScript strings via a JSON object so translations can no longer break the scripts.

### Bug Fixes
- Settings page no longer references an undefined `$current_user` (now calls `wp_get_current_user()`).
- The "Allow login via email" toggle is now enforced by the token endpoint (default unchanged).

### Public UI
- Restyled the front-end Firebase login / register / social-login widgets to a compact, neutral, Bootstrap-consistent theme (self-contained — does not load Bootstrap on the public site, so it cannot clash with the active theme). Social buttons are now neutral outlines.

### Codebase Integrity & Tests
- Removed the unused React/TypeScript admin UI (`admin/ui/`) — it was never enqueued or referenced.
- Refactored settings sanitization into a pure, unit-tested static method `Jwt_Auth_Admin::sanitize_settings()`.
- Added a PHPUnit test suite (`tests/`) with a minimal WordPress bootstrap: 19 unit tests covering helpers and the settings sanitizer — all passing.
- All PHP files pass `php -l`.

### Meta
- Author set to **x1t9**. Plugin/repository: https://github.com/x1t9/jwt-authenticator

## [2.0.0] — 2024

### Breaking Changes

- **License changed** from GPL-2.0+ to MIT
- **Plugin renamed** from "JWT Authentication for WP-API" to "JWT Authenticator"  
- **Token expiry** changed from 7 days to 1 hour (configurable via `jwt_auth_access_token_expiry` option)
- **Removed** upsell notifications, tracking/telemetry cron job, and all PRO promotion code
- **Removed** `jwt_auth_should_show_upsell()`, `jwt_auth_get_upsell_metrics()`, `jwt_auth_track_install_date()` global functions

### New Features

#### JWT Core
- **Token Refresh** — `POST /jwt-auth/v1/token/refresh` returns new access + refresh token pair with rotation
- **Token Revocation** — `POST /jwt-auth/v1/token/revoke` invalidates the current token
- **Token Listing** — `GET /jwt-auth/v1/tokens` lists all active tokens for the authenticated user (paginated)
- **Individual Token Revocation** — `DELETE /jwt-auth/v1/tokens/{jti}` revokes any specific token by JTI
- **Configurable Token Expiry** — Set access and refresh token lifetimes via WordPress options or admin UI
- **Email Login** — Accept email address in the `username` field of the token endpoint
- **Custom Header Support** — Configure any HTTP header name as the JWT bearer header (e.g. `X-Auth-Token`)
- **JTI Claim** — All tokens now include a unique `jti` identifier for revocation tracking
- **Revocation Check** — Token validation now checks DB for revocation status

#### API Key Authentication
- **User-Specific API Keys** — Each user can create/manage their own API keys
- **Universal API Keys** — Admins can create server-to-server keys not tied to a user
- **Flexible Key Delivery** — Accept key via `X-API-Key` header, `Authorization: ApiKey` header, or `?api_key` query param
- **Custom Key Header** — Configure the header name via `jwt_auth_api_key_header` option
- **Permissions/Route Restrictions** — Optionally restrict an API key to specific route patterns
- **Key Expiry** — API keys support optional expiration dates
- **Last-Used Tracking** — Records last usage timestamp per key

#### OAuth 2.0
- **Password Grant** — Username/password → OAuth 2.0 access token
- **Refresh Token Grant** — Refresh token → new access token
- **Client Credentials Grant** — Client ID/secret → access token for server-to-server auth
- **Token Revocation** — `POST /jwt-auth/v1/oauth/revoke`
- **Client Registration** — Admin-managed OAuth client registry

#### Third-Party JWT Authentication
- **Multi-Provider Support** — Configure multiple external JWT issuers (Auth0, Okta, Cognito, etc.)
- **JWKS Validation** — Automatically fetch and cache public keys from JWKS endpoints
- **Auto User Creation** — Optionally create WordPress users from verified third-party tokens
- **Role Assignment** — Configure default role per external provider
- **Dedicated Endpoint** — `POST /jwt-auth/v1/auth/third-party`

#### API Protection
- **Protection Modes** — Three modes: Disabled (default), Selective, Full
- **Selective Route Protection** — Specify exactly which route patterns require authentication
- **Route Whitelisting** — Always-public routes bypass all protection checks
- **Route Disabling** — Completely remove specific REST endpoints (return 404)
- **Guest Access Restriction** — Optionally require authentication for all REST API access
- **Role-Based Route Control** — Map WordPress roles to sets of allowed route patterns
- **Full REST API Disable** — Option to disable REST API entirely for non-admins
- **Wildcard Matching** — Route patterns support `*` wildcard (e.g. `/wp/v2/*`)

#### Rate Limiting
- **Per-IP Rate Limiting** — Sliding window rate limiting by client IP address
- **Per-User Rate Limiting** — Optionally limit by authenticated user instead of IP
- **Configurable Window** — Set window size (default 1 hour) and request limit (default 100)
- **Standard Headers** — Responses include `X-RateLimit-Limit`, `X-RateLimit-Remaining`, `X-RateLimit-Reset`
- **Retry-After** — 429 responses include `retry_after` seconds until window resets
- **Admin REST Route** — `GET/POST /jwt-auth/v1/admin/rate-limit`

#### Geo-IP Identification
- **Multiple Providers** — ip-api.com (free), ipapi.co, ipinfo.io
- **24-Hour Caching** — Geo lookups cached as transients to minimize API calls
- **Analytics Integration** — Country/city data stored with each analytics event
- **Configurable Provider** — Switch provider or disable via admin setting

#### Analytics & Monitoring
- **Event Tracking** — Tracks token generation, auth failures, API key usage, OAuth logins, Firebase logins
- **Analytics Dashboard** — `GET /jwt-auth/v1/admin/analytics` with 30-day aggregated stats
- **Auth Method Breakdown** — See which authentication methods are most used
- **Top Endpoints** — Identify most-accessed endpoints
- **Daily Request Trends** — Day-by-day request volume for last 30 days
- **Country Breakdown** — Top 10 countries by request volume
- **User Activity** — Per-user auth event history

#### Firebase Authentication
- **Firebase ID Token Verification** — Verifies Firebase JWT tokens against Google's public keys
- **Auto User Creation** — Automatically create WP users from Firebase credentials
- **Firebase UID Sync** — Stores `firebase_uid` in WP user meta for identity mapping
- **Login Mode Control** — Choose: Firebase only, WordPress only, or both
- **Custom Redirect URLs** — Configure login/logout redirect URLs (WooCommerce-aware)
- **WordPress Session** — `POST /jwt-auth/v1/auth/firebase/session` creates a WP cookie session
- **Public Config Endpoint** — `GET /jwt-auth/v1/auth/firebase/config` for front-end SDK init

#### Firebase Social Login (7 Providers)
- Google
- Facebook
- Apple
- Twitter / X
- GitHub
- Yahoo
- Microsoft

#### Firebase Phone / OTP Authentication
- Phone number OTP via Firebase Phone Auth
- Invisible reCAPTCHA integration
- WooCommerce checkout and My Account compatibility

#### Firebase Shortcodes
- `[firebase_login]` — Email/password login form with optional social buttons
- `[firebase_register]` — Registration form (creates Firebase + WP user)
- `[firebase_social_login]` — Social provider buttons (7 providers, 3 display styles)
- Lazy Firebase SDK loading (only on pages with shortcodes)
- Responsive CSS with CSS custom properties for theming

#### WooCommerce Integration
- **Checkout Firebase Login** — Firebase login form above WooCommerce checkout form
- **My Account Firebase Login** — Firebase login on WooCommerce My Account page
- **New Customer → Firebase Sync** — Auto-creates Firebase user when WC customer registers

#### Firestore Sync
- **User Meta Sync** — Syncs WordPress user meta to Firestore `wp_users` collection
- **Selective Field Sync** — Configure which meta keys to sync (empty = all public keys)
- **WooCommerce Product Sync** — Syncs product data to `wc_products` collection
- **WooCommerce Order Sync** — Syncs order status changes to `wc_orders` collection
- **Service Account Auth** — Uses Firebase service account for server-to-server Firestore access
- **Token Caching** — Caches OAuth2 access tokens for 50 minutes

#### Database Schema
Four new database tables:
- `{prefix}jwt_tokens` — Stores issued tokens for refresh/revocation
- `{prefix}jwt_api_keys` — Stores API key hashes and permissions
- `{prefix}jwt_rate_limits` — Sliding window rate limit counters
- `{prefix}jwt_analytics` — Auth event log with Geo-IP and user agent

#### Developer Experience
- Singleton pattern on all new classes for safe cross-plugin access
- 15+ new action hooks and filters
- `Jwt_Auth_Helpers` utility class (IP detection, key generation, hashing, route matching)
- MIT license — permissive use in commercial projects

### Improvements

- Updated `firebase/php-jwt` library namespace wrapper for conflict prevention
- Token validation now checks `jti` revocation before accepting token
- `generate_token()` now returns `token_type`, `expires_in`, and `refresh_token` fields
- CORS support now also configurable via admin UI (not just wp-config.php constant)
- Admin notices for upsells removed entirely

### Previous Releases

## [1.5.1] — Prior release
- Security: Updated dependencies
- Feature: Smart upgrade prompts based on usage
- Fix: UTM tracking on upgrade links

## [1.4.0] — Prior release
- Feature: Live API Explorer in admin dashboard
- Feature: Enhanced Configuration Dashboard (React)
- Performance: Consolidated API calls

## [1.0.0] — Initial release
- Standard JWT Authentication (RFC 7519)
- `/token` and `/token/validate` endpoints
- `JWT_AUTH_SECRET_KEY` configuration
- WordPress hooks: `jwt_auth_expire`, `jwt_auth_token_before_sign`, etc.
