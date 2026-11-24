# JWT Authenticator — Developer Documentation

> **Version:** 1.3.3 | **License:** MIT | **PHP:** 8.0+ | **WordPress:** 5.0+

## Table of Contents

1. [Architecture Overview](#architecture-overview)
2. [REST API Reference](#rest-api-reference)
3. [Configuration Reference](#configuration-reference)
4. [Authentication Methods](#authentication-methods)
5. [API Protection](#api-protection)
6. [Firebase Integration](#firebase-integration)
7. [WooCommerce Integration](#woocommerce-integration)
8. [Firestore Sync](#firestore-sync)
9. [Shortcodes](#shortcodes)
10. [Hooks & Filters Reference](#hooks--filters-reference)
11. [Security Best Practices](#security-best-practices)
12. [Developer Recipes](#developer-recipes)
13. [Admin Dashboards & Views (Bootstrap 5)](#admin-dashboards--views-bootstrap-5)

---

## Architecture Overview

```
jwt-authenticator/
├── jwt-authenticator.php                 ← Plugin bootstrap
├── LICENSE                               ← MIT License
├── DOCUMENTATION.md                      ← This file
├── CHANGELOG.md
├── includes/
│   ├── class-jwt-auth.php                ← Core class (registers all hooks)
│   ├── class-jwt-auth-db.php             ← Database installer & schema
│   ├── class-jwt-auth-helpers.php        ← Static utility helpers
│   ├── class-jwt-auth-token-manager.php  ← Token refresh, revocation, admin tools
│   ├── class-jwt-auth-api-keys.php       ← API Key authentication
│   ├── class-jwt-auth-oauth.php          ← OAuth 2.0 server
│   ├── class-jwt-auth-third-party-jwt.php← Third-party JWT user creation
│   ├── class-jwt-auth-protection.php     ← Selective API protection
│   ├── class-jwt-auth-rate-limiter.php   ← Rate limiting
│   ├── class-jwt-auth-geo-ip.php         ← Geo-IP lookup
│   ├── class-jwt-auth-analytics.php      ← Analytics & event tracking
│   ├── class-jwt-auth-firebase.php       ← Firebase Auth integration
│   ├── class-jwt-auth-shortcodes.php     ← Frontend shortcodes
│   ├── class-jwt-auth-woocommerce.php    ← WooCommerce integration
│   └── class-jwt-auth-firestore.php      ← Firestore data sync
├── public/
│   ├── class-jwt-auth-public.php         ← Token generation/validation endpoints
│   ├── js/firebase-ui.js                 ← Firebase UI JavaScript
│   └── css/firebase-ui.css               ← Firebase UI styles
└── admin/
    ├── class-jwt-auth-admin.php          ← Admin menu & REST routes
    ├── partials/
    │   └── jwt-auth-admin-dashboard.php  ← Unified Bootstrap 5 Dashboard & Settings (?page=jwt_authenticator)
    ├── css/
    │   ├── bootstrap.min.css             ← Local Bootstrap 5.3.3 CSS
    │   └── jwt-admin-theme.css           ← Scoped Bootstrap 5 admin integration theme
    └── js/
        └── bootstrap.bundle.min.js       ← Local Bootstrap 5.3.3 JS Bundle (with Popper)
```

### Authentication Flow

```
Client Request
     │
     ▼
determine_current_user (WordPress filter)
     │
     ├─ Priority 10: Jwt_Auth_Public    ← JWT Bearer token
     ├─ Priority 20: Jwt_Auth_Api_Keys  ← X-API-Key header / query param
     ├─ Priority 25: Jwt_Auth_ThirdPartyJwt ← Third-party JWT tokens
     │
     ▼
rest_pre_dispatch
     ├─ Priority  1: Jwt_Auth_RateLimiter  ← Rate limit check → 429
     ├─ Priority  1: Jwt_Auth_Protection   ← Route protection → 401/403/404
     │
     ▼
Route Handler executes
     │
     ▼
rest_post_dispatch → Rate limit headers appended
```

---

## REST API Reference

**Base URL:** `https://your-site.com/wp-json`

### JWT Token Endpoints

#### `POST /jwt-auth/v1/token` — Generate Token
Accepts username/email + password, returns access + refresh token pair.

**Request:**
```json
{ "username": "admin", "password": "secret123" }
```
*Also accepts `email` field as alias for `username`.*

**Response (200):**
```json
{
  "token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9...",
  "refresh_token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9...",
  "expires_in": 3600,
  "token_type": "Bearer",
  "user_email": "admin@example.com",
  "user_nicename": "admin",
  "user_display_name": "Admin"
}
```

**Error (403):**
```json
{ "code": "[jwt_auth] incorrect_password", "message": "The password you entered is incorrect.", "data": { "status": 403 } }
```

**curl:**
```bash
curl -X POST https://your-site.com/wp-json/jwt-auth/v1/token \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"secret123"}'
```

---

#### `POST /jwt-auth/v1/token/validate` — Validate Token
**Request header:** `Authorization: Bearer <token>`

**Response (200):**
```json
{ "code": "jwt_auth_valid_token", "data": { "status": 200 } }
```

---

#### `POST /jwt-auth/v1/token/refresh` — Refresh Token
**Request:**
```json
{ "refresh_token": "eyJ0eXAiOiJKV1Qi..." }
```

**Response (200):**
```json
{
  "token": "eyJ0eXAiOiJKV1Qi...",
  "refresh_token": "eyJ0eXAiOiJKV1Qi...",
  "expires_in": 3600,
  "token_type": "Bearer"
}
```

---

#### `POST /jwt-auth/v1/token/revoke` — Revoke Token
**Request header:** `Authorization: Bearer <token>`

**Response (200):**
```json
{ "code": "jwt_auth_token_revoked", "message": "Token revoked successfully.", "data": { "status": 200 } }
```

---

#### `GET /jwt-auth/v1/tokens` — List User Tokens
**Request header:** `Authorization: Bearer <token>`

**Response (200):**
```json
{
  "tokens": [
    {
      "jti": "01hx2v3k4m5n6p7q8r9s0t1u2v",
      "token_type": "access",
      "issued_at": "2024-01-15T10:00:00Z",
      "expires_at": "2024-01-15T11:00:00Z",
      "ip_address": "192.168.1.1",
      "revoked": false
    }
  ],
  "total": 3,
  "page": 1,
  "per_page": 20
}
```

---

#### `DELETE /jwt-auth/v1/tokens/{jti}` — Revoke Specific Token
**Request header:** `Authorization: Bearer <token>`

**Response (200):**
```json
{ "code": "jwt_auth_token_revoked", "data": { "status": 200 } }
```

---

### Admin Token Manager REST API

All admin endpoints require `manage_options` permissions (WordPress Administrator) and `X-WP-Nonce` header.

#### `GET /jwt-auth/v1/admin/tokens` — List All Tokens Across All Users
Supports filtering, search, and pagination.

**Query Parameters:**
- `status`: `all` (default), `active`, `expired`, `revoked`
- `type`: `all` (default), `access`, `refresh`
- `search`: Search username, email, or JTI
- `page`: Page number (default: 1)
- `per_page`: Tokens per page (default: 20, max: 100)

**Response (200):**
```json
{
  "tokens": [
    {
      "id": 1,
      "user_id": 1,
      "username": "admin",
      "user_email": "admin@example.com",
      "display_name": "Site Admin",
      "avatar_url": "https://secure.gravatar.com/avatar/...",
      "token_type": "access",
      "jti": "01hx2v3k4m5n6p7q8r9s0t1u2v",
      "issued_at": "2024-01-15 10:00:00",
      "expires_at": "2024-01-15 11:00:00",
      "revoked": false,
      "status": "active",
      "ip_address": "127.0.0.1"
    }
  ],
  "pagination": { "total": 45, "page": 1, "per_page": 20, "total_pages": 3 },
  "stats": { "total": 45, "active": 32, "revoked": 5, "expired": 8 }
}
```

---

#### `DELETE /jwt-auth/v1/admin/tokens/{jti}` — Revoke or Delete Any Token
- Default: Soft-deletes (sets `revoked = 1`, `revoked_at = NOW()`).
- Permanent deletion: Add `?hard=1` or `{ "hard": true }`.

---

#### `POST /jwt-auth/v1/admin/tokens/refresh` — Rotate & Refresh Token
Rotates a token by either `refresh_token` string or `jti`. Old refresh token is revoked and a new pair is issued.

**Request:**
```json
{ "jti": "01hx2v3k4m5n6p7q8r9s0t1u2v" }
```

---

#### `POST /jwt-auth/v1/admin/tokens/generate` — Generate Token Pair for User
Generates a new token pair for any user directly from the dashboard.

**Request:**
```json
{ "user_id": 1, "expiry_seconds": 3600 }
```

---

#### `GET /jwt-auth/v1/admin/tokens/stats` — Usage Statistics
Returns real-time usage statistics:
```json
{
  "total": 45,
  "active": 32,
  "expired": 8,
  "revoked": 5,
  "access_count": 35,
  "refresh_count": 10,
  "created_24h": 12,
  "created_7d": 28,
  "created_30d": 45,
  "top_users": [...],
  "recent_ips": [...]
}
```

---

#### `GET /jwt-auth/v1/admin/tokens/config-detect` — wp-config.php & JWT Configuration Detection
Returns real-time detection of `wp-config.php` constants, masked secret key, key entropy, algorithm, and lifetime settings:
```json
{
  "secret_key_configured": true,
  "secret_key_masked": "sk_l••••••••9a2b",
  "secret_key_length": 64,
  "secret_key_strength": "Excellent (512-bit+)",
  "wp_config_found": true,
  "wp_config_path": "/var/www/html/wp-config.php",
  "in_file_detected": true,
  "cors_enabled": true,
  "dev_mode": false,
  "algorithm": "HS256",
  "access_token_expiry": 3600,
  "refresh_token_expiry": 604800,
  "custom_header": "Authorization"
}
```

---

#### `POST /jwt-auth/v1/admin/tokens/purge-expired` — Clean Expired Records
Permanently deletes all expired token rows from the `jwt_tokens` database table.

---

#### `POST /jwt-auth/v1/admin/tokens/revoke-user` — Bulk Revoke for User
Revokes all active credentials for a specific user ID.

---

### API Key Endpoints

#### `POST /jwt-auth/v1/api-keys` — Create API Key
**Request header:** `Authorization: Bearer <token>`

**Request:**
```json
{ "name": "Mobile App Key", "permissions": [], "expires_at": "2025-01-01T00:00:00Z" }
```

**Response (201):**
```json
{
  "id": 42,
  "api_key": "jwta_a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6a7b8c9d0e1f2a3b4",
  "name": "Mobile App Key",
  "created_at": "2024-01-15T10:00:00Z"
}
```
> **Important:** The `api_key` value is returned **once only**. Store it securely.

---

#### `GET /jwt-auth/v1/api-keys` — List API Keys
Returns list without plaintext keys. **Requires Bearer token.**

---

#### `DELETE /jwt-auth/v1/api-keys/{id}` — Delete API Key
**Requires Bearer token.** Can only delete own keys.

---

#### `POST /jwt-auth/v1/api-keys/admin/universal` — Create Universal Key
**Requires admin Bearer token.**

```json
{ "name": "Server-to-Server Key", "permissions": ["/wp/v2/*"] }
```

---

### OAuth 2.0 Endpoints

#### `POST /jwt-auth/v1/oauth/token` — OAuth Token

**Password grant:**
```json
{ "grant_type": "password", "username": "admin", "password": "secret123" }
```

**Refresh token grant:**
```json
{ "grant_type": "refresh_token", "refresh_token": "eyJ..." }
```

**Client credentials grant:**
```json
{ "grant_type": "client_credentials", "client_id": "my-app", "client_secret": "secret" }
```

**Response (200):**
```json
{
  "access_token": "eyJ...",
  "token_type": "Bearer",
  "expires_in": 3600,
  "refresh_token": "eyJ...",
  "scope": ""
}
```

---

### Firebase Endpoints

#### `POST /jwt-auth/v1/auth/firebase` — Firebase Auth
Accepts Firebase ID token, returns WordPress JWT.

**Request:**
```json
{ "firebase_token": "eyJ...", "provider": "google" }
```

**Response (200):**
```json
{
  "token": "eyJ...",
  "refresh_token": "eyJ...",
  "expires_in": 3600,
  "token_type": "Bearer",
  "user_email": "user@gmail.com",
  "user_nicename": "user",
  "user_display_name": "John Doe",
  "firebase_uid": "abc123uid",
  "is_new_user": false
}
```

**curl:**
```bash
curl -X POST https://your-site.com/wp-json/jwt-auth/v1/auth/firebase \
  -H "Content-Type: application/json" \
  -d '{"firebase_token":"FIREBASE_ID_TOKEN_HERE"}'
```

---

#### `GET /jwt-auth/v1/auth/firebase/config` — Firebase Public Config
Returns the Firebase configuration needed to initialize the client SDK.

**Response (200):**
```json
{
  "project_id": "my-firebase-project",
  "web_api_key": "AIzaSy...",
  "auth_domain": "my-firebase-project.firebaseapp.com",
  "enabled_providers": ["google", "github", "password"]
}
```

---

#### `POST /jwt-auth/v1/auth/third-party` — Third-Party JWT Auth
```json
{ "provider": "my-provider", "token": "eyJ..." }
```

---

### Admin Endpoints (require `manage_options`)

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET/POST | `/jwt-auth/v1/admin/settings` | Get/update plugin settings |
| GET | `/jwt-auth/v1/admin/status` | Configuration health check |
| GET/POST | `/jwt-auth/v1/admin/protection` | API protection settings |
| GET/POST | `/jwt-auth/v1/admin/rate-limit` | Rate limit configuration |
| GET | `/jwt-auth/v1/admin/analytics` | Analytics data (last 30 days) |

---

## Configuration Reference

### wp-config.php Constants

| Constant | Type | Description |
|----------|------|-------------|
| `JWT_AUTH_SECRET_KEY` | string | **Required.** Secret key for HS256 signing. Use a strong random value. |
| `JWT_AUTH_CORS_ENABLE` | bool | Enable CORS headers on REST API responses. |

### WordPress Options (wp_update_option)

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `jwt_auth_access_token_expiry` | int | `3600` | Access token lifetime in seconds |
| `jwt_auth_refresh_token_expiry` | int | `2592000` | Refresh token lifetime in seconds (30 days) |
| `jwt_auth_custom_header` | string | `''` | Custom header name for JWT (e.g. `X-Auth-Token`) |
| `jwt_auth_protection_mode` | string | `disabled` | `disabled` / `selective` / `full` |
| `jwt_auth_protected_routes` | JSON | `[]` | Route patterns requiring auth (selective mode) |
| `jwt_auth_whitelisted_routes` | JSON | `[]` | Routes always allowed without auth |
| `jwt_auth_disable_rest_for_guests` | bool | `false` | Require auth for all REST requests |
| `jwt_auth_disabled_endpoints` | JSON | `[]` | Completely disable these route patterns |
| `jwt_auth_role_route_map` | JSON | `{}` | Map WP roles to allowed routes |
| `jwt_auth_disable_rest_api` | bool | `false` | Disable REST API for non-admins |
| `jwt_auth_rate_limit_enabled` | bool | `false` | Enable rate limiting |
| `jwt_auth_rate_limit_requests` | int | `100` | Max requests per window |
| `jwt_auth_rate_limit_window` | int | `3600` | Window size in seconds |
| `jwt_auth_rate_limit_per_user` | bool | `false` | Limit per user vs per IP |
| `jwt_auth_api_key_header` | string | `X-API-Key` | Custom header for API key auth |
| `jwt_auth_firebase_enabled` | bool | `false` | Enable Firebase integration |
| `jwt_auth_firebase_project_id` | string | `''` | Firebase project ID |
| `jwt_auth_firebase_web_api_key` | string | `''` | Firebase Web API key |
| `jwt_auth_firebase_service_account` | text | `''` | Firebase service account JSON |
| `jwt_auth_firebase_login_mode` | string | `both` | `firebase_only` / `wordpress_only` / `both` |
| `jwt_auth_firebase_auto_create_users` | bool | `true` | Auto-create WP users from Firebase |
| `jwt_auth_firebase_default_role` | string | `subscriber` | Role for auto-created users |
| `jwt_auth_firebase_redirect_login` | string | `''` | Redirect URL after Firebase login |
| `jwt_auth_firebase_redirect_logout` | string | `''` | Redirect URL after logout |
| `jwt_auth_firebase_sync_uid` | bool | `true` | Sync Firebase UID to WP user meta |
| `jwt_auth_firebase_enabled_providers` | JSON | `[]` | Enabled social providers |
| `jwt_auth_woo_firebase_checkout` | bool | `false` | Firebase login on WC checkout |
| `jwt_auth_woo_firebase_myaccount` | bool | `false` | Firebase login on WC My Account |
| `jwt_auth_woo_sync_to_firebase` | bool | `false` | Sync new WC customers to Firebase |
| `jwt_auth_firestore_enabled` | bool | `false` | Enable Firestore sync |
| `jwt_auth_firestore_project_id` | string | `''` | Firestore project ID |
| `jwt_auth_firestore_sync_user_meta` | bool | `false` | Sync user meta to Firestore |
| `jwt_auth_firestore_sync_woo_products` | bool | `false` | Sync WC products to Firestore |
| `jwt_auth_firestore_sync_woo_orders` | bool | `false` | Sync WC orders to Firestore |
| `jwt_auth_geoip_provider` | string | `ip-api` | `ip-api` / `ipapi` / `ipinfo` / `none` |
| `jwt_auth_geoip_api_key` | string | `''` | API key for Geo-IP provider |
| `jwt_auth_third_party_enabled` | bool | `false` | Enable third-party JWT auth |
| `jwt_auth_third_party_providers` | JSON | `[]` | Third-party provider configs |
| `jwt_auth_oauth_enabled` | bool | `false` | Enable OAuth 2.0 server |
| `jwt_auth_oauth_clients` | JSON | `[]` | Registered OAuth 2.0 clients |

---

## Authentication Methods

### 1. JWT Bearer Token
Include the access token in every request:
```
Authorization: Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9...
```

### 2. API Key
Three ways to pass an API key:
```bash
# Header (recommended)
curl -H "X-API-Key: jwta_yourkeyhere" https://your-site.com/wp-json/wp/v2/posts

# Query parameter
curl "https://your-site.com/wp-json/wp/v2/posts?api_key=jwta_yourkeyhere"

# Authorization header
curl -H "Authorization: ApiKey jwta_yourkeyhere" https://your-site.com/wp-json/wp/v2/posts
```

### 3. OAuth 2.0
```bash
# Get access token
TOKEN=$(curl -s -X POST https://your-site.com/wp-json/jwt-auth/v1/oauth/token \
  -d 'grant_type=password&username=admin&password=secret' | jq -r .access_token)

# Use token
curl -H "Authorization: Bearer $TOKEN" https://your-site.com/wp-json/wp/v2/posts
```

### 4. Basic Authentication (email or username)
```bash
curl -X POST https://your-site.com/wp-json/jwt-auth/v1/token \
  -d '{"username":"user@example.com","password":"secret"}'
```

### 5. Firebase Token
```javascript
// Get Firebase ID token from Firebase SDK
const idToken = await firebase.auth().currentUser.getIdToken();

// Exchange for WordPress JWT
const res = await fetch('/wp-json/jwt-auth/v1/auth/firebase', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({ firebase_token: idToken })
});
const { token } = await res.json();
```

---

## API Protection

### Protection Modes

**Disabled (default):** No automatic protection — existing WordPress auth applies.

**Selective:** Only routes matching `jwt_auth_protected_routes` require authentication.
```php
update_option('jwt_auth_protected_routes', json_encode([
  '/wp/v2/users',
  '/wp/v2/comments',
  '/myapp/v1/*'   // wildcard supported
]));
```

**Full:** All routes require authentication, except the whitelist.
```php
update_option('jwt_auth_protection_mode', 'full');
```

### Role-Based Protection
```php
update_option('jwt_auth_role_route_map', json_encode([
  'editor'      => ['/wp/v2/*'],
  'author'      => ['/wp/v2/posts', '/wp/v2/media'],
  'subscriber'  => ['/wp/v2/users/me'],
]));
```

### Disable REST API
```php
// Disable for everyone except admins
update_option('jwt_auth_disable_rest_api', true);

// Or disable completely for guests
update_option('jwt_auth_disable_rest_for_guests', true);
```

---

## Firebase Integration

### Setup Guide

**Step 1 — Create Firebase Project**
1. Go to [console.firebase.google.com](https://console.firebase.google.com)
2. Click "Create a project" → enter name → continue

**Step 2 — Enable Authentication Providers**
1. In Firebase Console: Authentication → Sign-in method
2. Enable desired providers (Google, Facebook, etc.)
3. For each social provider, follow provider-specific setup (OAuth client IDs)

**Step 3 — Get Service Account Key**
1. Project Settings (gear icon) → Service accounts
2. Click "Generate new private key" → download JSON file
3. In WordPress admin: JWT Auth → Firebase → paste entire JSON content into "Service Account" field

**Step 4 — Get Web API Key**
1. Project Settings → General → "Your apps" section
2. Copy "Web API Key" (looks like `AIzaSy...`)
3. Enter in JWT Auth → Firebase → "Web API Key"

**Step 5 — Configure Plugin**
```php
update_option('jwt_auth_firebase_enabled', true);
update_option('jwt_auth_firebase_project_id', 'my-project-123');
update_option('jwt_auth_firebase_web_api_key', 'AIzaSy...');
update_option('jwt_auth_firebase_login_mode', 'both'); // or 'firebase_only'
update_option('jwt_auth_firebase_auto_create_users', true);
update_option('jwt_auth_firebase_enabled_providers', json_encode(['google','github','password']));
```

---

## WooCommerce Integration

```php
// Enable Firebase login on checkout
update_option('jwt_auth_woo_firebase_checkout', true);

// Enable Firebase login on My Account
update_option('jwt_auth_woo_firebase_myaccount', true);

// Auto-sync WooCommerce registrations to Firebase
update_option('jwt_auth_woo_sync_to_firebase', true);
```

---

## Firestore Sync

```php
// Enable Firestore sync
update_option('jwt_auth_firestore_enabled', true);
update_option('jwt_auth_firestore_project_id', 'my-project-123');

// Sync user meta (uses service account from Firebase settings)
update_option('jwt_auth_firestore_sync_user_meta', true);

// Only sync specific meta keys (empty array = all public keys)
update_option('jwt_auth_firestore_user_meta_fields', json_encode(['first_name','last_name','billing_address_1']));

// Sync WooCommerce data
update_option('jwt_auth_firestore_sync_woo_products', true);
update_option('jwt_auth_firestore_sync_woo_orders', true);
```

Data appears in Firestore under collections: `wp_users`, `wc_products`, `wc_orders`.

---

## Shortcodes

### `[firebase_login]`
Renders a Firebase email/password login form.

| Attribute | Default | Description |
|-----------|---------|-------------|
| `redirect_url` | `jwt_auth_firebase_redirect_login` option | URL to redirect after login |
| `show_social` | `false` | Show social login buttons below form |
| `class` | `''` | Extra CSS class on container |

```
[firebase_login redirect_url="/dashboard" show_social="true"]
```

### `[firebase_register]`
Renders a Firebase registration form.

| Attribute | Default | Description |
|-----------|---------|-------------|
| `redirect_url` | home_url() | URL to redirect after registration |
| `default_role` | `subscriber` | WordPress role for new users |
| `class` | `''` | Extra CSS class |

```
[firebase_register redirect_url="/welcome" default_role="contributor"]
```

### `[firebase_social_login]`
Renders social provider buttons only.

| Attribute | Default | Description |
|-----------|---------|-------------|
| `providers` | `google,facebook,github` | Comma-separated provider list |
| `redirect_url` | option or home_url() | Redirect after login |
| `class` | `''` | Extra CSS class |
| `button_style` | `default` | `default` (text+icon) or `icon` (icon only) |

**Available providers:** `google`, `facebook`, `apple`, `twitter`, `github`, `yahoo`, `microsoft`

```
[firebase_social_login providers="google,apple,github" button_style="default"]
```

---

## Hooks & Filters Reference

### Actions

| Hook | Parameters | Description |
|------|-----------|-------------|
| `jwt_auth_firebase_user_created` | `$user_id, $firebase_payload, $provider` | Fired when a new WP user is created from Firebase |
| `jwt_auth_firebase_user_logged_in` | `$user_id, $firebase_payload` | Fired on each Firebase login |
| `jwt_auth_woo_customer_synced_to_firebase` | `$customer_id, $firebase_response` | Fired after WC customer is synced to Firebase |

### Filters

| Filter | Parameters | Return | Description |
|--------|-----------|--------|-------------|
| `jwt_auth_expire` | `$expire, $issued_at` | int | Modify access token expiry timestamp |
| `jwt_auth_not_before` | `$nbf, $issued_at` | int | Modify token not-before timestamp |
| `jwt_auth_token_before_sign` | `$token_array, $user` | array | Modify JWT payload before signing |
| `jwt_auth_token_before_dispatch` | `$data, $user` | array | Modify token response data |
| `jwt_auth_algorithm` | `$algorithm` | string | Change signing algorithm (e.g. `RS256`) |
| `jwt_auth_cors_allow_headers` | `$headers` | string | Customize CORS allowed headers |
| `jwt_auth_whitelist` | `$endpoints` | array | Add routes to auth whitelist |
| `jwt_auth_firebase_user_data` | `$user_data, $firebase_payload` | array | Modify user data before WP user creation |
| `jwt_auth_firebase_default_role` | `$role, $firebase_payload` | string | Customize role for auto-created Firebase users |
| `jwt_auth_firebase_before_token_verify` | `$id_token` | string | Intercept before Firebase token verification |

### Usage Examples

```php
// Extend token to 24 hours
add_filter( 'jwt_auth_expire', function( $expire, $issued_at ) {
    return $issued_at + DAY_IN_SECONDS;
}, 10, 2 );

// Add custom data to JWT payload
add_filter( 'jwt_auth_token_before_sign', function( $token, $user ) {
    $token['data']['user']['roles'] = $user->roles;
    $token['data']['user']['capabilities'] = array_keys( array_filter( $user->allcaps ) );
    return $token;
}, 10, 2 );

// Use RS256 algorithm
add_filter( 'jwt_auth_algorithm', fn() => 'RS256' );

// Assign editor role to Firebase Google users
add_filter( 'jwt_auth_firebase_default_role', function( $role, $payload ) {
    if ( isset( $payload['firebase']['sign_in_provider'] ) && $payload['firebase']['sign_in_provider'] === 'google.com' ) {
        return 'editor';
    }
    return $role;
}, 10, 2 );

// Hook into new Firebase user creation
add_action( 'jwt_auth_firebase_user_created', function( $user_id, $payload, $provider ) {
    // Send welcome email
    wp_mail(
        get_userdata($user_id)->user_email,
        'Welcome!',
        'Thanks for signing up via ' . $provider
    );
}, 10, 3 );

// Protect a custom endpoint (programmatic)
add_filter( 'jwt_auth_whitelist', function( $endpoints ) {
    // Always allow this public endpoint
    $endpoints[] = '/myplugin/v1/public-data';
    return $endpoints;
} );
```

---

## Security Best Practices

1. **Secret Key:** Use a minimum 32-character random secret. Generate with:
   ```bash
   curl https://api.wordpress.org/secret-key/1.1/salt/
   ```

2. **Token Expiry:** Keep access tokens short (1 hour). Use refresh tokens for longevity.

3. **HTTPS Only:** Never use JWT auth over HTTP. All tokens are Bearer credentials.

4. **Rate Limiting:** Enable rate limiting in production:
   ```php
   update_option('jwt_auth_rate_limit_enabled', true);
   update_option('jwt_auth_rate_limit_requests', 60); // 60 req/hour per IP
   ```

5. **API Key Rotation:** Rotate API keys regularly. Revoke unused keys promptly.

6. **Firebase Security Rules:** Add Firestore security rules to prevent direct client access:
   ```
   rules_version = '2';
   service cloud.firestore {
     match /databases/{database}/documents {
       match /{document=**} {
         allow read, write: if false; // Block all direct client access
       }
     }
   }
   ```

7. **Custom Header:** For extra security, use a custom auth header:
   ```php
   update_option('jwt_auth_custom_header', 'X-My-App-Token');
   ```

---

## Developer Recipes

### Protect a custom WP REST API endpoint

```php
add_action( 'rest_api_init', function() {
    register_rest_route( 'myapp/v1', '/sensitive-data', [
        'methods'             => 'GET',
        'callback'            => 'my_sensitive_handler',
        'permission_callback' => function() {
            return is_user_logged_in(); // JWT middleware sets the current user
        },
    ] );
} );
```

### Create an API key programmatically

```php
$manager  = Jwt_Auth_Api_Keys::get_instance();
$key_data = $manager->create_api_key(
    get_current_user_id(),   // user_id (0 for universal)
    'CI/CD Pipeline Key',    // name
    [ '/myapp/v1/*' ],       // allowed routes (empty = all)
    '2025-12-31T23:59:59Z'  // expires_at (null = never)
);

// $key_data['api_key'] — store this securely, shown ONCE
```

### Verify a Firebase token server-side

```php
$firebase = Jwt_Auth_Firebase::get_instance();
$payload  = $firebase->verify_firebase_token( $id_token_from_client );

if ( is_wp_error( $payload ) ) {
    // Handle error
    wp_die( $payload->get_error_message() );
}

// $payload['sub']   = Firebase UID
// $payload['email'] = User email
// $payload['name']  = Display name
```

### Add a custom third-party JWT provider

```php
$providers = json_decode( get_option( 'jwt_auth_third_party_providers', '[]' ), true );
$providers[] = [
    'name'              => 'Auth0',
    'issuer'            => 'https://your-tenant.auth0.com/',
    'jwks_uri'          => 'https://your-tenant.auth0.com/.well-known/jwks.json',
    'audience'          => 'your-api-identifier',
    'email_claim'       => 'email',
    'name_claim'        => 'name',
    'role'              => 'subscriber',
    'auto_create_users' => true,
];
update_option( 'jwt_auth_third_party_providers', json_encode( $providers ) );
```

---

## Admin Unified Dashboard (Bootstrap 5)

The plugin provides a unified single-page administrative dashboard under **Settings → JWT Authenticator** (`/wp-admin/options-general.php?page=jwt_authenticator`), built with a fully responsive Bootstrap 5 tabbed interface:

### Tabs:
1. **Dashboard (Overview)**:
   - 4 clickable overview stat cards (Total, Active, Expired, Revoked) that filter the All Tokens view
   - System & Environment Status card (PHP, WP, MySQL, JWT Secret Key, CORS status)
   - Quick Action buttons (Generate Token, Refresh Tool, Purge Expired, Settings)
2. **Generate Token**:
   - Side-by-side cards for:
     - **Generate New JWT Token Pair**: WordPress user dropdown, expiry selector, generated access & refresh tokens with 1-click copy and cURL snippet
     - **Refresh & Rotate Token Tool**: Paste any refresh token string or JTI to rotate credentials immediately
3. **All Tokens**:
   - Live token listing table with status filter, type filter, search bar, and pagination
   - Per-row actions: Refresh & rotate, revoke, or permanently delete token
4. **Settings**:
   - Bootstrap accordion organizing settings into 5 structured sections:
     - General & JWT Core (Access/Refresh token expiry, Custom header, Email login)
     - API Protection (Standard/Selective/Full protection, Guest restrictions, route lists)
     - Rate Limiting & Geo-IP (Rate limit limits/window, per-user counting, Geo-IP providers)
     - API Keys & OAuth 2.0 (API key header, universal key fallback, OAuth endpoints)
     - Firebase & WooCommerce (Project ID, Web API key, social providers, WooCommerce checkout & Firestore sync)
   - One-click "Save All Settings" action
5. **wp-config & JWT Configuration**:
   - Detects `wp-config.php` file path, accessibility, and placement
   - Displays masked secret key, character length, bit entropy rating, and placement diagnostics
   - Checks CORS and Dev Mode constant statuses
   - Copyable `wp-config.php` snippet with a **"Generate Random Secure Key"** 64-character generator button
6. **Usage Statistics**:
   - Real-time active sessions count, 24h, 7d, and 30d token issuance metrics
   - Access vs. Refresh token distribution progress bar
   - Top users by active credentials with bulk "Revoke All for User" option
   - Recent client IP address activity log
7. **Live API Explorer**:
   - In-browser interactive REST tester for `/jwt-auth/v1/token`
   - Formatted JSON response viewer with real-time HTTP status codes

