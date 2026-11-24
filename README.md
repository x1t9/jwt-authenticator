# JWT Authenticator

> **Complete JWT, Firebase, OAuth 2.0, and API Key authentication for the WordPress REST API — 100% free, MIT licensed.**
>
> By **x1t9** — [github.com/x1t9/jwt-authenticator](https://github.com/x1t9/jwt-authenticator)

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)
[![WordPress](https://img.shields.io/badge/WordPress-5.0%2B-blue?logo=wordpress)](https://wordpress.org)
[![PHP](https://img.shields.io/badge/PHP-8.0%2B-purple?logo=php)](https://php.net)
[![Version](https://img.shields.io/badge/version-1.3.3-green)](CHANGELOG.md)

---

## ✨ Features

### Core JWT
- 🔑 Token generation (`POST /wp-json/jwt-auth/v1/token`) — username **or email** + password
- 🔄 Token **refresh** and **revocation** with rotation
- 📋 Token listing and per-token revoke by JTI
- ⏱ Configurable expiry (access: 1h default, refresh: 30d default)
- 🔐 11 signing algorithms: HS256/384/512, RS256/384/512, ES256/384/512, PS256/384/512

### Authentication Methods
| Method | How to send |
|--------|------------|
| JWT Bearer | `Authorization: Bearer <token>` |
| API Key (universal or per-user) | `X-API-Key: jwta_...` or `?api_key=` or `Authorization: ApiKey ...` |
| OAuth 2.0 | `password`, `refresh_token`, `client_credentials` grants |
| Firebase ID Token | `POST /wp-json/jwt-auth/v1/auth/firebase` |
| Third-party JWT | Auth0, Okta, Cognito, etc. — with auto user creation |
| Basic (email/username) | Via token endpoint |

### 🔥 Firebase Integration
- Verify Firebase ID tokens against Google's public keys
- 7 social providers: **Google, Facebook, Apple, Twitter, GitHub, Yahoo, Microsoft**
- Phone/OTP passwordless login
- Auto-create WordPress users from Firebase credentials
- Configurable login mode: Firebase only / WordPress only / both
- WooCommerce checkout and My Account integration
- Auto-sync WooCommerce customers to Firebase on registration

### 🔒 API Protection
- Three modes: **Disabled**, **Selective**, **Full**
- Wildcard route patterns (`/wp/v2/*`)
- Role-based route control
- Rate limiting (per-IP or per-user, sliding window)
- Geo-IP identification

### 📊 Analytics
- 30-day event tracking: token generation, auth failures, API key usage
- Auth method breakdown, top endpoints, daily trends, country stats

### 🔗 Firestore Sync
- User meta → `wp_users` collection
- WooCommerce products → `wc_products`
- WooCommerce orders → `wc_orders`

### 📝 Shortcodes
```
[firebase_login redirect_url="/dashboard" show_social="true"]
[firebase_register default_role="subscriber"]
[firebase_social_login providers="google,apple,github" button_style="default"]
```

---

## 🚀 Quick Start

### 1. Install

**Via WordPress admin:** Upload the plugin zip and activate.

**Via WP-CLI:**
```bash
wp plugin install https://github.com/x1t9/jwt-authenticator/archive/refs/heads/main.zip --activate
```

### 2. Configure

Add to `wp-config.php`:
```php
define( 'JWT_AUTH_SECRET_KEY', 'your-strong-random-secret-key-min-32-chars' );
define( 'JWT_AUTH_CORS_ENABLE', true ); // optional
```

Generate a secure key: https://api.wordpress.org/secret-key/1.1/salt/

### 3. Get a Token

```bash
curl -X POST https://your-site.com/wp-json/jwt-auth/v1/token \
  -H "Content-Type: application/json" \
  -d '{"username": "admin", "password": "your-password"}'
```

**Response:**
```json
{
  "token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9...",
  "refresh_token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9...",
  "expires_in": 3600,
  "token_type": "Bearer",
  "user_email": "admin@example.com",
  "user_display_name": "Admin"
}
```

### 4. Use the Token

```bash
curl https://your-site.com/wp-json/wp/v2/posts \
  -H "Authorization: Bearer YOUR_TOKEN_HERE"
```

---

## 📡 REST API Endpoints

### JWT Token
| Method | Endpoint | Auth | Description |
|--------|----------|------|-------------|
| `POST` | `/jwt-auth/v1/token` | None | Generate token pair |
| `POST` | `/jwt-auth/v1/token/validate` | Bearer | Validate token |
| `POST` | `/jwt-auth/v1/token/refresh` | None (refresh_token body) | Refresh access token |
| `POST` | `/jwt-auth/v1/token/revoke` | Bearer | Revoke token |
| `GET`  | `/jwt-auth/v1/tokens` | Bearer | List user's tokens |
| `DELETE` | `/jwt-auth/v1/tokens/{jti}` | Bearer | Revoke specific token |

### API Keys
| Method | Endpoint | Auth | Description |
|--------|----------|------|-------------|
| `POST` | `/jwt-auth/v1/api-keys` | Bearer | Create user API key |
| `GET`  | `/jwt-auth/v1/api-keys` | Bearer | List user's keys |
| `DELETE` | `/jwt-auth/v1/api-keys/{id}` | Bearer | Delete key |
| `POST` | `/jwt-auth/v1/api-keys/admin/universal` | Admin Bearer | Create universal key |

### OAuth 2.0
| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/jwt-auth/v1/oauth/token` | password / refresh_token / client_credentials |
| `POST` | `/jwt-auth/v1/oauth/revoke` | Revoke OAuth token |

### Firebase
| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/jwt-auth/v1/auth/firebase` | Exchange Firebase ID token for WP JWT |
| `POST` | `/jwt-auth/v1/auth/firebase/session` | Create WP cookie session |
| `GET`  | `/jwt-auth/v1/auth/firebase/config` | Public Firebase config for SDK init |
| `POST` | `/jwt-auth/v1/auth/third-party` | Third-party JWT auth |

---

## 🔧 Configuration

All options are available in the **WordPress admin → JWT Authenticator** dashboard.

| Option | Default | Description |
|--------|---------|-------------|
| `jwt_auth_access_token_expiry` | `3600` | Access token lifetime (seconds) |
| `jwt_auth_refresh_token_expiry` | `2592000` | Refresh token lifetime (seconds) |
| `jwt_auth_protection_mode` | `disabled` | `disabled` / `selective` / `full` |
| `jwt_auth_rate_limit_enabled` | `false` | Enable rate limiting |
| `jwt_auth_firebase_enabled` | `false` | Enable Firebase integration |
| `jwt_auth_firebase_project_id` | `''` | Firebase project ID |
| `jwt_auth_firebase_web_api_key` | `''` | Firebase Web API key |

See [DOCUMENTATION.md](DOCUMENTATION.md) for the complete reference.

---

## 🪝 Hooks & Filters

```php
// Modify token expiry
add_filter( 'jwt_auth_expire', fn( $exp, $iat ) => $iat + DAY_IN_SECONDS, 10, 2 );

// Add custom data to JWT payload
add_filter( 'jwt_auth_token_before_sign', function( $token, $user ) {
    $token['data']['user']['roles'] = $user->roles;
    return $token;
}, 10, 2 );

// Use RS256 instead of HS256
add_filter( 'jwt_auth_algorithm', fn() => 'RS256' );

// Assign role based on Firebase provider
add_filter( 'jwt_auth_firebase_default_role', function( $role, $payload ) {
    return $payload['firebase']['sign_in_provider'] === 'google.com' ? 'editor' : $role;
}, 10, 2 );

// Hook into new Firebase user creation
add_action( 'jwt_auth_firebase_user_created', function( $user_id, $payload, $provider ) {
    // e.g. send welcome email
}, 10, 3 );
```

---

## 🔒 Security

Please report vulnerabilities privately. See [SECURITY.md](SECURITY.md).

**Best practices:**
- Use a minimum 32-character random `JWT_AUTH_SECRET_KEY`
- Always serve over HTTPS
- Enable rate limiting in production
- Keep access token expiry short (1 hour)

---

## 📄 License

[MIT](LICENSE) — free for personal and commercial use.

---

## 🤝 Contributing

Contributions are welcome! See [CONTRIBUTING.md](CONTRIBUTING.md).
