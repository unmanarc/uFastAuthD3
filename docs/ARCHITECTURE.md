# uFastAuthD3 Architecture

## Table of Contents

- [Project Overview & Design Goals](#--project-overview--design-goals)
- [Website Structure](#-website-structure)
- [Backend Architecture](#-backend-architecture)
- [Service Configuration Reference](#-service-configuration-reference)
- [API Endpoints Reference](#-api-endpoints-reference)
- [Service Connectivity Diagrams](#-service-connectivity-diagrams)
- [Authentication & Token Flows](#-authentication--token-flows)
- [User Interaction Patterns](#-user-interaction-patterns)

---

## 🧠 Project Overview & Design Goals

uFastAuthD3 is an **Identity and Access Management (IAM)** system built in **C++20**, using **SQLite3** as the database backend, and secured via **JWT (JSON Web Tokens)** for stateless authentication.

The architecture is designed to:
- Minimize token consumption (using short-lived access tokens + refresh tokens)
- Preserve full functionality and security
- Allow easy integration with any client-side app via proxy or direct API calls
- Provide ultra-low footprint optimized for minimal resource usage (RAM, CPU, storage)

### 🎯 Design Principles

The architecture prioritizes the following principles:

1. **Minimize Token Consumption** — Short-lived access tokens paired with refresh tokens reduce exposure window
2. **Full Functionality** — All IAM features accessible without compromising security
3. **Easy Integration** — Proxy-based injection allows zero-code integration with client applications
4. **Modular Design** — Independent web services enable seamless integration with distributed systems
5. **Ultra-Low Footprint** — Optimized for resource-constrained environments including IoT devices and Raspberry Pi

---

## 🌐 Website Structure

The websites are hosted under `/var/www/ufastauthd3` and follows the structure below:

### 🔧 Core Components

- **`authhandler/`** — Configured via a proxy from your application, this module provides assets needed for refreshing access tokens. Contains JavaScript helpers (`auth.js`) for token injection.

- **`global/`** — Shared resources for all portals. These are fetched via npm (defined in `var/www/package.json`) and can be overlaid with portal-specific content. Includes shared CSS, JS, and configuration files.

- **`appsync/`** — AppSync API frontend resources. Provides the interface for direct application integration via HTTP API.

- **`portals/`** — Contains the following subdirectories:

  - **`admin/`** — Admin portal for managing system settings, users, applications, roles, scopes, and authentication schemes. Full system administration interface with pages for:
    - Account management and field configuration
    - Application management
    - Authentication schemes and slots
    - System settings
    - Resource activity monitoring

  - **`login/`** — Unified login portal for all applications (single sign-on). This portal authenticates the user and injects the generated token into the target application. Supports:
    - Username/password authentication
    - Token-based authorization
    - Single Sign-On (SSO) flow

  - **`user/`** — Self-service portal for users to manage their own account details, credentials, and view associated applications. Includes:
    - Dashboard overview
    - Profile management
    - Credential management
    - Associated applications view

---

## 🏗️ Backend Architecture

The backend is located in the `src` directory and is organized into two main components:

### 📁 IdentityManager

The core identity management module responsible for:

- **SQLite3 database management** and schema handling
- **Thread-safe database access** using read-write mutexes
- Account, application, credential, and session management
- Authentication scheme configuration
- Security event logging

### 📁 Web Services

Each web service runs on a dedicated port and handles a specific aspect of the IAM system. All services use TLS encryption and are configured in separate configuration files under `etc/ufastauthd3/`.

---

## 🔌 Service Configuration Reference

| Service | Config File | Port | Bind Address | Domain (example) | Base URL |
|---------|-------------|------|--------------|------------------|----------|
| **LoginPortal** | `web_portal_login.conf` | `8443` | `0.0.0.0` | `login.localhost` | `https://login.localhost:8443` |
| **AdminPortal** | `web_portal_admin.conf` | `9443` | `0.0.0.0` | `iamadmin.localhost` | `https://iamadmin.localhost:9443` |
| **UserPortal** | `web_portal_user.conf` | `11443` | `0.0.0.0` | `iamuser.localhost` | `https://iamuser.localhost:11443` |
| **AppSync** | `web_appsync.conf` | `6080` | `0.0.0.0` | `appsync.localhost` | `https://appsync.localhost:6080` |
| **SessionAuthHandler** | `web_authhandler.conf` | `7080` | `0.0.0.0` | `auth.localhost` | `https://auth.localhost:7080` |

> **Note:** The domains above are example configurations using `.localhost` suffix for development. In production, replace with actual domain names and appropriate TLS certificates.

### Internal Proxy Routes

The AdminPortal and UserPortal configure internal proxies to forward authentication-related requests to SessionAuthHandler:

| Portal | Proxy Path | Backend Service | Backend Address |
|--------|-----------|-----------------|-----------------|
| AdminPortal | `/auth` | SessionAuthHandler | `127.0.0.1:7080` |
| UserPortal | `/auth` | SessionAuthHandler | `127.0.0.1:7080` |

| Portal | Redirect Path | Destination |
|--------|--------------|-------------|
| AdminPortal | `/login` | `https://login.localhost:8443/?app=IAM_ADMPORTAL` |
| UserPortal | `/login` | `https://login.localhost:8443/?app=IAM_USRPORTAL` |

---

## 🔑 API Endpoints Reference

All API endpoints are prefixed with `/api/v1/`. The following tables list each service's endpoints with their HTTP method, path, and authentication requirement.

### 🔐 LoginPortal Endpoints

| Method | Endpoint | Description | Auth |
|--------|----------|-------------|------|
| `POST` | `/api/v1/preAuthorize` | Pre-authentication check (prepare authentication context) | None |
| `POST` | `/api/v1/authorize` | Authenticate user with credentials (username/password or other slots) | None |
| `POST` | `/api/v1/token` | Transform current authentication to application access tokens (Access + Refresh JWT) | JWT Cookie |
| `POST` | `/api/v1/logout` | Logout and clear authentication cookies | None |
| `PUT` | `/api/v1/changeCredential` | Change/update user credential | None |
| `GET` | `/api/v1/getAppDescription` | Get application description | None |


### 🔄 AppSync Endpoints

| Method | Endpoint | Description | Auth |
|--------|----------|-------------|------|
| `POST` | `/api/v1/getApplicationAccountsList` | Get list of accounts for an application | API Key |
| `POST` | `/api/v1/getApplicationJWTConfig` | Get JWT configuration for an application | API Key |
| `POST` | `/api/v1/getApplicationJWTValidationKey` | Get JWT validation key for an application | API Key |
| `POST` | `/api/v1/updateAccessControlContext` | Sync scopes, roles, activities for an application | API Key |

> **Note:** AppSync endpoints require the `x-api-key` header or `APIKEY` field in the JSON body for authentication. The application name is passed as a URL variable (`?APP=<name>`).

### 🛡️ SessionAuthHandler Endpoints

| Method | Endpoint | Description | Auth |
|--------|----------|-------------|------|
| `GET` | `/api/v1/getLogoutCallbackURL` | Get the logout callback URL | None |
| `POST` | `/api/v1/refreshAccessToken` | Refresh access token using refresh token cookie | RefreshToken Cookie |
| `POST` | `/api/v1/callback` | Generic callback for token injection into applications | None (CORS enabled for LoginPortal) |

---

## 🔗 Service Connectivity Diagrams

### High-Level Architecture

```
┌──────────────────────────────────────────────────────────────────────────┐
│                   uFastAuthD3 System Architecture                         │
└──────────────────────────────────────────────────────────────────────────┘

                    ┌──────────────────────────┐
                    │    End User / Browser     │
                    └──────────┬───────────────┘
                               │
           ┌───────────────────┼───────────────────┐
           │                   │                   │
           ▼                   ▼                   ▼
    ┌──────────────┐  ┌──────────────┐  ┌──────────────┐
    │  LoginPortal │  │ AdminPortal  │  │  UserPortal  │
    │   :8443      │  │   :9443      │  │   :11443     │
    └──────┬───────┘  └──────┬───────┘  └──────┬───────┘
           │                 │                  │
           │  Authentication │  Admin API       │  User API
           │  & Token Issue  │  Requests        │  Requests
           │                 │                  │
           ▼                 ▼                  ▼
    ┌─────────────────────────────────────────────────────┐
    │                  IdentityManager                     │
    │              (SQLite3 Database Backend)              │
    │                                                     │
    │  ┌──────────┐ ┌──────────┐ ┌────────────────────┐  │
    │  │ Accounts │ │ Apps     │ │ Authentication     │  │
    │  │ & Fields │ │ & Roles  │ │ Controller         │  │
    │  └──────────┘ └──────────┘ └────────────────────┘  │
    │  ┌──────────┐ ┌──────────┐ ┌────────────────────┐  │
    │  │ Sessions │ │ Scopes   │ │ Security Events    │  │
    │  │          │ │          │ │ Logger             │  │
    │  └──────────┘ └──────────┘ └────────────────────┘  │
    └─────────────────────────┬───────────────────────────┘
                              │
              ┌───────────────┼───────────────┐
              │               │               │
              ▼               ▼               ▼
       ┌─────────────┐ ┌─────────────┐ ┌─────────────┐
       │   AppSync   │ │SessionAuth  │ │  TokensMgr  │
       │   :6080     │ │ Handler     │ │  (internal) │
       │             │ │   :7080     │ │             │
       └─────────────┘ └─────────────┘ └─────────────┘
```

### Inter-Service Communication

```
┌──────────────────────────────────────────────────────────────────────────┐
│                    Inter-Service Communication                            │
└──────────────────────────────────────────────────────────────────────────┘

  AdminPortal (:9443)                 UserPortal (:11443)
  ┌──────────────────────┐            ┌──────────────────────┐
  │  /api/v1/*           │            │  /api/v1/*           │
  │  → IdentityManager   │            │  → IdentityManager   │
  │                      │            │                      │
  │  /auth/*             │            │  /auth/*             │
  │  → PROXY →           │            │  → PROXY →           │
  │    SessionAuthHandler│            │    SessionAuthHandler│
  │    (127.0.0.1:7080)  │            │    (127.0.0.1:7080)  │
  │                      │            │                      │
  │  /login              │            │  /login              │
  │  → REDIRECT →        │            │  → REDIRECT →        │
  │    LoginPortal       │            │    LoginPortal       │
  │    (:8443?app=ADMIN) │            │    (:8443?app=USER)  │
  └──────────────────────┘            └──────────────────────┘

  LoginPortal (:8443)                 External Applications
  ┌──────────────────────┐            ┌──────────────────────┐
  │  /api/v1/*           │            │  /auth/*             │
  │  → IdentityManager   │            │  → PROXY →           │
  │                      │            │    SessionAuthHandler│
  │  → Generates JWT     │            │    (:7080)           │
  │    (Access+Refresh)  │            │                      │
  │  → Redirects to App  │◄────SSO─── │  /login              │
  │    with tokens       │            │  → REDIRECT →        │
  └──────────────────────┘            │    LoginPortal       │
                                      │    (:8443?app=X)     │
  AppSync (:6080)                     │                      │
  ┌──────────────────────┐            │  API Sync            │
  │  POST /api/v1/*      │            │  → AppSync (:6080)   │
  │  → IdentityManager   │            │    (API Key auth)    │
  │  (API Key auth)      │            │                      │
  └──────────────────────┘            └──────────────────────┘
```

### Data Flow Between Services

```
┌──────────────────────────────────────────────────────────────────────────┐
│                         Data Flow: Authentication                         │
└──────────────────────────────────────────────────────────────────────────┘

  Step 1: User requests protected resource
  ──────────────────────────────────────────
  Browser → [External App] → /auth/refreshToken → SessionAuthHandler (:7080)

  Step 2: SessionAuthHandler validates RefreshToken
  ─────────────────────────────────────────────────
  SessionAuthHandler → IdentityManager → SQLite3 (validate token)
  IdentityManager → SessionAuthHandler (account + slot data)

  Step 3: SessionAuthHandler generates new AccessToken
  ───────────────────────────────────────────────────
  SessionAuthHandler → TokensManager → Sign JWT with app-specific key
  TokensManager → SessionAuthHandler (signed token string)

  Step 4: Response to browser
  ───────────────────────────
  SessionAuthHandler → Browser (Set-Cookie: AccessToken, JSON response)

  Step 5: Browser uses AccessToken to access app
  ──────────────────────────────────────────────
  Browser → [External App] (Cookie: AccessToken)
  [External App] → Validates JWT signature using app's validation key
```

---

## 🔐 Authentication & Token Flows

### SSO Login Flow (Sequence Diagram)

```
  User              Browser           External App       LoginPortal        IdentityManager     SessionAuthHandler
   │                  │                  │                  │                  │                      │
   │──Clicks Link───>│                  │                  │                  │                      │
   │                  │──HTTP Request──>│                  │                  │                      │
   │                  │                  │──Check Cookie──>│                  │                      │
   │                  │   (AccessToken)  │                  │                  │                      │
   │                  │                  │                  │                  │                      │
   │                  │<─No Token───────│                  │                  │                      │
   │                  │                  │                  │                  │                      │
   │                  │<─Redirect─────────────────────────────────────────────│                      │
   │                  │   https://login.localhost:8443/?app=MyApp             │                      │
   │<─Redirect────────│                  │                  │                  │                      │
   │                  │                  │                  │                  │                      │
   │──Enters─────────>│──POST /api/v1/login/credentials───────────────────>│                      │
   │  Username/Pass   │   {user,pass,app,redirectUrl}                         │                      │
   │                  │                  │                  │──Validate Creds─>│                      │
   │                  │                  │                  │                  │                      │
   │                  │                  │                  │<─Auth Result────│                      │
   │                  │                  │                  │                  │                      │
   │                  │                  │                  │──Generate Tokens>│                      │
   │                  │                  │                  │  (Access+Refresh)│                      │
   │                  │                  │                  │                  │                      │
   │                  │<─302 Redirect─────────────────────────────────────────│                      │
   │                  │   Location: app_callback?token=ACCESS_JWT             │                      │
   │<─Redirect────────│                  │                  │                  │                      │
   │                  │                  │                  │                  │                      │
   │                  │──Follow Redirect──────────────────>│                  │                      │
   │                  │   (Cookie: AccessToken set)        │                  │                      │
   │<─200 OK──────────│                  │                  │                  │                      │
   │                  │                  │                  │                  │                      │
   │──Access Granted──│──API Call────────>│                  │                  │                      │
   │                  │   (Cookie: AccessToken)            │                  │                      │
```

### Refresh Token / Access Token Flow

#### Token Types

##### Access Token
- **Type:** JWT with `"type": "access"` claim
- **Default Lifetime:** 300 seconds (5 minutes) — configurable per application
- **Storage:** HttpOnly + Secure cookie named `AccessToken`
- **Signing:** Application-specific JWT keys
- **Contents:**
  - `sub` — Account name (subject)
  - `iat` — Issued at timestamp
  - `exp` — Expiration timestamp
  - `nbf` — Not before timestamp
  - `jti` — Unique token ID (random 16-char string)
  - `parentTokenId` — Reference to the refresh token's `jti`
  - `app` — Target application name
  - `type` — `"access"`
  - `slotIds` — Set of authenticated slot IDs
  - `sessionInactivityTimeout` — Session timeout value
  - `scope[]` — Application scopes (if enabled)
  - `accountInfo` — Basic account info (if enabled)
  - `isAdmin` — `true` if user is application admin

##### Refresh Token
- **Type:** JWT with `"type": "refresher"` claim
- **Default Lifetime:** 2,592,000 seconds (30 days) — configurable per application
- **Storage:** HttpOnly + Secure cookie named `RefreshToken`
- **Signing:** Application-specific JWT keys
- **Contents:**
  - `sub` — Account name (subject)
  - `iat` — Issued at timestamp
  - `exp` — Expiration timestamp
  - `nbf` — Not before timestamp
  - `jti` — Unique token ID
  - `app` — Target application name
  - `type` — `"refresher"`
  - `slotIds` — Set of authenticated slot IDs
  - `keepAuthenticated` — Boolean flag for persistent session

#### Token Refresh Sequence

```
  Client Browser          SessionAuthHandler             IdentityManager      SQLite3 DB
      │                         │                           │                    │
      │──POST /auth/refreshAccessToken────────────────────>│                    │
      │   (Cookie: RefreshToken)│                           │                    │
      │                         │                           │                    │
      │                         │──Decode JWT (no verify)   │                    │
      │                         │  → Extract: app, type     │                    │
      │                         │                           │                    │
      │                         │──Validate type=="refresher"                     │
      │                         │                           │                    │
      │                         │──Verify JWT signature     │                    │
      │                         │  (using app's JWT validator)│                   │
      │                         │                           │──Query Key────────>│
      │                         │<─Validation Key───────────│                    │
      │                         │                           │                    │
      │                         │<─Signature Valid──────────│                    │
      │                         │                           │                    │
      │                         │──Extract claims:          │                    │
      │                         │  - refreshTokenUser (sub) │                    │
      │                         │  - slotIds                │                    │
      │                         │  - appName (app)          │                    │
      │                         │                           │                    │
      │                         │──Query Account Info──────>│                    │
      │                         │                           │──SELECT account───>│
      │                         │<─Account Data─────────────│                    │
      │                         │                           │                    │
      │                         │──Generate new AccessToken │                    │
      │                         │  (TokensManager::configureAppAccessToken)      │
      │                         │                           │                    │
      │                         │──Sign JWT with app key    │                    │
      │                         │                           │                    │
      │<─Set-Cookie: AccessToken│                           │                    │
      │<─JSON: {maxAge: N}      │                           │                    │
```

#### Token Lifecycle

```
┌─────────────────────────────────────────────────────────────────────────┐
│                         Token Lifecycle                                  │
└─────────────────────────────────────────────────────────────────────────┘

  ┌──────────┐    ┌──────────────┐    ┌──────────────┐    ┌────────────┐
  │  LOGIN   │───>│ Tokens Issued│───>│ API Requests │───>│ Token      │
  │          │    │ (Access +    │    │ (use Access  │    │ Expires    │
  │ User     │    │  Refresh)    │    │  Token)      │    │ (~5 min)   │
  │ submits  │    │              │    │              │    │            │
  │ creds    │    │ Access:      │    │ Client sends │    │            │
  │          │    │   5 min TTL  │    │   Cookie:    │    │            │
  │          │    │ Refresh:     │    │   AccessToken│    │            │
  │          │    │   30 day TTL │    │              │    │            │
  └──────────┘    └──────────────┘    └──────┬───────┘    └─────┬──────┘
                                             │                  │
                                             │           ┌──────▼───────┐
                                             │           │ Auto-Refresh │
                                             │           │ Request      │
                                             │           │ (background) │
                                             │           └──────┬───────┘
                                             │                  │
                                             │           ┌──────▼───────┐
                                             │           │ SessionAuth  │
                                             │           │ Handler      │
                                             │           │ Validates    │
                                             │           │ RefreshToken │
                                             │           └──────┬───────┘
                                             │                  │
                                             │           ┌──────▼───────┐
                                             │           │ New Access   │
                                             │           │ Token Issued │
                                             │           │ (5 min TTL)  │
                                             │           └──────┬───────┘
                                             │                  │
                                             └──────────────────┼──────────────┐
                                        ┌───────────────────────▼──────────────┤
                                        │                                     │
                                 ┌──────▼───────┐                      ┌──────▼────┐
                                 │ Continue API │                      │ Refresh   │
                                 │  Requests    │                      │ Token     │
                                 │              │                      │ Expires   │
                                 │              │                      │ (~30 days)│
                                 └──────────────┘                      └─────┬─────┘
                                                                             │
                                                                   ┌─────────▼────────┐
                                                                   │ Re-Authenticate  │
                                                                   │ (full login)     │
                                                                   └──────────────────┘
```

#### Account Expiration Handling

Both Access Token and Refresh Token respect account expiration:
- If the account expires before the token's configured timeout, the token expires at the account expiration time
- This ensures disabled/expired accounts cannot use previously issued tokens

---

## 👤 User Interaction Patterns

### 1. Admin User Flow

```
┌─────────────────────────────────────────────────────────────────────────┐
│ Admin User Journey                                                       │
└─────────────────────────────────────────────────────────────────────────┘

  Admin
   │
   ├─(1) Opens: https://iamadmin.localhost:9443
   │
   ├─(2) Not authenticated
   │     └─→ AdminPortal redirects to:
   │         https://login.localhost:8443/?app=IAM_ADMPORTAL
   │
   ├─(3) Enters username/password at LoginPortal
   │     └─→ LoginPortal validates credentials via IdentityManager
   │     └─→ LoginPortal generates Access Token + Refresh Token
   │
   ├─(4) Redirected back to AdminPortal
   │     └─→ Cookies set: AccessToken, RefreshToken
   │
   ├─(5) Admin manages system resources:
   │     ├─→ Views/edits user accounts
   │     ├─→ Configures applications, roles, scopes
   │     ├─→ Manages authentication schemes and slots
   │     └─→ Updates system settings
   │
   └─(6) Access Token expires (~5 min)
         └─→ Frontend requests to /auth/* are proxied to
             SessionAuthHandler (127.0.0.1:7080)
         └─→ New AccessToken issued automatically
         └─→ Admin continues working without interruption
```

### 2. End User (Self-Service) Flow

```
┌─────────────────────────────────────────────────────────────────────────┐
│ End User Journey                                                         │
└─────────────────────────────────────────────────────────────────────────┘

  User
   │
   ├─(1) Opens: https://iamuser.localhost:11443
   │
   ├─(2) Not authenticated
   │     └─→ UserPortal redirects to:
   │         https://login.localhost:8443/?app=IAM_USRPORTAL
   │
   ├─(3) Enters username/password at LoginPortal
   │     └─→ LoginPortal validates credentials
   │     └─→ Tokens generated and session created
   │
   ├─(4) Redirected back to UserPortal
   │     └─→ Cookies set: AccessToken, RefreshToken
   │
   ├─(5) User manages own account:
   │     ├─→ Views dashboard (login history, active sessions)
   │     ├─→ Updates profile information
   │     ├─→ Manages credentials (add/change/remove passwords, OTP)
   │     └─→ Views associated applications
   │
   └─(6) Access Token auto-refreshed via proxy
         └─→ /auth/* → SessionAuthHandler (127.0.0.1:7080)
```

### 3. External Application Integration (Proxy Method — Zero Code)

```
┌─────────────────────────────────────────────────────────────────────────┐
│ External App Integration: Proxy Method (Zero-Code)                      │
└─────────────────────────────────────────────────────────────────────────┘

  Reverse Proxy (nginx/apache) in front of External App:

  ┌─────────────────────────────────────────────────┐
  │              Reverse Proxy                       │
  │                                                  │
  │  /api/*        → External App Backend            │
  │  /auth/*       → SessionAuthHandler (:7080)      │
  │  /login        → LoginPortal (:8443?app=MyApp)   │
  │  /static/*     → Local assets + authhandler/     │
  └─────────────────────────────────────────────────┘

  User Flow:
   │
   ├─(1) User opens External App at https://myapp.example.com
   │
   ├─(2) App detects no valid AccessToken
   │     └─→ Redirects to /login → LoginPortal
   │
   ├─(3) User authenticates at LoginPortal
   │
   ├─(4) LoginPortal redirects back to app callback
   │     └─→ AccessToken + RefreshToken cookies set
   │
   ├─(5) auth.js (from /auth/assets/js/auth.js) handles:
   │     ├─→ Reads AccessToken from cookie
   │     ├─→ Attaches token to API requests
   │     ├─→ Detects token expiration
   │     ├─→ Calls /auth/refreshAccessToken automatically
   │     └─→ Retries failed request with new token
   │
   └─(6) External app backend validates AccessToken
         └─→ Uses JWT validation key obtained via AppSync
```

---

## 🏛️ Configuration Files Reference

| File | Purpose |
|------|---------|
| `etc/ufastauthd3/ufastauthd3.conf` | Main application configuration |
| `etc/ufastauthd3/web_portal_login.conf` | LoginPortal web server config (port 8443) |
| `etc/ufastauthd3/web_portal_admin.conf` | AdminPortal web server config (port 9443) |
| `etc/ufastauthd3/web_portal_user.conf` | UserPortal web server config (port 11443) |
| `etc/ufastauthd3/web_appsync.conf` | AppSync web server config (port 6080) |
| `etc/ufastauthd3/web_authhandler.conf` | SessionAuthHandler web server config (port 7080) |
| `etc/ufastauthd3/jwt/` | JWT signing/validation keys storage |
| `etc/ufastauthd3/tls/` | TLS certificates and keys |

---