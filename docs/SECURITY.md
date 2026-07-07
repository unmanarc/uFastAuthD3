# Security Design Document

## Table of Contents

1. [IAM Providers (IAM Responsibility vs. Role Separation)](#iam-providers-iam-responsibility-vs-role-separation)
2. [/auth Directory (Redirect Handler)](#auth-directory-redirect-handler)
   - [Configuration and Security](#configuration-and-security)
3. [Authentication Cookies](#authentication-cookies)
4. [AppSync Service](#appsync-service)
   - [Authentication](#authentication)
   - [Endpoints](#endpoints)
     - [getApplicationAccountsList](#getapplicationaccountslist)
     - [getApplicationJWTConfig](#getapplicationjwtconfig)
     - [getApplicationJWTValidationKey](#getapplicationjwtvalidationkey)
     - [updateAccessControlContext](#updateaccesscontrolcontext)
5. [Password Management](#password-management)
    - [Storage](#storage)
    - [Backend Validation](#backend-validation)
    - [Password Change](#password-change)
    - [Password Strength Validation - Login vs. Admin Portal](#password-strength-validation---login-vs-admin-portal)
6. [Admin Account Inactivity Policy](#admin-account-inactivity-policy)

---

## IAM Providers (IAM Responsibility vs. Role Separation)

This application is designed for real-world deployment conditions rather than idealized scenarios. In practice, software development often faces the following constraints:

*   **Initial Release Focus:** The initial release prioritizes covering core use cases.
*   **Functional Priority:** Developers focus on delivering a functional product rather than implementing exhaustive, fortress-like security measures from day one.
*   **Resource Allocation:** Documentation and code reviews may be limited, particularly when budgets are heavily allocated to functional features.
*   **Maintenance Realities:** Application maintenance is often sporadic and typically occurs only when new features are being implemented, rather than for regular security patching.

Given these premises, we aim to abstract most "login and session" logic away from the main application development. We operate under the assumption that the application layer cannot be relied upon for consistent security updates and patches.

---

## `/auth` Directory (Redirect Handler)

The `/auth` directory acts as an HTTP proxy that redirects requests to our authentication service. It is responsible for managing:

*   Session scripts (e.g., refreshing access tokens).
*   Logout scripts.
*   Functional APIs for:
    - Token refresh
    - Logout operations
    - Token injection (callback from the IAM)

The configuration is located in `/etc/ufastauthd3/web_authhandler.conf` and runs on port **7080** by default.

### Configuration and Security

You must configure your application to redirect `/auth` requests to `http://127.0.0.1:7080/`.

> **Security Note:** By default, the service does not use HTTPS. **HTTPS must be enabled in production environments.**

Additionally, you must inject the following header into requests:

```http
x-api-key: <YOUR_APP_API_KEY>
```

The API Key can be configured and retrieved via the IAM admin application.

---

## Authentication Cookies

All cookies are marked as `Secure` (HTTPS only). They are configured with the following properties:

| Cookie Name | Path | HTTPOnly | SameSite | Description |
|---|---|---|---|---|
| `RefreshToken` | `/auth` | `true` | `Strict` | JWT token used to authenticate the user against the token management backend. |
| `AccessToken` | `/` | `true` | `Strict` | Short-lived JWT used to identify the current authenticated user across the entire application. |
| `SessionPublicData` | `/` | `false` | `None` | Current logged-in username. Used to manage the app-logout signal coming from the login portal and properly deauthenticate the user from the database. |
| `RefreshTokenId` | `/auth` | `true` | `None` | Current refresh token ID. Used to manage the app-logout signal coming from the login portal and properly deauthenticate the session from the database. |

---

## AppSync Service

The AppSync service is a RESTful API that allows your application to synchronize identity and access-control data with the uFastAuthD3 identity manager. It is configured in `/etc/ufastauthd3/web_appsync.conf`.

### Authentication

All AppSync endpoints require API-key-based authentication. Each request must provide:

*   `APP` (URL parameter) – The application name.
*   `APIKEY` (JSON body field) – The API key configured for the application in the IAM admin portal.

The target application must have **AppSync enabled** in its configuration; otherwise, requests are rejected with a `400 Bad Request` error.

### Endpoints

#### `getApplicationAccountsList`

Retrieves the list of accounts registered for a specified application.

*   **Method:** `POST`
*   **Requirement:** The application must have the `appSyncCanRetrieveAppAccountsList` flag enabled.
*   **Response:** JSON array of account objects.

#### `getApplicationJWTConfig`

Returns the JWT configuration settings for a specified application.

*   **Method:** `POST`
*   **Response:** JSON object containing the JWT configuration (algorithms, claims, expiration settings, etc.).

#### `getApplicationJWTValidationKey`

Returns the public validation key for verifying JWT tokens issued for a specific application.

*   **Method:** `POST`
*   **Response:** The JWT public/validation key as a JSON value.

#### `updateAccessControlContext`

Synchronizes the application's access-control definitions (scopes, roles, and activities) from the application to the identity manager. This endpoint performs a three-way sync:

1.  **Scopes** – Adds, updates, or removes application scopes based on the proposed list.
2.  **Roles** – Adds, updates, or removes application roles and manages their associated scopes.
3.  **Activities** – Adds, updates, or removes application activities (including parent-child relationships).

*   **Method:** `POST`
*   **Request Body:**
    ```json
    {
      "APIKEY": "<YOUR_APP_API_KEY>",
      "scopes": [
        { "id": "scope_name", "description": "Scope description" }
      ],
      "roles": [
        {
          "id": "role_name",
          "description": "Role description",
          "scopes": ["scope_name"]
        }
      ],
      "activities": [
        {
          "id": "activity_name",
          "description": "Activity description",
          "parentActivity": "parent_name"
        }
      ]
    }
    ```

---

## Password Management

### Storage

*   Passwords can be stored in multiple formats (e.g., SSHA, SHA, PLAIN).
*   **SSHA is recommended** as it provides the best protection against rainbow table attacks.
*   PLAIN is not usually used unless you explicitly configure that way.

### Backend Validation

*   The backend can utilize a CRAM-like mechanism to validate passwords.
*   This approach ensures that the raw password never needs to be transmitted to our server, enhancing security during the authentication process.

### Password Change

#### Design Philosophy

All password change enforcement—including strength validation, old-password confirmation, and format requirements—is implemented **exclusively on the frontend (UI/GUI layer)**. The backend does not perform these validations.

This design is intentional and stems from the following architectural principle:

**The raw password never leaves the user's browser.** Only the computed hash is transmitted to the server. Since the backend never receives the plaintext password, it cannot validate its strength, enforce complexity rules, or confirm the old password—only the client-side code can perform these checks because only the client has access to the actual password.

#### Security Rationale

This approach provides the following security benefits:

1.  **No Plaintext Password Handling on the Server:** The server never receives, processes, or stores the password in plaintext. This eliminates a significant attack surface: even if the server is compromised, attackers cannot intercept passwords in transit to the backend.
2.  **Reduced Data Exposure Risk:** Since the password is never transmitted over the network (only its hash), there is no risk of the raw password being captured in server logs, memory dumps, or network monitoring tools on the server side.
3.  **Client-Side Hash Computation:** The hash is computed entirely in the browser using client-side JavaScript, ensuring the password text exists only temporarily in the user's browser memory.

#### Risk Acceptance

By design, this architecture introduces a deliberate security trade-off that is documented and accepted:

| Risk | Description | Acceptance Rationale |
|---|---|---|
| Bypass of Strength Validation | A technically-savvy user can bypass the frontend validation and directly submit a hash to the backend API, potentially setting an insecure password (e.g., a hash for "123" or "password"). | The affected party is the user themselves. No other accounts or system integrity is compromised. |
| Direct Hash Manipulation | A user can manually compute and submit any hash value, including reusing an old hash or using a weak one. | The backend accepts the hash as a valid credential update. The user assumes full responsibility for the security of their own account. |
| Consistency Bypass | A user may submit a hash that does not match the password they believe they set, or skip the old-password confirmation step. | The system operates on a trust model where the client is the authority for password operations. |

**Risk Acceptance Statement:**

> The uFastAuthD3 design accepts the risk that a user may intentionally or unintentionally set a weak password by bypassing the GUI validation layer. The impact is contained to the individual user account performing the action. This risk is considered acceptable because:
>
> 1. **The affected party is solely the user who performed the action.** No other users, accounts, or system components are impacted.
> 2. **The alternative (server-side plaintext password handling) poses a greater risk.** Transmitting and processing plaintext passwords on the server introduces risks of mass exposure: server compromises, log leaks, insider threats, and network interception can expose credentials for *all* users, not just one.
> 3. **The responsibility model is clear.** The user who chooses to bypass the security controls assumes full responsibility for the consequences. The system provides the tools for secure password management through the GUI; opting out of those tools is a conscious (or unconscious) decision by the user.
> 4. **It is a contained sacrifice.** The security sacrifice (allowing a user to weaken their own account) is outweighed by the security gain (eliminating plaintext password handling server-wide).

#### Mitigation Guidance

Administrators and users are encouraged to:

*   Always use the provided GUI interfaces for password changes, which enforce strength validation and old-password confirmation.
*   Be aware that direct API manipulation of password hashes is possible but unsupported and carries self-inflicted risk.
*   Monitor for unusually weak password patterns if audit capabilities are enabled, as an indicator of potential misuse.

### Password Strength Validation - Login vs. Admin Portal

Password strength validation rules may include checks that reference the user's login/username (e.g., preventing the password from containing the username). However, the scope of this validation differs between the Login Portal and the Admin (User) Portal due to information disclosure considerations.

#### Single Login Field Recommendation

It is recommended to configure applications with a **single login field** rather than allowing multiple login identifiers (e.g., username, email, phone number). Using a single login field simplifies the password strength validation logic and reduces the complexity of information disclosure risks during the authentication flow.

#### Password Never Travels in Plaintext

The reason password strength validation is enforced exclusively on the client side is that **the password never travels in plaintext to the server**. The password hash is computed entirely within the browser using client-side JavaScript, and only the resulting hash is transmitted to the backend for authentication or storage.

This architectural decision has two important implications:

1. **The backend cannot validate password strength** because it never receives the plaintext password—only its hash. Therefore, all complexity checks, pattern validations, and personal-data comparisons must be performed client-side before hashing.
2. **The validation scope is inherently limited by the authentication phase.** During the Login Portal flow (pre-full-authentication), only the login field value is available for validation. During the User Portal flow (post-full-authentication), the complete set of account data is available, allowing for more comprehensive validation rules.

#### Login Portal

In the Login Portal (the initial authentication flow where a user changes a password before fully completing login), the password strength validation **only checks that the new password does not contain the user's recently introduced login/username**.

**Rationale:** At this stage, the user has already entered their login credentials but is not yet fully authenticated. Validating the password against a broader set of account data (such as email addresses, full names, or other personal information) could inadvertently disclose sensitive account information to an attacker.

By limiting the validation to only the username that the user already provided, the system minimizes the risk of information leakage during the pre-authentication phase.

#### User Portal

In the User Portal (where a fully authenticated user manages their credentials), the password strength validation **checks the new password against the complete set of login names associated with the account**, which may include the username, email address, full name, and other account data fields.

**Rationale:** By the time a user accesses the User Portal to change their password, they have already successfully completed the full authentication sequence (providing all required credentials). At this point, the user is fully authenticated and has legitimate access to view their own account data. Therefore, there is no risk of information disclosure through the validation rules, as the user already has permission to see all their account details. The system can safely enforce all configured password strength rules without concern for leaking sensitive information.

---

## Admin Account Inactivity Policy

Admin accounts are **exempt from inactivity-based deactivation**. Unlike regular user accounts, admin accounts will never be automatically disabled or flagged as inactive due to prolonged periods of non-use.

### Rationale

This policy is based on the following considerations:

1.  **Low Usage Frequency:** Admin accounts are inherently used less frequently than regular user accounts. Administrative tasks are typically performed on an as-needed basis, which can result in long periods between logins.
2.  **High Sensitivity:** Admin accounts have elevated privileges and provide access to critical system functions. If an admin account were to be deactivated due to inactivity, it could create a higher-risk scenario than the inactivity itself—for example, preventing administrators from logging in and performing urgent maintenance, responding to security incidents, or managing system configuration.
3.  **Operational Continuity:** Ensuring that admin accounts remain accessible at all times is critical for operational continuity. An unexpectedly locked admin account could delay critical interventions and exacerbate system issues.

### Admin Responsibility

While admin accounts are protected from automatic deactivation, this exemption places additional responsibility on administrators:

*   **Regular Access Verification:** Administrators should periodically verify that their admin credentials remain functional and accessible.
*   **Secure Credential Management:** Admin credentials must be stored securely and protected from unauthorized access, even during periods of non-use.
*   **Prompt Response to Security Events:** Administrators remain responsible for monitoring and responding to security events related to their admin accounts, regardless of usage frequency.
*   **Awareness of Access Status:** Administrators should be aware of the current status of their admin accounts and take immediate action if any suspicious activity is detected.

> **Note:** The system provides the infrastructure to keep admin accounts accessible; the administrator is responsible for maintaining proper care and security awareness regarding their admin accounts.