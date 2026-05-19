
### 🧠 Project Overview: IAM Implementation in C++ with SQLite3 using JWT Tokens

This project is an **Identity and Access Management (IAM)** system built in **C++**, using **SQLite3** as the database backend, and secured via **JWT tokens**.

---

## 🌐 Website Structure

The website is hosted under `/var/www/ufastauthd3` and follows the structure below:

### 🔧 Core Components:

- **`authhandler`**
  Configured via a proxy from your application, this module provides assets needed for refreshing access tokens.

- **`global`**
  Shared resources for all portals. These are fetched via npm (defined in `var/www/package.json`) and can be overlaid with portal-specific content.

- **`portals/`**
  Contains the following subdirectories:

  - **`admin`** – Admin portal for managing system settings and users.
  - **`login`** – Unified login portal for all applications (single sign-on). This portal authenticates the user and injects the generated token into the target application.
  - **`user`** – Self-service portal for users to manage their own account details and credentials.

---

## 🛠️ Backend in C++

The backend is located in the `src` directory and is organized into:

### 📁 IdentityManager
- Manages the **SQLite3 database**.
- Provides thread-safe access using **read-write mutexes**.
- Contains classes and functions to handle database operations cleanly and securely.

### 📁 Web
Contains subdirectories for each backend service, each running on a dedicated port:

#### 🧑‍💼 Backend AdminPortal
Handles administration functionalities within the admin portal.

#### 🔄 Backend AppSync
Direct HTTP link between the application and the IAM. Used for:
- Updating access control attributes
- Receiving authentication tokens
- Retrieving a list of accounts associated with the app

#### 🔐 Backend LoginPortal
Responsible for user authentication through the login portal. Generates:
- Access tokens
- Refresh tokens
- Posts tokens back into the original app

#### 🔄 Backend SessionAuthHandler
This backend is accessed via a proxy from your application and allows:
- Logout (removes cookies)
- Token refresh (cookies)
- Generic callback for injecting tokens as cookies into your app — **no additional coding required** from your side

#### 👤 Backend UserPortal
Allows users to:
- Update credentials
- View personal account information

---

## ⚙️ Endpoint Configuration

Endpoints are defined in `endpoints.cpp`. Here's a sample:

```cpp
endpoints->addEndpoint(Endpoints::POST, "authorize",     SecurityOptions::NO_AUTH, {}, nullptr, &authorize);
endpoints->addEndpoint(Endpoints::POST, "token",         SecurityOptions::REQUIRE_JWT_COOKIE_AUTH, {}, nullptr, &token);
endpoints->addEndpoint(Endpoints::GET,  "doesAccountExist", SecurityOptions::REQUIRE_JWT_COOKIE_AUTH, {"ACCOUNT_READ"}, nullptr, &doesAccountExist);
```

### Key Parameters:

- **Method**: HTTP method (e.g., `POST`, `GET`, `PUT`, `DELETE`, ...)
- **Endpoint Name**: The name of the API endpoint
- **Security Options**: Determines the level of authentication required:
  - `NO_AUTH`: No authentication needed
  - `REQUIRE_JWT_COOKIE_AUTH`: Requires a valid JWT cookie
- **Required Scopes**: Access permissions needed to access the endpoint (e.g., `ACCOUNT_READ`)
- **Function Pointer**: The actual handler function that will be called when the endpoint is invoked

---

### ✅ Goal: Reduce Token Usage While Preserving Full Functionality

The architecture is designed to:
- Minimize token consumption (e.g., using short-lived access tokens + refresh tokens)
- Preserve full functionality and security
- Allow easy integration with any client-side app via proxy or direct API calls

