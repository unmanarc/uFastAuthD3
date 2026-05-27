# uFastAuthD3 (Unmanarc Fast Authentication Daemon 3)

**Author:** Aaron Mizrachi (unmanarc) <dev@unmanarc.com>
**License:** [SSPL-1.0](https://spdx.org/licenses/SSPL-1.0.html) (Dual Licensing Available)
**Version:** 3.0.0

---

A lightweight **Identity and Access Management (IAM)** system designed for secure, stateless authentication in resource-constrained environments. Built in **C++20**, uFastAuthD3 provides fast and reliable authentication services for web applications, microservices, and IoT devices, even on platforms like the **Raspberry Pi**.

---

## 📖 Table of Contents

- [✨ Overview](#-overview)
- [🚀 Key Features](#-key-features)
- [🏗️ Architecture & Components](#️-architecture--components)
- [⚙️ System Requirements](#️-system-requirements)
- [🔧 Installation & Build](#-installation--build)
- [📁 Configuration](#-configuration)
- [🌐 Web Portals](#-web-portals)
- [🔐 Security](#-security)
- [🏃 Running the Service](#-running-the-service)
- [📄 License](#-license)
- [👤 Author](#-author)
- [🔗 Links](#-links)

---

## ✨ Overview

uFastAuthD3 is a full-featured IAM daemon that handles user identity, authentication, authorization, and session management through a modular architecture. It uses **SQLite3** as its local database backend and **JWT (JSON Web Tokens)** for secure, stateless token-based authentication.

The system is composed of multiple web services, each running on a dedicated port, providing:

- **Single Sign-On (SSO)** across multiple applications
- **Role-Based Access Control (RBAC)** with configurable scopes
- **Self-service user portals** for account management
- **Administrator portals** for full system control
- **Direct application integration** via HTTP API

The architecture is designed to minimize token consumption while preserving full functionality and security, allowing easy integration with any client-side application via proxy or direct API calls.

---

## 🚀 Key Features

- **🔑 JWT Authentication** — Stateless JSON Web Tokens for secure, token-based authentication with short-lived access tokens and refresh tokens
- **🧩 Microservices Architecture** — Modular design with independent web services for seamless integration with distributed systems
- **💾 Local SQLite3 Database** — Thread-safe database access using read-write mutexes, reducing external dependencies
- **🔒 Secure Authentication** — Passwords are hashed and sessions are encrypted using SSL/TLS
- **📱 Two-Factor Authentication (2FA)** — Optional 2FA via TOTP for heightened security
- **🏢 Multi-Application Support** — Manage multiple applications, user roles, and scopes within a single instance
- **🎯 Role-Based Access Control** — Fine-grained permissions using scopes and roles per application
- **📉 Ultra-Low Footprint** — Optimized for minimal resource usage (RAM, CPU, storage)
- **🖥️ Cross-Platform** — Works on Linux (Ubuntu, CentOS, Fedora, Raspbian)
- **🔌 Proxy-Based Integration** — Inject tokens as cookies into your applications with no additional coding required

---

## 🏗️ Architecture & Components

### 📁 IdentityManager

The core identity management module responsible for:

- SQLite3 database management and schema handling
- Thread-safe database access using read-write mutexes
- Account, application, credential, and session management
- Authentication scheme configuration
- Security event logging

**Key modules:**
- `identitymanager_db.cpp` — Database operations
- `identitymanager_accounts.cpp` — Account CRUD operations
- `identitymanager_authentication.cpp` — Authentication workflows
- `credentialvalidator.cpp` — Credential validation logic
- `domains.cpp` — Domain management

### 🌐 Web Services

Each web service runs on a dedicated port and handles a specific aspect of the IAM system:

#### 🧑‍💼 AdminPortal
Administrative web interface for managing:
- User accounts and credentials
- Applications, roles, and scopes
- Authentication schemes and slots
- System settings

#### 🔐 LoginPortal
Unified login portal providing:
- Single Sign-On (SSO) for all registered applications
- Access token and refresh token generation
- Token injection into target applications
- User registration and authorization flows

#### 👤 UserPortal
Self-service portal allowing users to:
- View and update personal account information
- Manage credentials and security settings
- View associated applications
- Dashboard with account overview

#### 🔄 AppSync
Direct HTTP API for application integration:
- Update access control attributes
- Receive and validate authentication tokens
- Retrieve account lists associated with the application
- Synchronize application state

#### 🛡️ SessionAuthHandler
Proxy-based service for session management:
- Token refresh via cookies
- Logout and cookie cleanup
- Generic callback for token injection into applications
- No additional coding required on the application side

#### 🎫 Tokens Manager
JWT token lifecycle management:
- Access token generation and validation
- Refresh token handling
- Token expiration and revocation

---

## ⚙️ System Requirements

### Operating System
- systemd-enabled Linux distribution (Ubuntu, CentOS, Fedora, Debian, etc.)

### Compiler
- GCC or Clang with **C++20** support

### Build Dependencies
- **CMake** >= 3.12
- **libMantids30** (development and SQLite packages)
- **SQLite3** (development headers)
- **OpenSSL** (development headers)
- **jsoncpp** (development headers)
- **Boost** (regex, thread components)
- **pthread**
- **zlib** (development headers)

### Runtime Dependencies
- systemd (service management)
- libMantids30 runtime libraries
- OpenSSL runtime libraries

---

## 🔧 Installation & Build

### Step 1: Install Prerequisites

**Debian/Ubuntu:**
```bash
sudo apt-get install build-essential cmake libsqlite3-dev libssl-dev libjsoncpp-dev libboost-dev libboost-regex-dev libboost-thread-dev zlib1g-dev pkg-config
```

**Red Hat/CentOS/Fedora:**
```bash
sudo yum install gcc-c++ cmake sqlite-devel openssl-devel jsoncpp-devel boost-devel zlib-devel pkg-config
```

### Step 2: Clone and Build

```bash
cd /root
git clone https://github.com/unmanarc/uFastAuthD3
cmake -B../builds/uFastAuthD3 ./uFastAuthD3 -DCMAKE_VERBOSE_MAKEFILE=ON
cd ../builds/uFastAuthD3
make -j12 install
```

### Step 3: Install Configuration Files

```bash
cp -a ~/uFastAuthD3/etc/ufastauthd3 /etc/
chmod 600 /etc/ufastauthd3/snakeoil.key
mkdir -p /var/www
mkdir -p /var/lib/ufastauthd3
rm -rf /var/www/ufastauthd3
cp -a ~/uFastAuthD3/var/www/ufastauthd3 /var/www
```

> **⚠️ Security Alert:** Replace the default snakeoil X.509 certificates with your own production certificates. Failure to do so may allow communication to be eavesdropped or tampered with.

### Step 4: Initialize the systemd Service

```bash
cat << 'EOF' | install -m 640 /dev/stdin /usr/lib/systemd/system/ufastauthd3.service
[Unit]
Description=Unmanarc Fast Authentication Daemon 3
After=network.target

[Service]
Type=simple
Restart=always
RestartSec=1
EnvironmentFile=/etc/default/ufastauthd3
ExecStart=/usr/local/bin/uFastAuthD3

[Install]
WantedBy=multi-user.target
EOF

cat << 'EOF' | install -m 640 /dev/stdin /etc/default/ufastauthd3
LD_LIBRARY_PATH=/usr/local/lib:
EOF

systemctl daemon-reload
systemctl enable --now ufastauthd3.service
```

---

## 📁 Configuration

The main configuration file is located at `/etc/ufastauthd3/ufastauthd3.conf` and uses a modular include-based structure.

### Main Configuration (`ufastauthd3.conf`)

```ini
; Logging Configuration
Logs {
    Debug "true"
    ShowDate "true"
    ShowColors "true"
}

; Authentication Backend
Auth {
    Driver "SQLite3"
    IAMMainFile "var/lib/ufastauthd3/main.db"
    IAMLogsFile "var/log/ufastauthd3/logs.db"
    TerminateOnSQLError "true"
}

; Include Web Server Configurations
#include "etc/ufastauthd3/web_appsync.conf"
#include "etc/ufastauthd3/web_authhandler.conf"
#include "etc/ufastauthd3/web_portal_login.conf"
#include "etc/ufastauthd3/web_portal_admin.conf"
#include "etc/ufastauthd3/web_portal_user.conf"
```

### Configuration Sections

| Section | Description |
|---------|-------------|
| `Logs` | Controls logging behavior (debug mode, date display, colors) |
| `Auth` | Database driver, main database path, log database path, error handling |
| `Web Portals` | Individual configuration files for each web service (ports, TLS, paths) |

### TLS Certificates

Certificate files are stored in `/etc/ufastauthd3/tls/`:
- `ca.crt` — Certificate Authority certificate
- `snakeoil.crt` — Default server certificate (replace in production)
- `snakeoil.key` — Default server private key (restrict permissions to 0600)

### Command-Line Options

| Flag | Option | Description | Default |
|------|--------|-------------|---------|
| `-c` | `config-dir` | Configuration directory path | `/etc/ufastauthd3` |
| `-r` | `resetadmpw` | Reset administrator password on next start | `false` |

---

## 🌐 Web Portals

The web interface is served from `/var/www/ufastauthd3` and includes the following portals:

### Admin Portal (`/portals/admin`)
Full system administration interface with pages for:
- Account management and field configuration
- Application management
- Authentication schemes and slots
- System settings
- Resource activity monitoring

### Login Portal (`/portals/login`)
Unified authentication entry point for all registered applications, supporting:
- Username/password authentication
- Token-based authorization
- Single Sign-On (SSO) flow

### User Portal (`/portals/user`)
Self-service user interface with:
- Dashboard overview
- Profile management
- Credential management
- Associated applications view

### Shared Resources
- **`/global/`** — Shared assets (CSS, JS, images) for all portals
- **`/authhandler/`** — Assets for token refresh and session management
- **`/appsync/`** — AppSync API frontend resources

---

## 🔐 Security

### SSL/TLS Encryption
All web communications are encrypted using SSL/TLS. Production deployments MUST replace the default snakeoil certificates with valid certificates from a trusted Certificate Authority.

### File Permissions
Configuration files containing sensitive data are automatically secured:
- `ufastauthd3.conf` permissions are enforced to `0600`
- Private key files must be restricted to `0600`

### Password Security
- Upon first initialization, a super-user password is generated and stored in a temporary file (e.g., `/tmp/syspwd-98ZAisMO`)
- **Login immediately** and change the default admin password
- Passwords are hashed before storage in the database

### Token Security
- Short-lived access tokens minimize exposure window
- Refresh tokens enable seamless session continuation
- JWT cookies are used for secure client-side authentication

---

## 🏃 Running the Service

### Start the Service
```bash
systemctl start ufastauthd3.service
```

### Stop the Service
```bash
systemctl stop ufastauthd3.service
```

### Check Service Status
```bash
systemctl status ufastauthd3.service
```

### View Logs
```bash
journalctl -xefu ufastauthd3
```

### Initial Admin Login
After the first startup, check the logs for the super-user password file path:
```
File '/tmp/syspwd-98ZAisMO' created with the super-user password. Login and change it immediately.
```

Access the login portal using your server's address:
```
https://<your-server-ip>:40443/login
```

Log in as `admin` with the password from the temporary file, then immediately change it through the admin portal.

---

## 📄 License

**SPDX-License-Identifier:** SSPL-1.0 OR LicenseRef-Commercial

This software is offered under a **dual-licensing model**:

1. **Server Side Public License, version 1 (SSPL v1)** — As published by MongoDB, Inc.
2. **Commercial/Proprietary License** — Granted directly by the copyright holder

You may choose and comply with either license. For commercial licensing options, contact:

**Aaron Mizrachi** <dev@unmanarc.com>

See the [LICENSE](LICENSE) file for full details.

**OpenSSL Linking Exception:** A special exception permits linking this program with the OpenSSL library under specific conditions. See the LICENSE file for details.

---

## 👤 Author

**Aaron Mizrachi (unmanarc)**
- Email: [dev@unmanarc.com](mailto:dev@unmanarc.com)

---

## 🔗 Links

- **Repository:** [github.com/unmanarc/uFastAuthD3](https://github.com/unmanarc/uFastAuthD3)
- **License:** [SSPL-1.0 on SPDX](https://spdx.org/licenses/SSPL-1.0.html)
- **SSPL Full Text:** [mongodb.com/licensing/server-side-public-license](https://www.mongodb.com/licensing/server-side-public-license)