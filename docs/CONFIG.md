# uFastAuthD3 Configuration Guide

## 📖 Table of Contents

- [Overview](#overview)
- [Configuration File Structure](#configuration-file-structure)
- [Main Configuration File](#main-configuration-file)
  - [Logs Section](#logs-section)
  - [Auth Section](#auth-section)
- [Web Service Configuration Files](#web-service-configuration-files)
  - [Common Configuration Sections](#common-configuration-sections)
    - [General Settings](#general-settings)
    - [TLS Configuration](#tls-configuration)
    - [Thread Pool Configuration](#thread-pool-configuration)
    - [Logs Configuration](#logs-configuration)
  - [AppSync Service](#appsync-service-port-7081https)
  - [Session Auth Handler](#session-auth-handler-port-7080)
  - [Login Portal](#login-portal-port-8443)
  - [Admin Portal](#admin-portal-port-9443)
  - [User Portal](#user-portal-port-11443)
- [TLS Certificates](#tls-certificates)
- [Command-Line Options](#command-line-options)
- [Configuration Best Practices](#configuration-best-practices)
- [Troubleshooting](#troubleshooting)

---

## Overview

uFastAuthD3 uses a modular configuration system based on include directives. The main configuration file located at `/etc/ufastauthd3/ufastauthd3.conf` serves as the entry point, importing individual configuration files for each web service.

This modular approach allows:
- Easy maintenance and updates
- Independent configuration of each service
- Clear separation of concerns
- Flexible deployment scenarios

---

## Configuration File Structure

The complete configuration consists of the following files:

| File | Description |
|------|-------------|
| `etc/ufastauthd3/ufastauthd3.conf` | Main configuration (logs, auth backend, includes) |
| `etc/ufastauthd3/web_appsync.conf` | AppSync API service configuration |
| `etc/ufastauthd3/web_authhandler.conf` | Session Auth Handler service configuration |
| `etc/ufastauthd3/web_portal_login.conf` | Login Portal configuration |
| `etc/ufastauthd3/web_portal_admin.conf` | Admin Portal configuration |
| `etc/ufastauthd3/web_portal_user.conf` | User Portal configuration |

### Directory Layout

```
/etc/ufastauthd3/
├── ufastauthd3.conf          # Main configuration
├── web_appsync.conf          # AppSync service
├── web_authhandler.conf      # Auth Handler service
├── web_portal_login.conf     # Login Portal
├── web_portal_admin.conf     # Admin Portal
├── web_portal_user.conf      # User Portal
├── tls/
│   ├── ca.crt                # Certificate Authority
│   ├── snakeoil.crt          # Default server certificate
│   └── snakeoil.key          # Default server private key
└── jwt/
    └── hmac_secret.key       # JWT HMAC secret key
```

---

## Main Configuration File

The main configuration file (`ufastauthd3.conf`) defines global settings and includes the web service configurations.

### Example Main Configuration

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
    IAMMainFile "/var/lib/ufastauthd3/main.db"
    IAMLogsFile "/var/log/ufastauthd3/logs.db"
    TerminateOnSQLError "true"
}

; Include Web Server Configurations
#include "etc/ufastauthd3/web_appsync.conf"
#include "etc/ufastauthd3/web_authhandler.conf"
#include "etc/ufastauthd3/web_portal_login.conf"
#include "etc/ufastauthd3/web_portal_admin.conf"
#include "etc/ufastauthd3/web_portal_user.conf"
```

### Logs Section

Controls the global logging behavior of the daemon.

| Parameter | Description | Default | Values |
|-----------|-------------|---------|--------|
| `Debug` | Enable debug-level logging | `"false"` | `"true"`, `"false"` |
| `ShowDate` | Prefix log messages with timestamp | `"true"` | `"true"`, `"false"` |
| `ShowColors` | Enable colored output in terminal | `"true"` | `"true"`, `"false"` |

### Auth Section

Configures the identity management backend database connection.

| Parameter | Description | Default | Example |
|-----------|-------------|---------|---------|
| `Driver` | Database driver to use | `"SQLite3"` | `"SQLite3"` |
| `IAMMainFile` | Path to the main IAM database | `/var/lib/ufastauthd3/main.db` | Relative or absolute path |
| `IAMLogsFile` | Path to the security events/logs database | `/var/log/ufastauthd3/logs.db` | Relative or absolute path |
| `TerminateOnSQLError` | Stop the daemon on critical database errors | `"true"` | `"true"`, `"false"` |

**Note:** All database paths are relative to the installation prefix unless specified as absolute paths.

---

## Web Service Configuration Files

Each web service has its own configuration file with a dedicated section block. All services share common configuration patterns.

### Listener-Based Architecture

Web services use a **listener-based configuration model**, where network listening parameters (port, address, protocol, TLS) are encapsulated in named `Listener` blocks. This architecture provides the following benefits:

- **Multi-listener support** — A single service can listen on multiple interfaces/protocols simultaneously (e.g., one TLS listener on `0.0.0.0:8443` and one plain listener on `127.0.0.1:8080`)
- **Per-listener isolation** — Each listener can have its own TLS certificate, protocol, and bind address
- **Cleaner configuration** — Network settings are grouped logically rather than scattered across the service block

### Common Configuration Sections

The following sections are available across all web service configurations.

#### Listener Block

Each service defines one or more listener blocks. A listener encapsulates all network-facing configuration:

```ini
ServiceName {
    Listener_TLS {
        ListenPort 8443
        ListenAddr "0.0.0.0"
        UseIPv6 false
        Protocol TLS
        TLS {
            CertFile "etc/ufastauthd3/tls/snakeoil.crt"
            KeyFile  "etc/ufastauthd3/tls/snakeoil.key"
        }
    }
}
```

| Parameter | Description | Example Values |
|-----------|-------------|----------------|
| `Listener_<name>` | Named listener block (e.g., `Listener_TLS`, `Listener_PLAIN`) | Any descriptive name |
| `ListenPort` | Port number this listener binds to | `8443`, `9443`, `7080` |
| `ListenAddr` | Bind address for this listener | `"0.0.0.0"` (all interfaces), `"127.0.0.1"` (localhost) |
| `UseIPv6` | Enable IPv6 for this listener | `true`, `false` |
| `Protocol` | Protocol used by this listener | `TLS`, `HTTP` |
| `TLS { }` | TLS certificate configuration for this listener | See TLS Configuration below |

##### Multiple Listeners Example

A service can define multiple listeners to serve on different endpoints:

```ini
ServiceName {
    Listener_TLS {
        ListenPort 8443
        ListenAddr "0.0.0.0"
        Protocol TLS
        TLS {
            CertFile "etc/ufastauthd3/tls/server.crt"
            KeyFile  "etc/ufastauthd3/tls/server.key"
        }
    }

    Listener_PLAIN {
        ListenPort 8080
        ListenAddr "127.0.0.1"
        Protocol HTTP
    }
}
```

#### TLS Configuration (inside Listener Block)

TLS settings are defined inside each listener block that uses the `TLS` protocol:

```ini
TLS {
    CertFile "etc/ufastauthd3/tls/snakeoil.crt"
    KeyFile  "etc/ufastauthd3/tls/snakeoil.key"
}
```

| Parameter | Description | Example |
|-----------|-------------|---------|
| `CertFile` | Path to the public certificate (PEM format) | `"etc/ufastauthd3/tls/snakeoil.crt"` |
| `KeyFile` | Path to the private key (PEM format) | `"etc/ufastauthd3/tls/snakeoil.key"` |

**Security Note:** The private key file should have restricted permissions (`0600`) to prevent unauthorized access.

#### Service-Level Settings

Settings that apply to the service as a whole (outside of listener blocks):

| Parameter | Description | Example |
|-----------|-------------|---------|
| `ResourcesPath` | Path to static web resources | `"/var/www/ufastauthd3/portals/login"` |

#### Thread Pool Configuration

Controls concurrency and threading behavior. Defined at the service level (outside listener blocks).

```ini
Threads {
    UseThreadPool false
    MaxConcurrentClients 500
    Debug {
        Enabled false
        Dir "/tmp"
    }
}
```

| Parameter | Description | Default | Values |
|-----------|-------------|---------|--------|
| `UseThreadPool` | Use thread pool instead of per-client threading | `false` | `true`, `false` |
| `ThreadsCount` | Number of threads in the pool | `20` | Integer (when `UseThreadPool true`) |
| `TaskQueues` | Number of task queues | `36` | Integer |
| `QueuesKeyRatio` | Queue distribution ratio | `0.5` | Float 0.0-1.0 |
| `MaxConcurrentClients` | Maximum concurrent connections | `500` | Integer (when `UseThreadPool false`) |
| `Debug.Enabled` | Enable thread debug output | `false` | `true`, `false` |
| `Debug.Dir` | Directory for debug files | `"/tmp"` | Path |

#### Logs Configuration

Configures per-service file logging with rotation support. Defined at the service level (outside listener blocks).

```ini
Logs {
    Dir "/var/log/ufastauthd3"
    CreateDir "true"
    File "web_loginportal.log"
    MaxFileSize "10mb"
    MaxBackups 5
    RotateOnStartup "true"
    RotateOnSize "true"
    LogFormat "combined"
    RotateOnSchedule "false"
    RotateSchedule {
        Minute "*"
        Hour "2"
        DayOfWeek "*"
        DayOfMonth "*"
        Month "*"
    }
    QueueMaxItems 10000
    QueueMaxInsertWaitTimeInMS 100
    UseThreadedQueue "true"
}
```

| Parameter | Description | Default | Values |
|-----------|-------------|---------|--------|
| `Dir` | Log file directory | `"/var/log/ufastauthd3"` | Path |
| `CreateDir` | Auto-create log directory | `"true"` | `"true"`, `"false"` |
| `File` | Log filename | Service-specific | String |
| `MaxFileSize` | Max log size before rotation | `"10mb"` | Size (e.g., "1Kb", "10Mb", "1Gb") |
| `MaxBackups` | Number of backup log files to keep | `5` | Integer |
| `RotateOnStartup` | Rotate logs on service start | `"true"` | `"true"`, `"false"` |
| `RotateOnSize` | Enable size-based rotation | `"true"` | `"true"`, `"false"` |
| `LogFormat` | Log output format | `"combined"` | `"json"`, `"combined"` |
| `RotateOnSchedule` | Enable scheduled rotation | `"false"` | `"true"`, `"false"` |
| `QueueMaxItems` | Max items in log queue | `10000` | Integer |
| `QueueMaxInsertWaitTimeInMS` | Queue insert timeout | `100` | Milliseconds |
| `UseThreadedQueue` | Use threaded log queue | `"true"` | `"true"`, `"false"` |

##### Scheduled Log Rotation

When `RotateOnSchedule "true"`, the `RotateSchedule` block defines rotation times:

| Parameter | Description | Example |
|-----------|-------------|---------|
| `Minute` | Minute of rotation | `"0"`, `"*"` (every) |
| `Hour` | Hour of rotation | `"2"` (2 AM) |
| `DayOfWeek` | Day of week | `"1"` (Monday), `"*"` (every day) |
| `DayOfMonth` | Day of month | `"1"`, `"*"` (every day) |
| `Month` | Month | `"1"` (January), `"*"` (every month) |

Example - Rotate every day at 2:00 AM:
```ini
RotateSchedule {
    Minute "0"
    Hour "2"
    DayOfWeek "*"
    DayOfMonth "*"
    Month "*"
}
```

---

### AppSync Service (Port 7081/7081s)

**Configuration File:** `web_appsync.conf`  
**Section Name:** `AppSyncWebService`

The AppSync service provides the HTTP API for application integration with uFastAuthD3. It handles token validation, session management, and authentication operations for registered applications.

Uses a `Listener_TLS` block for TLS-encrypted API connections.

| Setting | Default Value | Notes |
|---------|---------------|-------|
| Listener `ListenPort` | `7081` | TLS port |
| Listener `ListenAddr` | `"0.0.0.0"` | All interfaces |
| Listener `Protocol` | `TLS` | TLS enabled |
| `ResourcesPath` | `"/var/www/ufastauthd3/appsync"` | Static resources |

This service is designed to be accessed internally by other services and proxy configurations.

---

### Session Auth Handler (Port 7080)

**Configuration File:** `web_authhandler.conf`  
**Section Name:** `WebSessionAuthHandlerService`

The Session Auth Handler is a shared authentication module that can be embedded in applications. It manages authentication cookies, validates JWT tokens, and provides logout functionality.

Uses a `Listener_TLS` block for TLS-encrypted connections (can be configured without TLS for reverse proxy integration).

| Setting | Default Value | Notes |
|---------|---------------|-------|
| Listener `ListenPort` | `7080` | TLS port |
| Listener `ListenAddr` | `"0.0.0.0"` | All interfaces |
| Listener `Protocol` | `TLS` | TLS enabled |
| `ResourcesPath` | `"/var/www/ufastauthd3/authhandler"` | Static resources |

#### Additional Settings

```ini
Login {
    Origins "https://login.localhost:8443"
}
```

| Parameter | Description | Example |
|-----------|-------------|---------|
| `Login.Origins` | Allowed login portal origins | `"https://login.localhost:8443"` |

---

### Login Portal (Port 8443)

**Configuration File:** `web_portal_login.conf`  
**Section Name:** `LoginPortal`

The Login Portal is the primary authentication interface where users log in, register, and manage their session tokens.

Uses a `Listener_TLS` block for secure HTTPS connections.

| Setting | Default Value | Notes |
|---------|---------------|-------|
| Listener `ListenPort` | `8443` | HTTPS port |
| Listener `ListenAddr` | `"0.0.0.0"` | All interfaces (public-facing) |
| Listener `Protocol` | `TLS` | TLS required for authentication |
| `ResourcesPath` | `"/var/www/ufastauthd3/portals/login"` | Portal frontend |

#### Overlapped Directories

Shared resources across portals:

```ini
OverlappedDirectories {
    /assets {
        Path "/var/www/ufastauthd3/global/assets"
    }
    /local {
        Path "/var/www/ufastauthd3/global/local"
    }
}
```

#### API Configuration

```ini
API {
    Origins "https://login.localhost:8443"
}
```

| Parameter | Description | Example |
|-----------|-------------|---------|
| `Origins` | Allowed CORS origins (comma-separated) | `"https://login.localhost:8443"` |

#### JWT Configuration

```ini
JWT {
    Algorithm "HS256"
    CreateIfNotPresent "true"
    HMACSecretFile "etc/ufastauthd3/jwt/hmac_secret.key"
    PublicKeyFile ""
    PrivateKeyFile ""
}
```

| Parameter | Description | Default | Values |
|-----------|-------------|---------|--------|
| `Algorithm` | JWT signing algorithm | `"HS256"` | `"HS256"`, `"RS256"`, etc. |
| `CreateIfNotPresent` | Auto-generate secret key if missing | `"true"` | `"true"`, `"false"` |
| `HMACSecretFile` | Path to HMAC secret key file | - | Path |
| `PublicKeyFile` | Path to public key (for asymmetric algorithms) | `""` | Path |
| `PrivateKeyFile` | Path to private key (for asymmetric algorithms) | `""` | Path |

#### Session Timeouts

```ini
AuthenticationTimeout 150
IAMTokenTimeout 2592000
```

| Parameter | Description | Default | Unit |
|-----------|-------------|---------|------|
| `AuthenticationTimeout` | Duration of the authentication intermediary token | `150` | Seconds |
| `IAMTokenTimeout` | Duration of the IAM session token (user login session) | `2592000` | Seconds (30 days) |

#### Registration Settings

```ini
Registration {
    AllowSelfRegistration false
    AutoConfirm false
}
```

| Parameter | Description | Default | Values |
|-----------|-------------|---------|--------|
| `AllowSelfRegistration` | Allow users to create their own accounts | `false` | `true`, `false` |
| `AutoConfirm` | Auto-confirm newly registered accounts | `false` | `true`, `false` |

---

### Admin Portal (Port 9443)

**Configuration File:** `web_portal_admin.conf`  
**Section Name:** `AdminPortal`

The Admin Portal provides system administrators with full control over the IAM system: user management, application configuration, security settings, and monitoring.

Uses a `Listener_TLS` block for secure HTTPS connections.

| Setting | Default Value | Notes |
|---------|---------------|-------|
| Listener `ListenPort` | `9443` | HTTPS port |
| Listener `ListenAddr` | `"0.0.0.0"` | All interfaces |
| Listener `Protocol` | `TLS` | TLS required |
| `ResourcesPath` | `"/var/www/ufastauthd3/portals/admin"` | Portal frontend |

#### HTTP Proxy Configuration

The Admin Portal proxies authentication requests to the Session Auth Handler:

```ini
Proxies {
    "/auth" {
        UseTLS true
        RemoteHost "127.0.0.1"
        RemotePort 7080
        ExtraHeaders {
            "x-api-key" "%APIKEY%"
        }
    }
}
```

| Parameter | Description | Example |
|-----------|-------------|---------|
| `UseTLS` | Use TLS for proxy connection | `true` |
| `RemoteHost` | Auth Handler host | `"127.0.0.1"` |
| `RemotePort` | Auth Handler port | `7080` |
| `ExtraHeaders` | Additional headers sent with proxy requests | `"x-api-key" "%APIKEY%"` |

##### Proxy TLS Options (Optional)

```ini
TLS {
    CheckTLSPeer true
    UsePrivateCA true
    PrivateCAPath "/path/to/ca.pem"
}
```

| Parameter | Description | Default |
|-----------|-------------|---------|
| `CheckTLSPeer` | Validate remote TLS certificate | `true` |
| `UsePrivateCA` | Use custom CA for validation | `true` |
| `PrivateCAPath` | Path to private CA certificate | - |

#### Redirections

Configures login redirection:

```ini
Redirections {
    "/login" "https://login.localhost:8443/?app=IAM_ADMPORTAL"
}
```

The Admin Portal supports two redirection formats:
1. **With base64 encoded redirectURI:**
   ```
   "/login" "https://login.localhost:8443/?app=IAM_ADMPORTAL&redirectURI=aHR0cHM6Ly9pYW1hZG1pbi5sb2NhbGhvc3Q6OTQ0My8="
   ```
2. **With Default URI:**
   ```
   "/login" "https://login.localhost:8443/?app=IAM_ADMPORTAL"
   ```

---

### User Portal (Port 11443)

**Configuration File:** `web_portal_user.conf`  
**Section Name:** `UserPortal`

The User Portal allows end users to manage their profile, credentials, application access, and session information.

Uses a `Listener_TLS` block for secure HTTPS connections.

| Setting | Default Value | Notes |
|---------|---------------|-------|
| Listener `ListenPort` | `11443` | HTTPS port |
| Listener `ListenAddr` | `"0.0.0.0"` | All interfaces |
| Listener `Protocol` | `TLS` | TLS required |
| `ResourcesPath` | `"/var/www/ufastauthd3/portals/user"` | Portal frontend |

The User Portal uses the same configuration structure as the Admin Portal (Proxies, Redirections, OverlappedDirectories) but with User Portal-specific settings:

#### Redirections

```ini
Redirections {
    "/login" "https://login.localhost:8443/?app=IAM_USRPORTAL&redirectURI="
}
```

---

## Web Services Port Summary

| Service | Configuration File | Default Port | TLS | Bind Address | Purpose |
|---------|-------------------|--------------|-----|--------------|---------|
| AppSync | `web_appsync.conf` | 7081 | Yes (optional) | 127.0.0.1 | Application API integration |
| Session Auth Handler | `web_authhandler.conf` | 7080 | No (default) | 127.0.0.1 | Cookie/JWT session management |
| Login Portal | `web_portal_login.conf` | 8443 | Yes | 0.0.0.0 | User authentication interface |
| Admin Portal | `web_portal_admin.conf` | 9443 | Yes | 0.0.0.0 | Administrator control panel |
| User Portal | `web_portal_user.conf` | 11443 | Yes | 0.0.0.0 | User self-service portal |

---

## TLS Certificates

**Certificate management:** For a comprehensive guide on X.509 certificate generation, renewal, revocation, and maintenance using Easy-RSA PKI, see **[docs/CERTIFICATES.md](CERTIFICATES.md)**.



---

## Configuration Best Practices

### Security

1. **Always enable TLS** for public-facing services (Login, Admin, User portals, AppSync, AuthHandler)
2. **Replace snakeoil certificates** see [Certificates](CERTIFICATES.md)
3. **Use asymmetric JWT algorithms** (RS256) for multi-service deployments
4. **Disable self-registration** unless explicitly required
5. **Configure firewall rules** to restrict access to admin ports

### Performance

1. **Adjust `MaxConcurrentClients`** based on expected traffic load
2. **Enable `UseThreadPool`** for high-traffic deployments
3. **Tune log rotation** settings to balance disk usage and debugging needs
4. **Use `LogFormat "json"`** for production log aggregation with SIEM tools
5. **Set appropriate token timeouts** balancing security and user experience

### Logging

1. **Enable debug logging** only during troubleshooting
2. **Configure log rotation** to prevent disk space exhaustion
3. **Use scheduled rotation** for predictable log file management
4. **Monitor log sizes** in production environments

---

## Troubleshooting

### Common Issues

| Problem | Possible Cause | Solution |
|---------|----------------|----------|
| Service fails to start | Port already in use | Change `ListenPort` or stop conflicting service |
| TLS handshake fails | Invalid certificate/key | Verify certificate and key match, check file permissions |
| JWT errors | Missing HMAC secret | Set `CreateIfNotPresent "true"` or manually create the key file |
| Login redirection loop | Incorrect `Origins` or `Redirections` | Verify URLs match your deployment DNS/hostnames |
| Database errors | Incorrect path or permissions | Verify `IAMMainFile` path exists and is writable |
| 403 Forbidden on proxy | Missing API key | Ensure `%APIKEY%` is replaced with the actual API key |

### Viewing Logs

```bash
# View systemd service logs
journalctl -xefu ufastauthd3

# View specific service logs
tail -f /var/log/ufastauthd3/web_loginportal.log
tail -f /var/log/ufastauthd3/web_adminportal.log
```

---

## References

- [Architecture Documentation](ARCHITECTURE.md) — System architecture and component overview
- [Build Instructions](BUILD.md) — Compilation and installation guide
- [Initial Setup Guide](INIT.md) — First-time installation and configuration
- [Security Documentation](SECURITY.md) — Security considerations and best practices
