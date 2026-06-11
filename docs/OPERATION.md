# uFastAuthD3 Operation Guide

## 📖 Table of Contents

- [Overview](#overview)
- [Service Management](#service-management)
  - [Starting the Service](#starting-the-service)
  - [Stopping the Service](#stopping-the-service)
  - [Restarting the Service](#restarting-the-service)
  - [Checking Service Status](#checking-service-status)
  - [Enabling Auto-Start at Boot](#enabling-auto-start-at-boot)
- [Logging](#logging)
  - [Viewing System Logs](#viewing-system-logs)
  - [Service-Specific Logs](#service-specific-logs)
  - [Log Rotation](#log-rotation)
- [Initial Setup & First Login](#initial-setup--first-login)
- [Web Portals Access](#web-portals-access)
  - [Login Portal](#login-portal)
  - [Admin Portal](#admin-portal)
  - [User Portal](#user-portal)
  - [AppSync API](#appsync-api)
  - [Session Auth Handler](#session-auth-handler)
- [Daily Operations](#daily-operations)
  - [Monitoring Service Health](#monitoring-service-health)
  - [Checking Database Status](#checking-database-status)
  - [Verifying Active Connections](#verifying-active-connections)
- [Maintenance Tasks](#maintenance-tasks)
  - [Backup and Restore](#backup-and-restore)
  - [Resetting the Admin Password](#resetting-the-admin-password)
  - [Regenerating JWT Secret Key](#regenerating-jwt-secret-key)
- [Firewall & Network Configuration](#firewall--network-configuration)
  - [Required Ports](#required-ports)
  - [UFW Rules](#ufw-rules)
  - [FirewallD Rules](#firewalld-rules)
- [Troubleshooting](#troubleshooting)
  - [Common Issues](#common-issues)
  - [Service Won't Start](#service-wont-start)
  - [Port Conflicts](#port-conflicts)
  - [Database Issues](#database-issues)
- [References](#references)

---

## Overview

This guide provides comprehensive instructions for operating and maintaining the uFastAuthD3 service in production and development environments. It covers service management, logging, initial setup, daily operations, maintenance tasks, firewall configuration, and troubleshooting.

uFastAuthD3 runs as a systemd service that manages multiple internal web services, each listening on a dedicated port. The daemon handles authentication, authorization, session management, and provides web portals for administrators and end users.


---

## Command-Line Options

uFastAuthD3 supports the following command-line flags:

| Flag | Long Option | Description | Default |
|------|-------------|-------------|---------|
| `-c` | `--config-dir` | Path to the configuration directory | `/etc/ufastauthd3` |
| `-r` | `--resetadmpw` | Reset the administrator password on next startup | `false` |

### Usage Examples

```bash
# Start with default configuration
ufastauthd3

# Start with custom configuration directory
ufastauthd3 -c /opt/myconfig

# Reset admin password on next start
ufastauthd3 -r
```

---

## Service Management

uFastAuthD3 is managed as a systemd service named `ufastauthd3.service`.

### Starting the Service

```bash
systemctl start ufastauthd3.service
```

### Stopping the Service

```bash
systemctl stop ufastauthd3.service
```

### Restarting the Service

```bash
systemctl restart ufastauthd3.service
```

Use this after configuration changes to apply them without a full system reboot.

### Checking Service Status

```bash
systemctl status ufastauthd3.service
```

This command displays:
- Whether the service is active (running) or inactive (dead)
- The main process ID (PID)
- Recent log output from the service
- Memory and CPU usage

### Enabling Auto-Start at Boot

To start uFastAuthD3 automatically when the system boots:

```bash
systemctl enable ufastauthd3.service
```

To disable auto-start:

```bash
systemctl disable ufastauthd3.service
```

Check whether the service is enabled:

```bash
systemctl is-enabled ufastauthd3.service
```

---

## Logging

uFastAuthD3 uses a dual logging system: systemd journal for daemon-level messages and per-service log files for detailed operational logs.

### Viewing System Logs

View real-time systemd journal logs for the uFastAuthD3 service:

```bash
journalctl -xefu ufastauthd3
```

Flags explained:
- `-x` — Add explanatory help text where available
- `-e` — Paginate to the end of the journal (show latest entries)
- `-f` — Follow mode (stream logs in real-time like `tail -f`)
- `-u ufastauthd3` — Filter by the ufastauthd3 unit


### Service-Specific Logs

Each web service writes its own log file in the configured log directory (default: `/var/log/ufastauthd3/`):

```bash
# View Login Portal logs
tail -f /var/log/ufastauthd3/web_loginportal.log

# View Admin Portal logs
tail -f /var/log/ufastauthd3/web_adminportal.log

# View User Portal logs
tail -f /var/log/ufastauthd3/web_userportal.log

# View AppSync API logs
tail -f /var/log/ufastauthd3/web_appsync.log

# View Session Auth Handler logs
tail -f /var/log/ufastauthd3/web_authhandler.log
```

View all service logs simultaneously:

```bash
tail -f /var/log/ufastauthd3/*.log
```

### Log Rotation

Log rotation is configured per-service in each web service configuration file. The default rotation settings are:

| Setting | Default Value | Description |
|---------|--------------|-------------|
| `MaxFileSize` | `10mb` | Maximum size before rotation |
| `MaxBackups` | `5` | Number of backup files to retain |
| `RotateOnStartup` | `"true"` | Rotate logs when the service starts |
| `RotateOnSize` | `"true"` | Enable size-based rotation |

Rotated files follow the naming pattern: `<logfile>.1`, `<logfile>.2`, etc., where `.1` is the most recent backup.

For detailed log rotation configuration, including scheduled rotation, see [docs/CONFIG.md](CONFIG.md#logs-configuration).

---

## Initial Setup & First Login

> **Note:** The complete first-time setup procedure, including `/etc/hosts` configuration, TLS certificate generation with Easy-RSA, URL configuration, JWT key generation, systemd service enabling, and firewall setup, is documented in **[docs/INIT.md](INIT.md)**.

On the very first startup, uFastAuthD3 automatically generates a temporary super-user password for the `admin` account. To retrieve it:

```bash
journalctl -xefu ufastauthd3 | grep "super-user password"
```

If you lose the temporary password, see [Resetting the Admin Password](#resetting-the-admin-password) below.

---

## Web Portals Access

uFastAuthD3 exposes multiple web services, each accessible on a dedicated port. All public-facing portals use HTTPS with TLS encryption.

### Login Portal

The Login Portal is the primary authentication interface where users log in, register (if enabled), and manage session tokens.

| Property | Value |
|----------|-------|
| **URL** | `https://<login-domain>:8443` |
| **Example** | `https://login.localhost:8443` |
| **Default Port** | `8443` |
| **Bind Address** | `0.0.0.0` (all interfaces) |
| **TLS** | Required |
| **Config Key** | `API.Origins` in `web_portal_login.conf` |

### Admin Portal

The Admin Portal provides system administrators with full control over the IAM system.

| Property | Value |
|----------|-------|
| **URL** | `https://<admin-domain>:9443` |
| **Example** | `https://iamadmin.localhost:9443` |
| **Default Port** | `9443` |
| **Bind Address** | `0.0.0.0` (all interfaces) |
| **TLS** | Required |
| **Config Key** | `API.Origins` in `web_portal_admin.conf` |

### User Portal

The User Portal allows end users to manage their profile, credentials, application access, and session information.

| Property | Value |
|----------|-------|
| **URL** | `https://<user-domain>:11443` |
| **Example** | `https://iamuser.localhost:11443` |
| **Default Port** | `11443` |
| **Bind Address** | `0.0.0.0` (all interfaces) |
| **TLS** | Required |
| **Config Key** | `API.Origins` in `web_portal_user.conf` |

> **Note:** The actual URLs depend on what is configured in each web service's `API.Origins` directive. The domain/CN must match the TLS certificate. The examples above use the default configuration values (`login.localhost`, `iamadmin.localhost`, `iamuser.localhost`). In production, replace these with your actual domain names (e.g., `https://login.yourdomain.com:8443`). Each portal is accessed at the root path `/`, not via a subdirectory.

### AppSync API

The AppSync service provides the HTTP API for application integration with uFastAuthD3.

| Property | Value |
|----------|-------|
| **URL** | `http://127.0.0.1:7081` (localhost only) |
| **Default Port** | `7081` |
| **Bind Address** | `127.0.0.1` (localhost only) |
| **TLS** | Optional |

**Note:** This service is designed for internal use only and binds to localhost by default. Access it through proxy configuration or from the same host.

### Session Auth Handler

The Session Auth Handler manages authentication cookies, validates JWT tokens, and provides logout functionality.

| Property | Value |
|----------|-------|
| **URL** | `http://127.0.0.1:7080` (localhost only) |
| **Default Port** | `7080` |
| **Bind Address** | `127.0.0.1` (localhost only) |
| **TLS** | Optional |

**Note:** Like AppSync, this service is internal and typically accessed through a reverse proxy.

### Web Services Port Summary

| Service | Default Port | TLS | Bind Address | Purpose |
|---------|-------------|-----|--------------|---------|
| Login Portal | 8443 | Yes | 0.0.0.0 | User authentication interface |
| Admin Portal | 9443 | Yes | 0.0.0.0 | Administrator control panel |
| User Portal | 11443 | Yes | 0.0.0.0 | User self-service portal |
| AppSync API | 7081 | Optional | 127.0.0.1 | Application API integration |
| Session Auth Handler | 7080 | Optional | 127.0.0.1 | Cookie/JWT session management |

---

## Daily Operations

### Monitoring Service Health

Check if the service is running and healthy:

```bash
# Check service status
systemctl is-active ufastauthd3.service

# Check if all web service ports are listening
ss -tlnp | grep -E '(8443|9443|11443|7080|7081)'

# Alternative using netstat
netstat -tlnp | grep -E '(8443|9443|11443|7080|7081)'
```

Expected output should show all configured ports in LISTEN state:

```
tcp  0  0  0.0.0.0:8443    0.0.0.0:*   LISTEN  1234/ufastauthd3
tcp  0  0  0.0.0.0:9443    0.0.0.0:*   LISTEN  1234/ufastauthd3
tcp  0  0  0.0.0.0:11443   0.0.0.0:*   LISTEN  1234/ufastauthd3
tcp  0  0  127.0.0.1:7080  0.0.0.0:*   LISTEN  1234/ufastauthd3
tcp  0  0  127.0.0.1:7081  0.0.0.0:*   LISTEN  1234/ufastauthd3
```

### Checking Database Status

uFastAuthD3 uses SQLite3 for its backend database. The main database and logs database locations are configured in the main configuration file.

Default paths:
- **Main Database:** `/var/lib/ufastauthd3/main.db`
- **Logs Database:** `/var/log/ufastauthd3/logs.db`

Verify the databases exist and are accessible:

```bash
# Check main database file
ls -lh /var/lib/ufastauthd3/main.db

# Check logs database file
ls -lh /var/log/ufastauthd3/logs.db

# Verify database integrity
sqlite3 /var/lib/ufastauthd3/main.db "PRAGMA integrity_check;"

# View database tables
sqlite3 /var/lib/ufastauthd3/main.db ".tables"

```

### Verifying Active Connections

Monitor active database connections and concurrent clients:

```bash
# Check open file descriptors for the ufastauthd3 process
ls -l /proc/$(pgrep ufastauthd3)/fd | wc -l

# Monitor memory usage
ps -o pid,rss,vsz,cmd -p $(pgrep ufastauthd3)
```

---

## Maintenance Tasks

### Backup and Restore

Regular backups are essential for protecting your IAM data. uFastAuthD3 stores all data in SQLite3 database files and configuration files.

**Important:** You must stop the service before performing a backup to ensure data consistency, and restart it afterward.

```bash
# Stop the service before backup
systemctl stop ufastauthd3.service

# Perform your backup (copy the files listed below)

# Restart the service after backup
systemctl start ufastauthd3.service
```

#### Files to Back Up

| Item | Path | Description |
|------|------|-------------|
| Main Database | `/var/lib/ufastauthd3/main.db` | All accounts, applications, sessions, credentials |
| Logs Database | `/var/log/ufastauthd3/logs.db` | Security events and audit logs |
| Configuration | `/etc/ufastauthd3/` | All configuration files |
| JWT Secret | `/etc/ufastauthd3/jwt/hmac_secret.key` | JWT signing key |
| TLS Certificates | `/etc/ufastauthd3/tls/` | Server certificates and keys |


### Resetting the Admin Password

If you have lost the admin password, you can reset it using the `--resetadmpw` command-line flag:

```bash
# Stop the current service
systemctl stop ufastauthd3.service

# Start with password reset flag (temporary manual start)
ufastauthd3 -r

# Check logs for the new temporary password
journalctl -xefu ufastauthd3 | grep "super-user password"
```

After resetting, log in with the new temporary password and immediately set a new permanent password through the Admin Portal.

**Note:** If you started the service manually with `-r`, stop it with `Ctrl+C` and restart normally:

```bash
systemctl start ufastauthd3.service
```

### Regenerating JWT Secret Key

If the JWT HMAC secret key is lost or compromised, remove the existing key file and restart the service. The application will automatically generate a new one on startup:

```bash
# Remove the existing JWT secret key
rm /etc/ufastauthd3/jwt/hmac_secret.key

# Restart the service (a new key will be generated automatically)
systemctl restart ufastauthd3.service
```

**Warning:** Regenerating the JWT secret invalidates all existing JWT tokens. All users will need to log in again.

---

## Firewall & Network Configuration

> **Note:** Initial firewall setup during first-time installation is documented in **[docs/INIT.md](INIT.md#step-8-configure-the-firewall)**.

### Required Ports

The following ports must be open for proper operation. Internal services (AppSync, AuthHandler) bind to localhost and do not require firewall rules.

| Port | Protocol | Service | Direction | Required |
|------|----------|---------|-----------|----------|
| 8443 | TCP | Login Portal | Inbound | Yes |
| 9443 | TCP | Admin Portal | Inbound | Yes |
| 11443 | TCP | User Portal | Inbound | Yes |
| 7080 | TCP | Session Auth Handler | Local | No (localhost) |
| 7081 | TCP | AppSync API | Local | No (localhost) |

### UFW Quick Reference

```bash
# Check current rules
sudo ufw status verbose

# Allow a port
sudo ufw allow <port>/tcp comment 'uFastAuthD3 <service>'

# Deny a port
sudo ufw deny <port>/tcp
```

### FirewallD Quick Reference

```bash
# List open ports
sudo firewall-cmd --list-ports

# Add a port
sudo firewall-cmd --permanent --add-port=<port>/tcp && sudo firewall-cmd --reload

# Remove a port
sudo firewall-cmd --permanent --remove-port=<port>/tcp && sudo firewall-cmd --reload
```

---

## Troubleshooting

### Common Issues

| Problem | Possible Cause | Solution |
|---------|----------------|----------|
| Service fails to start | Port already in use | Change `ListenPort` or stop conflicting service |
| TLS handshake fails | Invalid certificate/key | See [docs/CERTIFICATES.md](CERTIFICATES.md#troubleshooting) |
| JWT errors | Missing HMAC secret | Set `CreateIfNotPresent "true"` in config |
| Login redirection loop | Incorrect URLs | Verify `Origins` and `Redirections` match your DNS/hostnames |
| Database errors | Wrong path or permissions | Verify database paths exist and are writable |
| 403 Forbidden on proxy | Missing API key | Ensure `%APIKEY%` is replaced with the actual API key |
| Cannot access a portal | Firewall blocking port | Open the required port in your firewall |

### Quick Checks

- **Service status:** `systemctl status ufastauthd3.service`
- **View logs:** `journalctl -xefu ufastauthd3`
- **Check ports:** `ss -tlnp | grep ufastauthd3`
- **Database integrity:** `sqlite3 /var/lib/ufastauthd3/main.db "PRAGMA integrity_check;"`

---

## References

- [Architecture Documentation](ARCHITECTURE.md) — System architecture and component overview
- [Build Instructions](BUILD.md) — Compilation and installation guide
- [Configuration Guide](CONFIG.md) — Detailed configuration reference for all web services
- [Security Documentation](SECURITY.md) — Security considerations and best practices
- [Main README](../README.md) — Project overview and quick start